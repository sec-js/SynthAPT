use serde::{Deserialize, Serialize};
use serde_json::json;
use std::thread;

use crate::message::{Msg, PaneId};
use crate::model::{AgentMessage, MessageRole};

const CLAUDE_API_URL: &str = "https://api.anthropic.com/v1/messages";
const CLAUDE_MODEL: &str = "claude-sonnet-4-6";

/// Snapshot of model state for the agent background thread
#[derive(Debug, Clone)]
pub struct AgentModelSnapshot {
    pub playbook_json: String,
}

/// Request body for Claude API
#[derive(Debug, Serialize)]
struct ClaudeRequest {
    model: String,
    max_tokens: u32,
    system: String,
    messages: Vec<ClaudeMessage>,
    tools: Vec<ClaudeTool>,
}

/// A message in Claude format
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ClaudeMessage {
    role: String,
    content: ClaudeContent,
}

/// Content can be a string or array of content blocks
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum ClaudeContent {
    Text(String),
    Blocks(Vec<ContentBlock>),
}

/// A content block (text or tool use/result)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
enum ContentBlock {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "tool_use")]
    ToolUse {
        id: String,
        name: String,
        input: serde_json::Value,
    },
    #[serde(rename = "tool_result")]
    ToolResult {
        tool_use_id: String,
        content: String,
    },
}

/// Tool definition for Claude
#[derive(Debug, Serialize)]
struct ClaudeTool {
    name: &'static str,
    description: &'static str,
    input_schema: serde_json::Value,
}

/// Response from Claude API
#[derive(Debug, Deserialize)]
struct ClaudeResponse {
    content: Vec<ContentBlock>,
    stop_reason: Option<String>,
}

/// Error response from Claude API
#[derive(Debug, Deserialize)]
struct ClaudeError {
    error: ClaudeErrorDetail,
}

#[derive(Debug, Deserialize)]
struct ClaudeErrorDetail {
    message: String,
}

/// Get the Claude API key from env var or ~/.config/SynthAPT/config.toml
fn get_api_key() -> Option<String> {
    // Env var takes priority
    if let Ok(key) = std::env::var("ANTHROPIC_API_KEY") {
        if !key.is_empty() {
            return Some(key);
        }
    }
    crate::config::Config::load().api_key
}

/// Get tool definitions for the editor agent
fn get_tool_definitions() -> Vec<ClaudeTool> {
    vec![
        ClaudeTool {
            name: "edit_playbook",
            description: "Replace the entire playbook with new JSON. The JSON will be validated against the playbook schema before applying. Returns 'ok' on success or an error message describing what is wrong.",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "json": {
                        "type": "string",
                        "description": "The complete playbook JSON string"
                    }
                },
                "required": ["json"]
            }),
        },
    ]
}

/// Build the ops reference section of the system prompt from static metadata.
fn build_ops_reference() -> String {
    use common::tui::metadata::all_task_metadata;

    let mut lines = vec!["Available ops (required fields shown plain, optional fields marked with ?). IMPORTANT: omit optional fields entirely when not needed — do NOT set them to null:".to_string()];
    for meta in all_task_metadata() {
        let fields: Vec<String> = meta.fields.iter().map(|f| {
            if f.required {
                format!("{}: {}", f.name, f.type_hint)
            } else {
                format!("{}?: {}", f.name, f.type_hint)
            }
        }).collect();

        if fields.is_empty() {
            lines.push(format!("- {} — {}", meta.op, meta.description));
        } else {
            lines.push(format!("- {} — {}  [{}]", meta.op, meta.description, fields.join(", ")));
        }
    }
    lines.join("\n")
}

/// System prompt for the playbook editor agent
fn get_system_prompt() -> String {
    let ops_ref = build_ops_reference();
    format!(r#"You are an AI assistant integrated into a playbook editor for a detection engineering framework.
You help users design and edit playbooks that replicate malware behavior. This will be used to develop and validate detections, or train security professionals on malware.

Each task_set in the rust_agent represents an individual thread. When the payload is executed, it checks the task byte and executes the task_set that corresponds to that byte.
So, for example, the initial payload will always have 0x00 in its task byte, task_set 0 may have a task to migrate to another process with task_set 1.
Task set 1 will have all the actions you want the new thread in the injected process to do.

Each rust_agent has a "magic" u32 that it uses to find itself in memory.
If two agents in the same process have the same magic, the process will crash.
The default magic for the first agent is 0x17171717, and operations like migrate and start_thread will increment this value.
But, the payload has no way to check for collisions on remote systems so you'll have to manage magic values in these cases.
It's best to always set the magic value to a unique number.

A playbook is a JSON file with this structure:
{{
  "constants": [
    "c:\\windows\\temp\\test.txt"
  ],
  "task_sets": {{
    "0": [
      {{"op": "set_var", "var": 0, "data": "hello world"}},
      {{"op": "write_file", "path": "%0", "content": "$0"}},
      {{"op": "sleep", "ms": 1000}},
      {{"op": "run_command", "command": "whoami"}},
      {{"op": "print_var"}}
    ],
    "1": [...]
  }}
}}

The task_sets object maps string IDs (usually "0", "1", ...) to arrays of task objects. task_sets are essentially threads.

Each task has an "op" field identifying its type, plus additional fields depending on the op.

{ops_ref}

When the user asks you to modify the playbook, use the edit_playbook tool with the complete new JSON.

If the user asks you to replicate malware from a report or an article you need to reimagine the malware according to the opcodes you have available.
The important part is reproducing the correct Sysmon/EDR/Windows logs, NOT replicating every aspect of the malware.

The current playbook will be provided as context with each message.

IMPORTANT
- The user usually won't be able to see output unless it's an executable. If they want to debug, it's helpful to redirect stdout to a file at the beginning of the task_set. Only do this if they ask or mention debugging as it will create an additional artifact.
- You don't need to place an end opcode at the end of a task_set as one is automatically appended. The end opcode is only for conditionals.
- The search param in opcodes like migrate accepts a numeric pid or a search string. The search string is a case-sensitive search for the process name/args.
- If you don't supply a task_id/task to opcodes like migrate and create_thread, it will run the current task_set. This can cause infinite loops, so always set the task id unless you have good reason not to.
- You can pass constants using a % and variables with a $
- The following opcodes are not included in the default feature set. Do not use them unless the user explicitly requests them: frida_hook, http_beacon, dll_list, mem_map, malfind, ldr_check
"#)
}

/// Format the playbook snapshot as context to inject into user messages
fn format_context(snapshot: &AgentModelSnapshot) -> String {
    format!("[Current Playbook JSON]:\n{}", snapshot.playbook_json)
}

/// Convert internal messages to Claude API format
fn to_claude_messages(messages: &[AgentMessage], snapshot: &AgentModelSnapshot) -> Vec<ClaudeMessage> {
    let context = format_context(snapshot);
    let msg_count = messages.len();

    messages.iter().enumerate().map(|(i, msg)| {
        let role = match msg.role {
            MessageRole::User => "user",
            MessageRole::Assistant | MessageRole::Tool => "assistant",
        };

        // Prefix the latest user message with context
        let content = if role == "user" && i == msg_count - 1 {
            format!("{}\n\n{}", context, msg.content)
        } else {
            msg.content.clone()
        };

        ClaudeMessage {
            role: role.to_string(),
            content: ClaudeContent::Text(content),
        }
    }).collect()
}

/// Execute a tool call and return the result string
fn execute_tool(tool_name: &str, input: &serde_json::Value) -> String {
    match tool_name {
        "edit_playbook" => {
            let json_str = match input.get("json").and_then(|v| v.as_str()) {
                Some(s) => s,
                None => return "error: missing 'json' field in tool input".to_string(),
            };
            match crate::cli::validate_playbook(json_str) {
                Ok(_) => {
                    crate::message::send(Msg::ApplyPlaybookJson { json: json_str.to_string() });
                    "ok: playbook applied successfully".to_string()
                }
                Err(report) => report,
            }
        }
        _ => format!("error: unknown tool '{}'", tool_name),
    }
}

/// Send a message to Claude in a background thread
pub fn send_message_async(
    pane_id: PaneId,
    messages: Vec<AgentMessage>,
    snapshot: AgentModelSnapshot,
) {
    thread::spawn(move || {
        let result = send_message_sync(pane_id, &messages, &snapshot);

        match result {
            Ok(response) => {
                crate::message::send(Msg::AgentResponse {
                    pane_id,
                    content: response,
                    role: MessageRole::Assistant,
                });
                crate::message::send(Msg::AgentDone { pane_id });
            }
            Err(e) => {
                crate::message::send(Msg::AgentError { pane_id, error: e });
            }
        }
    });
}

/// Synchronously send messages to Claude (called from background thread)
fn send_message_sync(
    pane_id: PaneId,
    messages: &[AgentMessage],
    snapshot: &AgentModelSnapshot,
) -> Result<String, String> {
    let api_key = get_api_key()
        .ok_or_else(|| "No API key found. Set ANTHROPIC_API_KEY env var or add api_key under [claude] in ~/.config/swarm/config.toml".to_string())?;

    let mut claude_messages = to_claude_messages(messages, snapshot);

    loop {
        let request = ClaudeRequest {
            model: CLAUDE_MODEL.to_string(),
            max_tokens: 8192,
            system: get_system_prompt(),
            messages: claude_messages.clone(),
            tools: get_tool_definitions(),
        };

        let response = ureq::post(CLAUDE_API_URL)
            .set("Content-Type", "application/json")
            .set("anthropic-version", "2023-06-01")
            .set("x-api-key", &api_key)
            .send_json(&request)
            .map_err(|e| {
                match e {
                    ureq::Error::Status(code, resp) => {
                        let body = resp.into_string().unwrap_or_default();
                        if let Ok(err) = serde_json::from_str::<ClaudeError>(&body) {
                            format!("API error {}: {}", code, err.error.message)
                        } else {
                            format!("API error {}: {}", code, body)
                        }
                    }
                    other => format!("Request failed: {}", other),
                }
            })?;

        let response_text = response.into_string()
            .map_err(|e| format!("Failed to read response: {}", e))?;

        let claude_response: ClaudeResponse = serde_json::from_str(&response_text)
            .map_err(|e| {
                if let Ok(err) = serde_json::from_str::<ClaudeError>(&response_text) {
                    return err.error.message;
                }
                format!("Failed to parse response: {} - {}", e, response_text)
            })?;

        let mut has_tool_use = false;
        let mut tool_results = Vec::new();
        let mut text_response = String::new();

        for block in &claude_response.content {
            match block {
                ContentBlock::Text { text } => {
                    text_response.push_str(text);
                }
                ContentBlock::ToolUse { id, name, input } => {
                    has_tool_use = true;

                    let tool_output = execute_tool(name, input);

                    // Show tool call summary in the UI
                    let input_str = serde_json::to_string(input).unwrap_or_else(|_| "{}".to_string());
                    let preview = if tool_output.len() > 200 {
                        format!("{}...", &tool_output[..200])
                    } else {
                        tool_output.clone()
                    };
                    crate::message::send(Msg::AgentResponse {
                        pane_id,
                        content: format!("[{}({}) -> {}]", name, input_str, preview),
                        role: MessageRole::Tool,
                    });

                    tool_results.push(ContentBlock::ToolResult {
                        tool_use_id: id.clone(),
                        content: tool_output,
                    });
                }
                _ => {}
            }
        }

        let truncated = claude_response.stop_reason.as_deref() == Some("max_tokens");

        if has_tool_use {
            // Send any reasoning text before continuing
            if !text_response.is_empty() {
                crate::message::send(Msg::AgentResponse {
                    pane_id,
                    content: text_response,
                    role: MessageRole::Assistant,
                });
            }

            // Add assistant message with tool use blocks
            claude_messages.push(ClaudeMessage {
                role: "assistant".to_string(),
                content: ClaudeContent::Blocks(claude_response.content.clone()),
            });

            // Add tool results
            claude_messages.push(ClaudeMessage {
                role: "user".to_string(),
                content: ClaudeContent::Blocks(tool_results),
            });

            continue;
        }

        if truncated && !text_response.is_empty() {
            crate::message::send(Msg::AgentResponse {
                pane_id,
                content: text_response.clone(),
                role: MessageRole::Assistant,
            });

            claude_messages.push(ClaudeMessage {
                role: "assistant".to_string(),
                content: ClaudeContent::Text(text_response),
            });
            claude_messages.push(ClaudeMessage {
                role: "user".to_string(),
                content: ClaudeContent::Text("Continue.".to_string()),
            });
            continue;
        }

        if text_response.is_empty() {
            return Err("Empty response from Claude".to_string());
        }

        return Ok(text_response);
    }
}
