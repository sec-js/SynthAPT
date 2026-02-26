use serde::{Deserialize, Serialize};
use serde_json::json;
use std::io::BufRead;
use std::thread;

use crate::message::{Msg, PaneId};
use crate::model::{AgentMessage, MessageRole};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OllamaMessage {
    role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_calls: Option<Vec<OllamaToolCall>>,
}

/// In the native Ollama API, tool call arguments are a JSON object (not a string).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct OllamaToolCall {
    function: OllamaToolCallFunction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OllamaToolCallFunction {
    name: String,
    arguments: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct OllamaRequest {
    model: String,
    messages: Vec<OllamaMessage>,
    tools: Vec<serde_json::Value>,
    stream: bool,
    think: bool,
}

// Each line in the NDJSON stream
#[derive(Debug, Deserialize)]
struct StreamLine {
    message: Option<StreamMessage>,
    done: bool,
}

#[derive(Debug, Deserialize)]
struct StreamMessage {
    content: Option<String>,
    tool_calls: Option<Vec<OllamaToolCall>>,
}

fn get_tool_definitions() -> Vec<serde_json::Value> {
    vec![
        json!({
            "type": "function",
            "function": {
                "name": "edit_playbook",
                "description": "Replace the entire playbook with new JSON. The JSON will be validated against the playbook schema before applying. Returns 'ok' on success or an error message.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "json": {
                            "type": "string",
                            "description": "The complete playbook JSON string"
                        }
                    },
                    "required": ["json"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "fetch_url",
                "description": "Fetch the contents of a URL via HTTP GET.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "The URL to fetch"
                        }
                    },
                    "required": ["url"]
                }
            }
        }),
    ]
}

fn execute_tool(tool_name: &str, arguments: &serde_json::Value) -> String {
    match tool_name {
        "edit_playbook" => {
            let json_str = match arguments.get("json").and_then(|v| v.as_str()) {
                Some(s) => s,
                None => return "error: missing 'json' field".to_string(),
            };
            match crate::cli::validate_playbook(json_str) {
                Ok(_) => {
                    crate::message::send(Msg::ApplyPlaybookJson { json: json_str.to_string() });
                    "ok: playbook applied successfully".to_string()
                }
                Err(report) => report,
            }
        }
        "fetch_url" => {
            let url = match arguments.get("url").and_then(|v| v.as_str()) {
                Some(s) => s,
                None => return "error: missing 'url' field".to_string(),
            };
            match ureq::get(url).call() {
                Ok(resp) => resp.into_string().unwrap_or_else(|e| format!("error reading response: {}", e)),
                Err(e) => format!("error fetching url: {}", e),
            }
        }
        _ => format!("error: unknown tool '{}'", tool_name),
    }
}

fn build_messages(messages: &[AgentMessage], snapshot: &super::claude::AgentModelSnapshot) -> Vec<OllamaMessage> {
    let context = format!("[Current Playbook JSON]:\n{}", snapshot.playbook_json);
    let msg_count = messages.len();

    messages.iter().enumerate().map(|(i, msg)| {
        let role = match msg.role {
            MessageRole::User => "user",
            MessageRole::Assistant | MessageRole::Tool => "assistant",
        };

        let content = if role == "user" && i == msg_count - 1 {
            format!("{}\n\n{}", context, msg.content)
        } else {
            msg.content.clone()
        };

        OllamaMessage {
            role: role.to_string(),
            content: Some(content),
            tool_calls: None,
        }
    }).collect()
}

pub fn send_message_async(
    pane_id: PaneId,
    messages: Vec<AgentMessage>,
    snapshot: super::claude::AgentModelSnapshot,
) {
    thread::spawn(move || {
        let config = crate::config::Config::load();
        let url = format!("http://{}:{}/api/chat", config.ollama_host, config.ollama_port);
        let model = config.ollama_model.clone();
        crate::message::send(Msg::Log {
            level: crate::model::LogLevel::Info,
            message: format!("[ollama] sending to {} model={}", url, model),
        });

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            send_message_sync(pane_id, &messages, &snapshot, &url, &model)
        }));

        match result {
            Ok(Ok(response)) => {
                crate::message::send(Msg::AgentResponse {
                    pane_id,
                    content: response,
                    role: MessageRole::Assistant,
                });
                crate::message::send(Msg::AgentDone { pane_id });
            }
            Ok(Err(e)) => {
                crate::message::send(Msg::AgentError { pane_id, error: e });
            }
            Err(_) => {
                crate::message::send(Msg::AgentError {
                    pane_id,
                    error: "Ollama agent panicked — check host/port/model in ~/.config/SynthAPT/config.toml".to_string(),
                });
            }
        }
    });
}

fn send_message_sync(
    pane_id: PaneId,
    messages: &[AgentMessage],
    snapshot: &super::claude::AgentModelSnapshot,
    url: &str,
    model: &str,
) -> Result<String, String> {
    let system_msg = OllamaMessage {
        role: "system".to_string(),
        content: Some(super::claude::get_system_prompt()),
        tool_calls: None,
    };

    let mut ollama_messages: Vec<OllamaMessage> = std::iter::once(system_msg)
        .chain(build_messages(messages, snapshot))
        .collect();

    loop {
        let request = OllamaRequest {
            model: model.to_string(),
            messages: ollama_messages.clone(),
            tools: get_tool_definitions(),
            stream: true,
            think: false,
        };

        let response = ureq::post(url)
            .set("Content-Type", "application/json")
            .send_json(&request)
            .map_err(|e| match e {
                ureq::Error::Status(code, resp) => {
                    let body = resp.into_string().unwrap_or_default();
                    format!("API error {}: {}", code, body)
                }
                other => format!("Request failed: {}", other),
            })?;

        // /api/chat streams NDJSON: one JSON object per line
        let reader = std::io::BufReader::new(response.into_reader());

        let mut content = String::new();
        let mut tool_calls: Vec<OllamaToolCall> = Vec::new();

        for line in reader.lines() {
            let line = line.map_err(|e| format!("Stream read error: {}", e))?;
            if line.is_empty() { continue; }

            let stream_line: StreamLine = match serde_json::from_str(&line) {
                Ok(l) => l,
                Err(_) => continue,
            };

            if let Some(msg) = stream_line.message {
                if let Some(text) = msg.content {
                    content.push_str(&text);
                }
                if let Some(tcs) = msg.tool_calls {
                    if !tcs.is_empty() {
                        tool_calls = tcs;
                    }
                }
            }

            if stream_line.done {
                break;
            }
        }

        if !tool_calls.is_empty() {
            if !content.is_empty() {
                crate::message::send(Msg::AgentResponse {
                    pane_id,
                    content: content.clone(),
                    role: MessageRole::Assistant,
                });
            }

            ollama_messages.push(OllamaMessage {
                role: "assistant".to_string(),
                content: if content.is_empty() { None } else { Some(content) },
                tool_calls: Some(tool_calls.clone()),
            });

            for tc in &tool_calls {
                let result = execute_tool(&tc.function.name, &tc.function.arguments);

                let preview = if result.len() > 200 { format!("{}...", &result[..200]) } else { result.clone() };
                crate::message::send(Msg::AgentResponse {
                    pane_id,
                    content: format!("[{}({}) -> {}]", tc.function.name, tc.function.arguments, preview),
                    role: MessageRole::Tool,
                });

                ollama_messages.push(OllamaMessage {
                    role: "tool".to_string(),
                    content: Some(result),
                    tool_calls: None,
                });
            }

            continue;
        }

        if content.is_empty() {
            return Err("Empty response from Ollama".to_string());
        }
        return Ok(content);
    }
}
