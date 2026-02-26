//! First-run setup wizard for SynthAPT.

use crate::model::{Model, WizardData, WizardPopupState, WizardStep};

/// Open the wizard at the Provider step.
pub fn start(mut model: Model) -> Model {
    model.wizard_step = WizardStep::Provider;
    model.wizard_data = WizardData::default();
    model.wizard_popup = Some(WizardPopupState {
        input: String::new(),
        cursor: 0,
        selected: 0,
    });
    model.shortcut_stack.push(crate::shortcuts::wizard_popup_context());
    model
}

/// Advance to the next wizard step or complete.
/// Called from update.rs with the current input value.
pub fn advance(mut model: Model, input: String, selected: usize) -> Model {
    let step = model.wizard_step.clone();
    match step {
        WizardStep::Provider => {
            let provider = if selected == 1 { "ollama" } else { "claude" };
            model.wizard_data.provider = provider.to_string();
            if provider == "ollama" {
                model = set_step(model, WizardStep::OllamaHost, "127.0.0.1");
            } else {
                model = set_step(model, WizardStep::ClaudeApiKey, "");
            }
        }
        WizardStep::OllamaHost => {
            model.wizard_data.ollama_host = if input.trim().is_empty() { "127.0.0.1".to_string() } else { input.trim().to_string() };
            model = set_step(model, WizardStep::OllamaPort, "11434");
        }
        WizardStep::OllamaPort => {
            model.wizard_data.ollama_port = if input.trim().is_empty() { "11434".to_string() } else { input.trim().to_string() };
            model = set_step(model, WizardStep::OllamaModel, "qwen3");
        }
        WizardStep::OllamaModel => {
            model.wizard_data.ollama_model = if input.trim().is_empty() { "qwen3".to_string() } else { input.trim().to_string() };
            model = complete(model);
        }
        WizardStep::ClaudeApiKey => {
            model.wizard_data.api_key = input;
            model = complete(model);
        }
    }
    model
}

/// Skip wizard — default to Claude with no API key.
pub fn skip(mut model: Model) -> Model {
    model.wizard_data = WizardData { provider: "claude".to_string(), ..WizardData::default() };
    complete(model)
}

fn set_step(mut model: Model, step: WizardStep, prefill: &str) -> Model {
    model.wizard_step = step;
    model.wizard_popup = Some(WizardPopupState {
        input: prefill.to_string(),
        cursor: prefill.len(),
        selected: 0,
    });
    model
}

fn complete(mut model: Model) -> Model {
    model.wizard_popup = None;
    model.shortcut_stack.pop_to(crate::shortcuts::ContextName::WizardPopup);

    let data = model.wizard_data.clone();
    let mut config = crate::config::Config::default();

    if data.provider == "ollama" {
        config.provider = crate::config::Provider::Ollama;
        config.ollama_host = if data.ollama_host.is_empty() { "127.0.0.1".to_string() } else { data.ollama_host };
        config.ollama_port = data.ollama_port.parse().unwrap_or(11434);
        config.ollama_model = if data.ollama_model.is_empty() { "qwen3".to_string() } else { data.ollama_model };
    } else {
        config.provider = crate::config::Provider::Claude;
        if !data.api_key.trim().is_empty() {
            config.api_key = Some(data.api_key.trim().to_string());
        }
    }

    if let Err(e) = config.save() {
        model.debug_state.error(format!("[wizard] Failed to save config: {e}"));
    }

    do_normal_init(model)
}

/// Run normal initialization (load initial playbook if one was set).
pub fn do_normal_init(model: Model) -> Model {
    crate::hooks::run_normal_init(model)
}
