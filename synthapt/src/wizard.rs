//! First-run setup wizard for SynthAPT.
//!
//! Runs when ~/.config/SynthAPT/config.toml does not exist and prompts
//! the user for their Claude API key.

use crate::model::{Model, WizardPopupState};

/// Open the wizard popup and push its shortcut context.
pub fn start(mut model: Model) -> Model {
    model.wizard_popup = Some(WizardPopupState {
        input: String::new(),
        cursor: 0,
    });
    model.shortcut_stack.push(crate::shortcuts::wizard_popup_context());
    model
}

/// Called when the user submits the API key (may be empty = skip).
pub fn complete(mut model: Model, api_key: String) -> Model {
    // Close the popup
    model.wizard_popup = None;
    model.shortcut_stack.pop_to(crate::shortcuts::ContextName::WizardPopup);

    // Save config (even if empty, so we don't show the wizard again)
    let mut config = crate::config::Config::default();
    if !api_key.trim().is_empty() {
        config.api_key = Some(api_key.trim().to_string());
    }
    if let Err(e) = config.save() {
        model.debug_state.error(format!("[wizard] Failed to save config: {e}"));
    }

    // Continue with normal app init
    do_normal_init(model)
}

/// Run normal initialization (load initial playbook if one was set).
pub fn do_normal_init(model: Model) -> Model {
    crate::hooks::run_normal_init(model)
}
