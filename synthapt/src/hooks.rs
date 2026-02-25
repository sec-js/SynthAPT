use std::sync::OnceLock;

use crate::message::PaneId;
use crate::model::{Model, PaneType};

static INITIAL_PATH: OnceLock<Option<String>> = OnceLock::new();

/// Call before starting the TUI to configure which playbook to load on init.
pub fn set_initial_path(path: Option<String>) {
    INITIAL_PATH.set(path).ok();
}

/// Called once when the application starts.
/// Runs the first-run wizard if the config file doesn't exist; otherwise loads normally.
pub fn on_app_init(model: Model) -> Model {
    if crate::config::Config::needs_setup() {
        crate::wizard::start(model)
    } else {
        run_normal_init(model)
    }
}

/// Load the initial playbook (called after wizard completes or on normal startup).
pub fn run_normal_init(model: Model) -> Model {
    match INITIAL_PATH.get() {
        Some(Some(path)) => {
            crate::update::update(model, crate::message::Msg::Load { path: path.clone() })
        }
        _ => model,
    }
}

/// Called when the user edits the playbook (add node, edit field, delete node)
pub fn on_playbook_edited(model: Model) -> Model {
    crate::update::update(model, crate::message::Msg::Save)
}

/// Called once when the application is shutting down
pub fn on_app_shutdown(model: Model) -> Model {
    model
}

/// Called when a new pane is created
pub fn on_pane_created(model: Model, _pane_id: PaneId, _pane_type: PaneType) -> Model {
    model
}

/// Called when a pane is about to be destroyed
pub fn on_pane_destroyed(model: Model, _pane_id: PaneId, _pane_type: PaneType) -> Model {
    model
}
