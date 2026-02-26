pub mod claude;
pub mod ollama;

pub use claude::AgentModelSnapshot;
pub use claude::get_system_prompt;

use crate::message::PaneId;
use crate::model::AgentMessage;

pub fn send_message_async(
    pane_id: PaneId,
    messages: Vec<AgentMessage>,
    snapshot: AgentModelSnapshot,
) {
    match crate::config::Config::load().provider {
        crate::config::Provider::Ollama => ollama::send_message_async(pane_id, messages, snapshot),
        crate::config::Provider::Claude => claude::send_message_async(pane_id, messages, snapshot),
    }
}
