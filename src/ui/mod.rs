// Terminal UI module
// Provides the interactive terminal interface

pub mod terminal;
pub mod status;

pub use terminal::{
    TerminalUI, ChatMessage, MessageSource, ConnectionStatus, UIEvent, run_ui_loop
};
pub use status::StatusBar;
