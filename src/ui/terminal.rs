// Terminal UI implementation with ratatui
// Provides an interactive split-pane interface for encrypted chat

use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
    Frame, Terminal as RatatuiTerminal,
};
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use std::io;
use tokio::sync::mpsc;

pub struct TerminalUI {
    messages: Vec<ChatMessage>,
    input: String,
    scroll_offset: usize,
    connection_status: ConnectionStatus,
    key_rotation_countdown: u64,
}

#[derive(Clone)]
pub struct ChatMessage {
    pub from: MessageSource,
    pub content: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageSource {
    Sent,
    Received,
    System,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionStatus {
    Disconnected,
    Connecting,
    Handshaking,
    Connected,
    Error(String),
}

pub enum UIEvent {
    SendMessage(String),
    Quit,
}

impl TerminalUI {
    pub fn new() -> Self {
        Self {
            messages: Vec::new(),
            input: String::new(),
            scroll_offset: 0,
            connection_status: ConnectionStatus::Disconnected,
            key_rotation_countdown: 60,
        }
    }

    pub fn add_message(&mut self, from: MessageSource, content: String) {
        let timestamp = chrono::Local::now().format("%H:%M:%S").to_string();
        self.messages.push(ChatMessage {
            from,
            content,
            timestamp,
        });

        // Auto-scroll to bottom
        if self.messages.len() > 20 {
            self.scroll_offset = self.messages.len() - 20;
        }
    }

    pub fn set_status(&mut self, status: ConnectionStatus) {
        self.connection_status = status;
    }

    pub fn set_key_rotation_countdown(&mut self, seconds: u64) {
        self.key_rotation_countdown = seconds;
    }

    pub fn draw(&self, frame: &mut Frame, area: Rect) {
        // Create main layout
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),      // Status bar
                Constraint::Min(10),         // Messages
                Constraint::Length(3),       // Input
            ])
            .split(area);

        // Draw status bar
        self.draw_status_bar(frame, chunks[0]);

        // Draw messages
        self.draw_messages(frame, chunks[1]);

        // Draw input
        self.draw_input(frame, chunks[2]);
    }

    fn draw_status_bar(&self, frame: &mut Frame, area: Rect) {
        let status_text = match &self.connection_status {
            ConnectionStatus::Disconnected => {
                Span::styled("Disconnected", Style::default().fg(Color::Red))
            }
            ConnectionStatus::Connecting => {
                Span::styled("Connecting...", Style::default().fg(Color::Yellow))
            }
            ConnectionStatus::Handshaking => {
                Span::styled("Performing key exchange...", Style::default().fg(Color::Yellow))
            }
            ConnectionStatus::Connected => {
                Span::styled("Connected (Quantum-Safe)", Style::default().fg(Color::Green))
            }
            ConnectionStatus::Error(msg) => {
                Span::styled(format!("Error: {}", msg), Style::default().fg(Color::Red))
            }
        };

        let rotation_text = if matches!(self.connection_status, ConnectionStatus::Connected) {
            Span::styled(
                format!(" | Key rotation: {}s", self.key_rotation_countdown),
                Style::default().fg(Color::Cyan),
            )
        } else {
            Span::raw("")
        };

        let status_line = Line::from(vec![
            Span::raw(" "),
            status_text,
            rotation_text,
        ]);

        let status_block = Paragraph::new(status_line)
            .block(Block::default().borders(Borders::ALL).title("Status"));

        frame.render_widget(status_block, area);
    }

    fn draw_messages(&self, frame: &mut Frame, area: Rect) {
        let messages: Vec<ListItem> = self
            .messages
            .iter()
            .skip(self.scroll_offset)
            .map(|msg| {
                let (prefix, style) = match msg.from {
                    MessageSource::Sent => (
                        "> ",
                        Style::default().fg(Color::Blue).add_modifier(Modifier::BOLD),
                    ),
                    MessageSource::Received => (
                        "< ",
                        Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                    ),
                    MessageSource::System => (
                        "* ",
                        Style::default().fg(Color::Yellow).add_modifier(Modifier::ITALIC),
                    ),
                };

                let content = Line::from(vec![
                    Span::styled(&msg.timestamp, Style::default().fg(Color::DarkGray)),
                    Span::raw(" "),
                    Span::styled(prefix, style),
                    Span::styled(&msg.content, style),
                ]);

                ListItem::new(content)
            })
            .collect();

        let messages_list = List::new(messages)
            .block(Block::default().borders(Borders::ALL).title("Messages"));

        frame.render_widget(messages_list, area);
    }

    fn draw_input(&self, frame: &mut Frame, area: Rect) {
        let input_text = Paragraph::new(self.input.as_str())
            .block(Block::default().borders(Borders::ALL).title("Input (Enter to send, Ctrl+C to quit)"))
            .wrap(Wrap { trim: false });

        frame.render_widget(input_text, area);
    }

    pub fn handle_input(&mut self, key: KeyEvent) -> Option<UIEvent> {
        match key.code {
            KeyCode::Char(c) => {
                self.input.push(c);
                None
            }
            KeyCode::Backspace => {
                self.input.pop();
                None
            }
            KeyCode::Enter => {
                if !self.input.trim().is_empty() {
                    let message = self.input.clone();
                    self.input.clear();
                    Some(UIEvent::SendMessage(message))
                } else {
                    None
                }
            }
            KeyCode::Esc => Some(UIEvent::Quit),
            _ => None,
        }
    }
}

impl Default for TerminalUI {
    fn default() -> Self {
        Self::new()
    }
}

/// Run the terminal UI event loop
pub async fn run_ui_loop(
    mut ui: TerminalUI,
    mut rx: mpsc::Receiver<ChatMessage>,
    tx: mpsc::Sender<UIEvent>,
) -> io::Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = RatatuiTerminal::new(backend)?;

    loop {
        // Draw UI
        terminal.draw(|f| {
            ui.draw(f, f.area());
        })?;

        // Handle events (non-blocking)
        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    // Handle Ctrl+C
                    if key.code == KeyCode::Char('c') && key.modifiers.contains(event::KeyModifiers::CONTROL) {
                        let _ = tx.send(UIEvent::Quit).await;
                        break;
                    }

                    if let Some(event) = ui.handle_input(key) {
                        match event {
                            UIEvent::Quit => {
                                let _ = tx.send(UIEvent::Quit).await;
                                break;
                            }
                            other => {
                                let _ = tx.send(other).await;
                            }
                        }
                    }
                }
            }
        }

        // Check for incoming messages
        while let Ok(msg) = rx.try_recv() {
            ui.messages.push(msg);
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_terminal_ui_creation() {
        let ui = TerminalUI::new();
        assert_eq!(ui.messages.len(), 0);
        assert_eq!(ui.input, "");
    }

    #[test]
    fn test_add_message() {
        let mut ui = TerminalUI::new();
        ui.add_message(MessageSource::Sent, "Test message".to_string());
        assert_eq!(ui.messages.len(), 1);
        assert_eq!(ui.messages[0].content, "Test message");
    }

    #[test]
    fn test_input_handling() {
        let mut ui = TerminalUI::new();

        // Type some characters
        ui.handle_input(KeyEvent::from(KeyCode::Char('h')));
        ui.handle_input(KeyEvent::from(KeyCode::Char('i')));
        assert_eq!(ui.input, "hi");

        // Backspace
        ui.handle_input(KeyEvent::from(KeyCode::Backspace));
        assert_eq!(ui.input, "h");
    }

    #[test]
    fn test_status_changes() {
        let mut ui = TerminalUI::new();

        ui.set_status(ConnectionStatus::Connecting);
        assert_eq!(ui.connection_status, ConnectionStatus::Connecting);

        ui.set_status(ConnectionStatus::Connected);
        assert_eq!(ui.connection_status, ConnectionStatus::Connected);
    }
}
