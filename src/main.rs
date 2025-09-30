// Aegis - Quantum-Secure Terminal Chat System
// A post-quantum encrypted messaging system with forward secrecy

mod crypto;
mod network;
mod storage;
mod ui;
mod security;
mod session;

use clap::Parser;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use std::io::Write;

#[derive(Parser, Debug)]
#[command(name = "aegis")]
#[command(author = "Aegis Contributors")]
#[command(version = "0.1.0")]
#[command(about = "Quantum-secure terminal chat system", long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Parser, Debug)]
enum Commands {
    /// Start server and listen for connections
    Listen {
        /// Port to listen on
        #[arg(short, long, default_value = "9999")]
        port: u16,

        /// Key rotation interval in seconds
        #[arg(short = 'r', long, default_value = "60")]
        rotation_interval: u64,

        /// Use TLS 1.3 encryption
        #[arg(short, long)]
        tls: bool,
    },

    /// Connect to a peer
    Connect {
        /// Address to connect to (host:port)
        address: String,

        /// Key rotation interval in seconds
        #[arg(short = 'r', long, default_value = "60")]
        rotation_interval: u64,

        /// Use TLS 1.3 encryption
        #[arg(short, long)]
        tls: bool,

        /// Server name for TLS verification
        #[arg(short = 's', long, default_value = "localhost")]
        server_name: String,
    },
}

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();

    println!("🛡️  Aegis - Quantum-Secure Terminal Chat");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();

    let result = match args.command {
        Commands::Listen { port, rotation_interval, tls } => {
            run_server(port, rotation_interval, tls).await
        }
        Commands::Connect { address, rotation_interval, tls, server_name } => {
            run_client(&address, rotation_interval, tls, &server_name).await
        }
    };

    if let Err(e) = result {
        eprintln!("❌ Error: {}", e);
        std::process::exit(1);
    }
}

async fn run_server(port: u16, rotation_interval: u64, use_tls: bool) -> Result<(), Box<dyn std::error::Error>> {
    use network::connection::Listener;
    use session::Session;

    println!("🔊 Listening on port {}...", port);
    if use_tls {
        println!("🔐 TLS 1.3 enabled");
    }
    println!("⏳ Waiting for connection...");

    let listener = if use_tls {
        Listener::bind_tls(&format!("0.0.0.0:{}", port)).await?
    } else {
        Listener::bind(&format!("0.0.0.0:{}", port)).await?
    };

    let connection = listener.accept().await?;

    println!("✅ Connection established from {}", connection.peer_addr());
    println!("🔐 Performing quantum-safe key exchange...");

    let session = Session::accept(connection).await?;

    println!("✅ Secure session established!");
    println!("🔑 Key rotation every {} seconds", rotation_interval);
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Type messages and press Enter to send. Ctrl+C to quit.");
    println!();

    run_chat_loop(session, rotation_interval).await
}

async fn run_client(address: &str, rotation_interval: u64, use_tls: bool, server_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    use network::connection::{connect, connect_tls};
    use session::Session;

    println!("🔌 Connecting to {}...", address);
    if use_tls {
        println!("🔐 TLS 1.3 enabled");
    }

    let connection = if use_tls {
        connect_tls(address, server_name).await?
    } else {
        connect(address).await?
    };

    println!("✅ Connected to {}", connection.peer_addr());
    println!("🔐 Performing quantum-safe key exchange...");

    let session = Session::connect(connection).await?;

    println!("✅ Secure session established!");
    println!("🔑 Key rotation every {} seconds", rotation_interval);
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Type messages and press Enter to send. Ctrl+C to quit.");
    println!();

    run_chat_loop(session, rotation_interval).await
}

async fn run_chat_loop(mut session: session::Session, rotation_interval: u64) -> Result<(), Box<dyn std::error::Error>> {
    // Create channel for stdin input
    let (stdin_tx, mut stdin_rx) = mpsc::channel::<String>(100);

    // Spawn task to read from stdin
    tokio::spawn(async move {
        let stdin = tokio::io::stdin();
        let mut reader = BufReader::new(stdin);
        let mut line = String::new();

        loop {
            print!("> ");
            let _ = std::io::stdout().flush();

            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => break, // EOF
                Ok(_) => {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() {
                        if stdin_tx.send(trimmed.to_string()).await.is_err() {
                            break;
                        }
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Create timers for key rotation and heartbeat
    let mut rotation_timer = interval(Duration::from_secs(rotation_interval));
    rotation_timer.tick().await; // Skip first immediate tick

    let mut heartbeat_timer = interval(Duration::from_secs(30));
    heartbeat_timer.tick().await; // Skip first immediate tick

    // Main event loop using tokio::select!
    loop {
        tokio::select! {
            // Handle stdin input
            Some(text) = stdin_rx.recv() => {
                if let Err(e) = session.send(text.as_bytes()).await {
                    eprintln!("\r❌ Send error: {}", e);
                    break;
                }
            }

            // Handle incoming network messages
            result = session.recv() => {
                match result {
                    Ok(data) => {
                        if !data.is_empty() {
                            let text = String::from_utf8_lossy(&data);
                            println!("\r< {}", text);
                            print!("> ");
                            let _ = std::io::stdout().flush();
                        }
                    }
                    Err(e) => {
                        eprintln!("\r❌ Receive error: {}", e);
                        break;
                    }
                }
            }

            // Handle key rotation timer
            _ = rotation_timer.tick() => {
                if let Err(e) = session.ratchet.rotate() {
                    eprintln!("\r❌ Key rotation error: {}", e);
                    break;
                } else {
                    println!("\r🔑 Keys rotated");
                    print!("> ");
                    let _ = std::io::stdout().flush();
                }
            }

            // Handle heartbeat timer
            _ = heartbeat_timer.tick() => {
                if let Err(e) = session.send_heartbeat().await {
                    eprintln!("\r❌ Heartbeat error: {}", e);
                    break;
                }
            }
        }
    }

    // Close session
    let _ = session.close().await;

    println!("\r👋 Disconnected");
    Ok(())
}
