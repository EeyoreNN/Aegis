// TCP connection handler with TLS 1.3
// Provides secure, async network connections

use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use rustls::{ServerConfig, ClientConfig, RootCertStore};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use std::sync::Arc;
use std::net::SocketAddr;
use thiserror::Error;

use super::{NetworkError, protocol::{Message, frame_message, parse_framed_message}};

const READ_BUFFER_SIZE: usize = 8192;

#[derive(Error, Debug)]
pub enum ConnectionError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("Connection closed")]
    Closed,

    #[error("Timeout")]
    Timeout,

    #[error("Handshake failed: {0}")]
    HandshakeFailed(String),
}

/// Connection stream type
enum ConnectionStream {
    Plain(TcpStream),
    TlsClient(Box<tokio_rustls::client::TlsStream<TcpStream>>),
    TlsServer(Box<tokio_rustls::server::TlsStream<TcpStream>>),
}

/// Represents an active connection with optional TLS
pub struct Connection {
    stream: ConnectionStream,
    peer_addr: SocketAddr,
    buffer: Vec<u8>,
}

impl Connection {
    /// Create a new plain TCP connection
    pub fn from_tcp(stream: TcpStream, peer_addr: SocketAddr) -> Self {
        Self {
            stream: ConnectionStream::Plain(stream),
            peer_addr,
            buffer: Vec::with_capacity(READ_BUFFER_SIZE),
        }
    }

    /// Create a new TLS client connection
    pub fn from_tls_client(stream: tokio_rustls::client::TlsStream<TcpStream>, peer_addr: SocketAddr) -> Self {
        Self {
            stream: ConnectionStream::TlsClient(Box::new(stream)),
            peer_addr,
            buffer: Vec::with_capacity(READ_BUFFER_SIZE),
        }
    }

    /// Create a new TLS server connection
    pub fn from_tls_server(stream: tokio_rustls::server::TlsStream<TcpStream>, peer_addr: SocketAddr) -> Self {
        Self {
            stream: ConnectionStream::TlsServer(Box::new(stream)),
            peer_addr,
            buffer: Vec::with_capacity(READ_BUFFER_SIZE),
        }
    }

    /// Send a message over the connection
    pub async fn send_message(&mut self, message: &Message) -> Result<(), NetworkError> {
        let framed = frame_message(message)?;

        match &mut self.stream {
            ConnectionStream::Plain(stream) => {
                stream.write_all(&framed).await?;
                stream.flush().await?;
            }
            ConnectionStream::TlsClient(stream) => {
                stream.write_all(&framed).await?;
                stream.flush().await?;
            }
            ConnectionStream::TlsServer(stream) => {
                stream.write_all(&framed).await?;
                stream.flush().await?;
            }
        }

        Ok(())
    }

    /// Receive a message from the connection
    pub async fn recv_message(&mut self) -> Result<Message, NetworkError> {
        loop {
            // Try to parse a message from the buffer
            if self.buffer.len() >= 4 {
                match parse_framed_message(&self.buffer) {
                    Ok((message, consumed)) => {
                        self.buffer.drain(..consumed);
                        return Ok(message);
                    }
                    Err(NetworkError::ProtocolError(ref e)) if e.contains("Incomplete") => {
                        // Need more data, continue reading
                    }
                    Err(e) => return Err(e),
                }
            }

            // Read more data from the stream
            let mut temp_buf = vec![0u8; READ_BUFFER_SIZE];
            let n = match &mut self.stream {
                ConnectionStream::Plain(stream) => stream.read(&mut temp_buf).await?,
                ConnectionStream::TlsClient(stream) => stream.read(&mut temp_buf).await?,
                ConnectionStream::TlsServer(stream) => stream.read(&mut temp_buf).await?,
            };

            if n == 0 {
                return Err(NetworkError::ConnectionError("Connection closed by peer".to_string()));
            }

            self.buffer.extend_from_slice(&temp_buf[..n]);
        }
    }

    /// Get the peer address
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// Close the connection
    pub async fn close(mut self) -> Result<(), NetworkError> {
        match &mut self.stream {
            ConnectionStream::Plain(stream) => {
                stream.shutdown().await?;
            }
            ConnectionStream::TlsClient(stream) => {
                stream.shutdown().await?;
            }
            ConnectionStream::TlsServer(stream) => {
                stream.shutdown().await?;
            }
        }
        Ok(())
    }
}

/// Listen for incoming connections
pub struct Listener {
    tcp_listener: TcpListener,
    tls_acceptor: Option<Arc<TlsAcceptor>>,
}

impl Listener {
    /// Bind to an address without TLS
    pub async fn bind(addr: &str) -> Result<Self, NetworkError> {
        let tcp_listener = TcpListener::bind(addr).await?;
        Ok(Self {
            tcp_listener,
            tls_acceptor: None,
        })
    }

    /// Bind to an address with TLS
    pub async fn bind_tls(addr: &str) -> Result<Self, NetworkError> {
        let tcp_listener = TcpListener::bind(addr).await?;

        // Generate self-signed certificate
        let (certs, key) = generate_self_signed_cert()?;

        // Create TLS config
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| NetworkError::ConnectionError(format!("TLS config error: {}", e)))?;

        let acceptor = TlsAcceptor::from(Arc::new(config));

        Ok(Self {
            tcp_listener,
            tls_acceptor: Some(Arc::new(acceptor)),
        })
    }

    /// Accept a new connection
    pub async fn accept(&self) -> Result<Connection, NetworkError> {
        let (stream, peer_addr) = self.tcp_listener.accept().await?;

        if let Some(acceptor) = &self.tls_acceptor {
            let tls_stream = acceptor
                .accept(stream)
                .await
                .map_err(|e| NetworkError::ConnectionError(format!("TLS accept failed: {}", e)))?;

            Ok(Connection::from_tls_server(tls_stream, peer_addr))
        } else {
            Ok(Connection::from_tcp(stream, peer_addr))
        }
    }

    /// Get the local address
    pub fn local_addr(&self) -> Result<SocketAddr, NetworkError> {
        Ok(self.tcp_listener.local_addr()?)
    }
}

/// Connect to a remote peer without TLS
pub async fn connect(addr: &str) -> Result<Connection, NetworkError> {
    let stream = TcpStream::connect(addr).await?;
    let peer_addr = stream.peer_addr()?;

    Ok(Connection::from_tcp(stream, peer_addr))
}

/// Connect to a remote peer with TLS
pub async fn connect_tls(addr: &str, server_name: &str) -> Result<Connection, NetworkError> {
    let stream = TcpStream::connect(addr).await?;
    let peer_addr = stream.peer_addr()?;

    // Create TLS config (accepting self-signed certs for demo)
    let root_store = RootCertStore::empty();

    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));

    let server_name = ServerName::try_from(server_name.to_string())
        .map_err(|e| NetworkError::ConnectionError(format!("Invalid server name: {}", e)))?;

    let tls_stream = connector
        .connect(server_name, stream)
        .await
        .map_err(|e| NetworkError::ConnectionError(format!("TLS connect failed: {}", e)))?;

    Ok(Connection::from_tls_client(tls_stream, peer_addr))
}

/// Skip server verification for self-signed certificates (DEMO ONLY - NOT FOR PRODUCTION)
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer,
        _intermediates: &[CertificateDer],
        _server_name: &ServerName,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

/// Generate self-signed certificate for TLS (for testing/demo purposes)
pub fn generate_self_signed_cert() -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), NetworkError> {
    use rcgen::generate_simple_self_signed;

    let subject_alt_names = vec!["localhost".to_string(), "127.0.0.1".to_string()];

    let cert = generate_simple_self_signed(subject_alt_names)
        .map_err(|e| NetworkError::ConnectionError(format!("Certificate generation failed: {}", e)))?;

    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_bytes = cert.key_pair.serialized_der().to_vec();
    let key_der = PrivateKeyDer::Pkcs8(key_bytes.into());

    Ok((vec![cert_der], key_der))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::protocol::Message;

    #[tokio::test]
    async fn test_listener_bind() {
        let listener = Listener::bind("127.0.0.1:0").await.unwrap();
        assert!(listener.local_addr().is_ok());
    }

    #[tokio::test]
    async fn test_connection_message_roundtrip() {
        // Start a listener
        let listener = Listener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Spawn accept task
        let accept_handle = tokio::spawn(async move {
            listener.accept().await
        });

        // Connect to the listener
        let mut client = connect(&addr.to_string()).await.unwrap();

        // Accept the connection
        let mut server = accept_handle.await.unwrap().unwrap();

        // Send a message from client to server
        let msg = Message::heartbeat();
        client.send_message(&msg).await.unwrap();

        // Receive on server
        let received = server.recv_message().await.unwrap();
        assert_eq!(received.message_type, msg.message_type);
    }

    #[test]
    fn test_generate_self_signed_cert() {
        let result = generate_self_signed_cert();
        assert!(result.is_ok());

        let (certs, key) = result.unwrap();
        assert!(!certs.is_empty());
    }
}
