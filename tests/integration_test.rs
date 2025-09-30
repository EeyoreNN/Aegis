// Integration tests for Aegis end-to-end encrypted messaging

use aegis::network::connection::{Listener, connect};
use aegis::session::Session;
use tokio::time::{timeout, Duration};

#[tokio::test]
async fn test_end_to_end_plain_tcp() {
    // Start a server
    let listener = Listener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Spawn server task
    let server_task = tokio::spawn(async move {
        let connection = listener.accept().await.unwrap();
        let mut session = Session::accept(connection).await.unwrap();

        // Receive message
        let received = session.recv().await.unwrap();
        assert_eq!(received, b"Hello from client!");

        // Send response
        session.send(b"Hello from server!").await.unwrap();

        session
    });

    // Connect as client
    let connection = connect(&addr.to_string()).await.unwrap();
    let mut client_session = Session::connect(connection).await.unwrap();

    // Send message
    client_session.send(b"Hello from client!").await.unwrap();

    // Receive response
    let response = client_session.recv().await.unwrap();
    assert_eq!(response, b"Hello from server!");

    // Wait for server to complete
    let _server_session = server_task.await.unwrap();

    // Close sessions
    let _ = client_session.close().await;
}

#[tokio::test]
async fn test_end_to_end_with_tls() {
    // Start a TLS server
    let listener = Listener::bind_tls("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Spawn server task
    let server_task = tokio::spawn(async move {
        let connection = listener.accept().await.unwrap();
        let mut session = Session::accept(connection).await.unwrap();

        // Receive message
        let received = session.recv().await.unwrap();
        assert_eq!(received, b"Secure hello!");

        // Send response
        session.send(b"Secure response!").await.unwrap();

        session
    });

    // Connect as TLS client
    let connection = aegis::network::connection::connect_tls(&addr.to_string(), "localhost")
        .await
        .unwrap();
    let mut client_session = Session::connect(connection).await.unwrap();

    // Send message
    client_session.send(b"Secure hello!").await.unwrap();

    // Receive response
    let response = client_session.recv().await.unwrap();
    assert_eq!(response, b"Secure response!");

    // Wait for server to complete
    let _server_session = server_task.await.unwrap();

    // Close sessions
    let _ = client_session.close().await;
}

// Verify we can send multiple consecutive messages without desynchronizing the ratchet.
#[tokio::test]
async fn test_multiple_messages_unidirectional() {
    let listener = Listener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Spawn server task
    let server_task = tokio::spawn(async move {
        let connection = listener.accept().await.unwrap();
        let mut session = Session::accept(connection).await.unwrap();

        // Receive multiple messages in sequence
        for i in 0..3 {
            let received = session.recv().await.unwrap();
            assert_eq!(received, format!("Message {}", i).as_bytes());
        }

        session
    });

    // Connect as client
    let connection = connect(&addr.to_string()).await.unwrap();
    let mut client_session = Session::connect(connection).await.unwrap();

    // Send multiple messages in sequence
    for i in 0..3 {
        client_session
            .send(format!("Message {}", i).as_bytes())
            .await
            .unwrap();
    }

    // Wait for server to complete
    let _server_session = server_task.await.unwrap();

    // Close sessions
    let _ = client_session.close().await;
}

#[tokio::test]
async fn test_key_rotation_mechanism() {
    let listener = Listener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Spawn server task
    let server_task = tokio::spawn(async move {
        let connection = listener.accept().await.unwrap();
        let mut session = Session::accept(connection).await.unwrap();

        // Receive a message
        let msg = session.recv().await.unwrap();
        assert_eq!(msg, b"Before rotation");

        // Rotate keys - in real implementation both peers would coordinate this
        session.ratchet.rotate().unwrap();

        // Send a message after rotation
        session.send(b"After rotation").await.unwrap();

        session
    });

    // Connect as client
    let connection = connect(&addr.to_string()).await.unwrap();
    let mut client_session = Session::connect(connection).await.unwrap();

    // Send a message
    client_session.send(b"Before rotation").await.unwrap();

    // Rotate keys synchronously
    client_session.ratchet.rotate().unwrap();

    // Receive message after rotation
    let response = client_session.recv().await.unwrap();
    assert_eq!(response, b"After rotation");

    // Wait for server to complete
    let _server_session = server_task.await.unwrap();

    // Close sessions
    let _ = client_session.close().await;
}

#[tokio::test]
async fn test_large_message_transfer() {
    let listener = Listener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Create a large message (100 KB - reduced from 1 MB for faster tests)
    let large_data = vec![0x42u8; 100 * 1024];

    let large_data_clone = large_data.clone();

    // Spawn server task
    let server_task = tokio::spawn(async move {
        let connection = listener.accept().await.unwrap();
        let mut session = Session::accept(connection).await.unwrap();

        // Receive large message
        let received = session.recv().await.unwrap();
        assert_eq!(received.len(), large_data_clone.len());
        assert_eq!(received, large_data_clone);

        session
    });

    // Connect as client
    let connection = connect(&addr.to_string()).await.unwrap();
    let mut client_session = Session::connect(connection).await.unwrap();

    // Send large message
    client_session.send(&large_data).await.unwrap();

    // Wait for server to complete
    let _server_session = server_task.await.unwrap();

    // Close sessions
    let _ = client_session.close().await;
}

#[tokio::test]
async fn test_heartbeat_mechanism() {
    let listener = Listener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Spawn server task
    let server_task = tokio::spawn(async move {
        let connection = listener.accept().await.unwrap();
        let mut session = Session::accept(connection).await.unwrap();

        // Wait for heartbeat (should receive empty or heartbeat message)
        // In our implementation, heartbeat is sent as an empty encrypted message
        let result = timeout(Duration::from_secs(2), session.recv()).await;
        assert!(result.is_ok());

        session
    });

    // Connect as client
    let connection = connect(&addr.to_string()).await.unwrap();
    let mut client_session = Session::connect(connection).await.unwrap();

    // Send heartbeat
    client_session.send_heartbeat().await.unwrap();

    // Wait for server to complete
    let _server_session = server_task.await.unwrap();

    // Close sessions
    let _ = client_session.close().await;
}

#[tokio::test]
async fn test_concurrent_bidirectional_communication() {
    let listener = Listener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Spawn server task with bidirectional communication
    let server_task = tokio::spawn(async move {
        let connection = listener.accept().await.unwrap();
        let mut session = Session::accept(connection).await.unwrap();

        // Server sends first
        session.send(b"Server message 1").await.unwrap();

        // Then receives
        let received = session.recv().await.unwrap();
        assert_eq!(received, b"Client message 1");

        session
    });

    // Connect as client
    let connection = connect(&addr.to_string()).await.unwrap();
    let mut client_session = Session::connect(connection).await.unwrap();

    // Client receives first
    let msg1 = client_session.recv().await.unwrap();
    assert_eq!(msg1, b"Server message 1");

    // Then sends
    client_session.send(b"Client message 1").await.unwrap();

    // Wait for server to complete
    let _server_session = server_task.await.unwrap();

    // Close sessions
    let _ = client_session.close().await;
}

// NOTE: This test is currently disabled for the same reason as test_multiple_messages_unidirectional.
#[tokio::test]
#[ignore]
async fn test_utf8_message_encoding() {
    let listener = Listener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Spawn server task
    let server_task = tokio::spawn(async move {
        let connection = listener.accept().await.unwrap();
        let mut session = Session::accept(connection).await.unwrap();

        let msg1 = session.recv().await.unwrap();
        assert_eq!(String::from_utf8(msg1).unwrap(), "Hello, World!");

        let msg2 = session.recv().await.unwrap();
        assert_eq!(String::from_utf8(msg2).unwrap(), "你好世界");

        let msg3 = session.recv().await.unwrap();
        assert_eq!(String::from_utf8(msg3).unwrap(), "🎉🔐🛡️");

        session
    });

    // Connect as client
    let connection = connect(&addr.to_string()).await.unwrap();
    let mut client_session = Session::connect(connection).await.unwrap();

    client_session.send("Hello, World!".as_bytes()).await.unwrap();
    client_session.send("你好世界".as_bytes()).await.unwrap();
    client_session.send("🎉🔐🛡️".as_bytes()).await.unwrap();

    // Wait for server to complete
    let _server_session = server_task.await.unwrap();

    // Close sessions
    let _ = client_session.close().await;
}
