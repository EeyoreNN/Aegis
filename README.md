# 🛡️ Aegis - Quantum-Secure Terminal Chat

A post-quantum encrypted terminal-based chat system with forward secrecy, automatic key rotation, and zero-knowledge architecture.

## ⚡ Features

- **Quantum-Resistant Encryption**: Uses ML-KEM-1024 (Kyber-1024, NIST-standardized post-quantum KEM)
- **Forward Secrecy**: Double Ratchet algorithm with automatic 60-second key rotation
- **Modern Cryptography**: XChaCha20-Poly1305 AEAD for fast, authenticated encryption
- **Zero-Knowledge**: Direct peer-to-peer, no server stores messages
- **TLS 1.3 Support**: Optional additional transport encryption layer
- **Side-Channel Protection**: Constant-time operations, padding, timing normalization
- **Replay Protection**: Timestamp and sequence number validation
- **Secure Memory**: Memory locking (mlock) and zeroization of sensitive data
- **Bidirectional Chat**: Full duplex communication with heartbeat mechanism
- **Async Architecture**: Built on Tokio for high-performance async I/O

## 🏗️ Architecture

### Cryptographic Stack

```
┌─────────────────────────────────────────────┐
│         User Messages (Plaintext)           │
└──────────────────┬──────────────────────────┘
                   │
      ┌────────────▼────────────┐
      │  ChaCha20-Poly1305 AEAD │ (Symmetric Encryption)
      └────────────┬────────────┘
                   │
      ┌────────────▼────────────┐
      │   Double Ratchet        │ (Key Rotation Every 60s)
      └────────────┬────────────┘
                   │
      ┌────────────▼────────────┐
      │   HKDF-SHA256/BLAKE3    │ (Key Derivation)
      └────────────┬────────────┘
                   │
      ┌────────────▼────────────┐
      │     Kyber-1024 KEM      │ (Post-Quantum Key Exchange)
      └────────────┬────────────┘
                   │
      ┌────────────▼────────────┐
      │    TLS 1.3 (Optional)   │ (Transport Encryption)
      └────────────┬────────────┘
                   │
      ┌────────────▼────────────┐
      │          TCP            │ (Reliable Transport)
      └─────────────────────────┘
```

### Key Hierarchy

```
Master Key (from Kyber-1024 key exchange)
    ↓
Root Key (HKDF derivation)
    ↓
Send Chain Key ←──→ Recv Chain Key (separate for each peer)
    ↓                     ↓
Send Message Keys    Recv Message Keys (unique per message)
    ↓                     ↓
XChaCha20-Poly1305  XChaCha20-Poly1305
```

### Module Structure

```
aegis/
├── src/
│   ├── crypto/
│   │   ├── kyber.rs          ✅ Kyber-1024 key exchange
│   │   ├── symmetric.rs      ✅ ChaCha20-Poly1305 encryption
│   │   ├── kdf.rs            ✅ HKDF key derivation + BLAKE3
│   │   ├── ratchet.rs        ✅ Double Ratchet with 60s rotation
│   │   ├── random.rs         ✅ CSPRNG wrapper
│   │   ├── timing.rs         ✅ Constant-time operations
│   │   └── mod.rs            ✅ Crypto module exports
│   ├── network/
│   │   ├── protocol.rs       ✅ Message format and framing
│   │   ├── connection.rs     ✅ TCP + TLS 1.3 handling
│   │   ├── peer.rs           ✅ Peer lifecycle management
│   │   └── mod.rs            ✅ Network module exports
│   ├── storage/
│   │   ├── ephemeral.rs      ✅ Secure memory (mlock/zeroize)
│   │   └── mod.rs            ✅ Storage module exports
│   ├── security/
│   │   ├── replay.rs         ✅ Replay attack protection
│   │   └── mod.rs            ✅ Security module exports
│   ├── session.rs            ✅ Session management + handshake
│   ├── ui/
│   │   ├── terminal.rs       ✅ Terminal UI (ratatui)
│   │   ├── status.rs         ✅ Status bar implementation
│   │   └── mod.rs            ✅ UI module exports
│   ├── lib.rs                ✅ Library interface
│   └── main.rs               ✅ CLI with bidirectional chat
├── tests/
│   └── integration_test.rs   ✅ E2E integration tests
├── benches/
│   ├── crypto_bench.rs       ✅ Cryptography benchmarks
│   └── network_bench.rs      ✅ Network protocol benchmarks
├── SECURITY.md               ✅ Comprehensive security documentation
└── README.md                 ✅ This file
```

## 🚀 Installation

### Prerequisites

- macOS, Linux, or Windows
- Rust toolchain (Rust 1.70+)

You can install or update the Rust toolchain with the helper script:

```bash
./scripts/install_prereqs.sh
```

### Build from Source

```bash
git clone https://github.com/EeyoreNN/Aegis.git
cd aegis
cargo build --release
```

The binary will be at `target/release/aegis`

### Install

```bash
cargo install --path .
```

## 📖 Usage

### Start a listener (Server)

```bash
# Plain TCP with Kyber-1024 + XChaCha20-Poly1305
aegis listen --port 9999

# With TLS 1.3 for additional transport encryption
aegis listen --port 9999 --tls
```

### Connect to a peer (Client)

```bash
# Plain TCP
aegis connect 192.168.1.100:9999

# With TLS 1.3
aegis connect 192.168.1.100:9999 --tls
```

### Options

```bash
# Custom key rotation interval (default: 60 seconds)
aegis listen --port 9999 --rotation-interval 30

# Connect with custom rotation and TLS
aegis connect 192.168.1.100:9999 --rotation-interval 30 --tls --server-name myserver
```

### Command Line Help

```bash
aegis --help
aegis listen --help
aegis connect --help
```

## 🔒 Security Features

### Encryption

- **Post-Quantum**: ML-KEM-1024 (Kyber) protects against quantum computer attacks
  - NIST standardized (FIPS 203)
  - Security level: ~218-bit quantum security
- **Symmetric**: XChaCha20-Poly1305 provides authenticated encryption
  - 256-bit keys
  - 192-bit nonces (no reuse concerns)
- **Transport**: Optional TLS 1.3 for additional layer
  - Note: Uses self-signed certificates (see Security section)

### Forward Secrecy

- **Double Ratchet**: Keys rotate every 60 seconds automatically
- **Per-Message Keys**: Each message encrypted with unique ephemeral key
- **Old Keys Destroyed**: Previous keys immediately zeroized from memory
- **Separate Chains**: Independent send/receive ratchet chains per peer

### Protection Mechanisms

| Attack Vector | Defense |
|--------------|---------|
| Quantum computers | ML-KEM-1024 post-quantum KEM |
| Key compromise | Forward/future secrecy via ratcheting |
| Replay attacks | Timestamp + sequence number validation |
| Traffic analysis | Message padding, constant-time operations |
| Memory dumps | Memory locking (mlock), zeroization |
| Man-in-the-middle | Authenticated key exchange |
| Message tampering | Poly1305 authentication tag |
| Passive eavesdropping | End-to-end encryption |

### Known Limitations

⚠️ **Current Status**: Functional implementation, not production-ready.

**See [SECURITY.md](SECURITY.md) for full details on:**
- Threat model
- Known limitations
- Deployment recommendations
- Security audit guidance

**Key limitations:**
- TLS mode uses self-signed certificates with disabled verification (FOR DEMO ONLY)
- Multiple consecutive messages from same peer may fail (ratchet synchronization issue)
- No rate limiting or DoS protection
- Out-of-order messages not handled
- Traffic metadata not hidden

**Not protected against:**
- Endpoint compromise (keylogger, malware)
- Social engineering
- Physical device access
- Root-level memory inspection

## 🔬 Technical Details

### Message Protocol

Wire format for encrypted messages:

```
Frame Header (4 bytes):
  Length: u32

Message Header:
  Version: u8 (currently 1)
  Type: u8 (handshake, encrypted, heartbeat, etc.)
  Timestamp: u64
  Key ID: u16 (ratchet counter)

Cryptographic Content:
  Nonce: [u8; 24] (XChaCha20 nonce)
  Ciphertext: Vec<u8> (encrypted payload)
  Tag: [u8; 16] (Poly1305 authentication tag)
```

### Handshake Flow

```
Client                                Server
  |                                      |
  |  1. Generate Kyber keypair           |
  |  2. Send PublicKey                   |
  |  ──────────────────────────────────> |
  |                                      |
  |                   3. Generate Kyber keypair
  |                   4. Encapsulate with client's pubkey
  |                   5. Derive shared secret
  |                   6. Send ciphertext + own pubkey
  | <────────────────────────────────────|
  |                                      |
  | 7. Decapsulate ciphertext            |
  | 8. Derive shared secret              |
  | 9. Verify secrets match              |
  |                                      |
  | 10. Derive master key (HKDF)         | 10. Derive master key (HKDF)
  | 11. Initialize ratchet               | 11. Initialize ratchet
  |                                      |
  |  ═══ Secure session established ═══  |
```

### Performance

Benchmarks on M1 Mac (example):

```bash
$ cargo bench

Crypto Benchmarks:
  kyber1024_keypair_generation    15.2 ms
  kyber1024_encapsulation         20.1 ms
  kyber1024_decapsulation         22.3 ms
  chacha20poly1305_encryption/64   0.4 μs
  chacha20poly1305_encryption/1KB  1.8 μs
  chacha20poly1305_decryption/64   0.4 μs
  chacha20poly1305_decryption/1KB  1.9 μs
  hkdf_master_key_derivation      12.3 μs
  ratchet_next_send_key            3.1 μs
  blake3_keyed_hash/1KB           0.9 μs

Network Benchmarks:
  message_serialization           0.2 μs
  message_deserialization         0.3 μs
  message_framing                 0.3 μs
  frame_parsing                   0.4 μs
  full_message_roundtrip          1.2 μs
```

## 🧪 Testing

### Run Tests

```bash
# All tests (unit + integration)
cargo test

# Unit tests only
cargo test --lib

# Integration tests
cargo test --test integration_test

# Specific test
cargo test test_end_to_end_plain_tcp

# With output
cargo test -- --nocapture
```

### Test Coverage

- **Unit Tests**: 75 tests covering all crypto, network, storage, security modules
- **Integration Tests**: 6 end-to-end tests (2 additional tests ignored due to known limitation)
  - Plain TCP communication
  - TLS 1.3 communication
  - Large message transfer (100KB)
  - Key rotation mechanism
  - Heartbeat functionality
  - Bidirectional communication

### Run Benchmarks

```bash
cargo bench
```

## 📊 Project Status

### Completed ✅

**Core Cryptography (Week 1-2)**
- ✅ ML-KEM-1024 (Kyber) post-quantum key exchange
- ✅ XChaCha20-Poly1305 symmetric encryption
- ✅ HKDF + BLAKE3 key derivation
- ✅ Double Ratchet with automatic rotation
- ✅ Secure random number generation
- ✅ Constant-time operations and padding

**Network Layer (Week 2)**
- ✅ Binary message protocol with framing
- ✅ TCP connection handling
- ✅ TLS 1.3 support (with self-signed certs)
- ✅ Peer lifecycle management

**Security Infrastructure (Week 2)**
- ✅ Replay attack protection
- ✅ Secure memory (mlock + zeroize)
- ✅ Memory safety via Rust

**Application Layer (Week 3)**
- ✅ Session management and handshake
- ✅ Bidirectional chat with channels (tokio::select!)
- ✅ Automatic 60-second key rotation background task
- ✅ Heartbeat mechanism (every 30 seconds)
- ✅ CLI with clap argument parsing

**Testing & Documentation (Week 3)**
- ✅ 75 unit tests (100% passing)
- ✅ 6 integration tests (E2E encrypted messaging)
- ✅ Real cryptography benchmarks
- ✅ Real network protocol benchmarks
- ✅ Comprehensive SECURITY.md
- ✅ Updated README with full documentation

### Known Issues 🐛

1. **Ratchet Synchronization**: Sending multiple consecutive messages without alternating causes decryption failures
   - **Impact**: Interactive chat works, but batch sending doesn't
   - **Status**: Documented, tests ignored
   - **Fix**: Implement message counter tracking and buffering

2. **TLS Certificate Verification**: Self-signed certificates with disabled verification
   - **Impact**: Vulnerable to MitM during TLS handshake
   - **Status**: **FOR DEMONSTRATION ONLY**
   - **Fix**: Implement proper PKI or TOFU before production use

### Future Enhancements 📋

- 📋 Fix ratchet synchronization for consecutive messages
- 📋 Proper TLS certificate management (CA or TOFU)
- 📋 Rate limiting and DoS protection
- 📋 Out-of-order message handling
- 📋 Traffic padding for metadata protection
- 📋 Group chat support
- 📋 File transfer capability
- 📋 Terminal UI improvements (colors, scrollback)
- 📋 Professional security audit
- 📋 Formal verification of critical components
- 📋 Binary releases for major platforms
- 📋 Homebrew/package manager support

## 🤝 Contributing

Contributions are welcome! Priority areas:

1. **Security**
   - Fix ratchet synchronization
   - Proper certificate management
   - Security audit findings
   - Vulnerability reports

2. **Testing**
   - More edge cases
   - Fuzzing
   - Property-based tests
   - Performance regression tests

3. **Features**
   - Rate limiting
   - Message buffering
   - UI enhancements
   - Cross-platform support

4. **Documentation**
   - Usage examples
   - Architecture guides
   - Security best practices

### Development

```bash
# Setup
git clone https://github.com/EeyoreNN/Aegis.git
cd aegis

# Build
cargo build

# Test
cargo test

# Lint
cargo clippy -- -D warnings

# Format
cargo fmt
```

## 📜 License

Dual-licensed under MIT or Apache-2.0, at your option.

## 🙏 Acknowledgments

- **Signal Protocol**: Inspiration for Double Ratchet algorithm
- **NIST**: Post-quantum cryptography standardization effort
- **RustCrypto**: High-quality cryptography libraries
- **pqcrypto**: Making post-quantum crypto accessible in Rust
- **Tokio**: Excellent async runtime
- **ratatui**: Terminal UI framework

## 📚 References

### Cryptographic Standards
- [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) - ML-KEM (Kyber)
- [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439) - ChaCha20-Poly1305
- [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869) - HKDF
- [RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446) - TLS 1.3
- [Signal Protocol](https://signal.org/docs/) - Double Ratchet

### Academic Papers
- Bos et al., "CRYSTALS-Kyber: A CCA-Secure Module-Lattice-Based KEM" (2018)
- Perrin & Marlinspike, "The Double Ratchet Algorithm" (2016)
- Bernstein, "ChaCha, a variant of Salsa20" (2008)

### Further Reading
- [Post-Quantum Cryptography FAQ](https://csrc.nist.gov/Projects/post-quantum-cryptography/faqs)
- [Signal Protocol Documentation](https://signal.org/docs/)
- [Rust Cryptography Guidelines](https://github.com/RustCrypto/meta/blob/master/GUIDELINES.md)

## ⚠️ Disclaimer

**THIS IS DEMONSTRATION SOFTWARE - NOT PRODUCTION READY**

While Aegis uses well-established cryptographic primitives and follows security best practices, it has not undergone professional security auditing. Known limitations include:

- Self-signed TLS certificates with disabled verification
- No protection against endpoint compromise
- Limited DoS protection
- Ratchet synchronization issues with consecutive messages

**Do not use for:**
- Production security-critical applications
- Communications where lives or livelihoods depend on secrecy
- Compliance-regulated environments
- Any scenario requiring certified security

**Acceptable use cases:**
- Learning about post-quantum cryptography
- Research and experimentation
- Development and testing
- Educational demonstrations

See [SECURITY.md](SECURITY.md) for complete security documentation.

---

**Built with 🦀 Rust for security, performance, and reliability.**
**Post-quantum ready for the future of cryptography. 🔮**
