# Aegis Security Documentation

## Overview

Aegis is a quantum-secure terminal chat system designed with security as its primary goal. This document outlines the cryptographic primitives, security architecture, threat model, and security considerations.

## Cryptographic Primitives

### Post-Quantum Key Exchange
- **Algorithm**: ML-KEM-1024 (Kyber-1024)
- **Security Level**: NIST Level 5 (~256-bit classical, ~218-bit quantum security)
- **Purpose**: Initial key establishment resistant to quantum computer attacks
- **Library**: `pqcrypto-kyber` v0.8
- **Standard**: NIST PQC standardization (Module-Lattice-Based KEM)

### Symmetric Encryption
- **Algorithm**: XChaCha20-Poly1305
- **Key Size**: 256 bits
- **Nonce Size**: 192 bits (24 bytes)
- **Purpose**: Authenticated encryption of messages
- **Library**: `chacha20poly1305` v0.10
- **Properties**:
  - Authenticated encryption with associated data (AEAD)
  - Probabilistically secure against chosen-ciphertext attacks
  - Large nonce space prevents nonce reuse

### Key Derivation
- **Primary**: HKDF with SHA-256
  - Used for master key derivation from shared secrets
  - Extract-and-expand paradigm for key material
- **Secondary**: BLAKE3
  - Keyed hashing for ratchet chain derivation
  - Extremely fast with strong security guarantees
  - Output length: 256 bits

### Forward Secrecy
- **Algorithm**: Double Ratchet (Signal Protocol-inspired)
- **Rotation Interval**: 60 seconds (configurable)
- **Properties**:
  - Compromised keys don't affect past messages
  - Automatic key rotation for ongoing sessions
  - Separate send and receive chains per peer

### Memory Safety
- **Language**: Rust (memory-safe by design)
- **Key Zeroization**: All sensitive data zeroized on drop
- **Memory Locking**: mlock/VirtualLock on key material (OS-dependent)
- **Library**: `zeroize` v1.8 with `ZeroizeOnDrop`

## Architecture

### Zero-Knowledge Design
- **No Central Server**: Peer-to-peer architecture
- **No Key Escrow**: No third party can decrypt messages
- **No Metadata Collection**: No telemetry or usage tracking
- **Ephemeral Keys**: Session keys exist only in RAM

### Network Layers

```
Application Layer:  Chat messages
Session Layer:      Double Ratchet + XChaCha20-Poly1305
Handshake Layer:    Kyber-1024 key exchange
Transport Layer:    TLS 1.3 (optional) + TCP
```

### Message Format

```
┌─────────────────────────────────────────────────────────────┐
│ Frame Header (4 bytes)                                       │
│   - Length (u32): Total message length                       │
├─────────────────────────────────────────────────────────────┤
│ Message Header                                               │
│   - Version (1 byte): Protocol version                       │
│   - Type (1 byte): Message type                              │
│   - Timestamp (8 bytes): Unix timestamp                      │
│   - Key ID (2 bytes): Ratchet counter                        │
├─────────────────────────────────────────────────────────────┤
│ Nonce (24 bytes): XChaCha20 nonce                           │
├─────────────────────────────────────────────────────────────┤
│ Ciphertext (variable): Encrypted payload                     │
├─────────────────────────────────────────────────────────────┤
│ Auth Tag (16 bytes): Poly1305 authentication tag            │
└─────────────────────────────────────────────────────────────┘
```

## Threat Model

### In Scope

1. **Passive Network Eavesdropping**: Attacker observes all network traffic
   - **Mitigation**: End-to-end encryption with XChaCha20-Poly1305
   - **Additional**: Optional TLS 1.3 for transport encryption

2. **Active Network Attacks**: Man-in-the-middle, replay attacks
   - **Mitigation**: Authenticated encryption, timestamp validation
   - **Replay Protection**: 5-minute time window, sequence number tracking

3. **Quantum Computer Attacks**: Future quantum adversary with Shor's algorithm
   - **Mitigation**: ML-KEM-1024 post-quantum key exchange
   - **Security Level**: 218-bit quantum security

4. **Memory Forensics**: Attacker gains access to RAM dumps
   - **Mitigation**: Secure memory with mlock, immediate zeroization
   - **Limitation**: Cannot prevent root-level real-time memory inspection

5. **Compromise of Long-Term Keys**: Attacker obtains past session keys
   - **Mitigation**: Forward secrecy via Double Ratchet
   - **Guarantee**: Past messages remain secure

### Out of Scope

1. **Endpoint Compromise**: Malware, keyloggers, screen capture on user's machine
2. **Side-Channel Attacks**: Timing attacks, power analysis (some mitigations in place)
3. **Denial of Service**: Resource exhaustion attacks
4. **Traffic Analysis**: Metadata about message timing and size
5. **Social Engineering**: Phishing, user mistakes, weak passwords

## Security Features

### 1. Post-Quantum Security
The Kyber-1024 key exchange ensures that even an adversary with a large-scale quantum computer cannot retroactively decrypt captured session establishment traffic.

**Security Basis**:
- Learning with Errors (LWE) problem
- NIST PQC Round 3 finalist, now standardized as ML-KEM
- No known quantum algorithm breaks LWE efficiently

### 2. Forward Secrecy
The Double Ratchet protocol ensures that compromise of current keys does not compromise past messages.

**Mechanism**:
- Each message encrypted with ephemeral key
- Keys derived from ratchet chain and immediately deleted
- 60-second automatic rotation creates fresh chain keys

### 3. Replay Protection
Messages include timestamps and sequence numbers to prevent replay attacks.

**Implementation**:
- Maximum time skew: 5 minutes
- In-memory bloom filter of seen message IDs
- Window-based sequence number validation

### 4. Authentication
All messages are authenticated using Poly1305 MAC as part of AEAD.

**Properties**:
- Forgery probability: 2^-128
- Prevents message tampering
- Cryptographic binding to nonce and associated data

### 5. Constant-Time Operations
Cryptographic comparisons use constant-time implementations.

**Purpose**:
- Prevents timing side-channel attacks
- Used for MAC verification, padding validation

### 6. Secure Random Number Generation
All nonces and keys use cryptographically secure randomness.

**Sources**:
- Operating system RNG (getrandom, /dev/urandom, BCryptGenRandom)
- Library: `rand` v0.8 with `OsRng`

## Known Limitations

### 1. Ratchet Synchronization
**Issue**: Current implementation requires message alternation between peers for proper ratchet synchronization.

**Impact**: Sending multiple consecutive messages from one peer without receiving may cause decryption failures.

**Status**: Documented limitation, tracked for future fix.

**Workaround**: Interactive chat pattern (alternating send/receive) works correctly.

### 2. Message Ordering
**Issue**: Out-of-order message delivery not currently handled.

**Impact**: Messages must arrive in order sent.

**Mitigation**: TCP provides in-order delivery.

**Future**: Implement buffering and counter-based reordering.

### 3. Denial of Service
**Issue**: No rate limiting or resource exhaustion protection.

**Impact**: Malicious peer can send large messages or flood connections.

**Status**: Not implemented in current version.

### 4. Traffic Analysis
**Issue**: Message sizes and timing metadata visible to network observers.

**Impact**: Patterns may reveal information about conversation.

**Potential Mitigation**: Padding, dummy traffic (not implemented).

### 5. Self-Signed Certificates
**Issue**: TLS mode uses self-signed certificates with disabled verification.

**Impact**: Vulnerable to MitM during TLS handshake.

**Status**: **FOR DEMONSTRATION ONLY - NOT FOR PRODUCTION**

**Production Fix**: Use proper PKI, certificate pinning, or trust-on-first-use (TOFU).

## Deployment Recommendations

### For Testing/Development
```bash
# Plain TCP (Kyber + XChaCha20 only)
aegis listen --port 9999

# With TLS 1.3 (adds transport encryption layer)
aegis listen --port 9999 --tls
```

### For Production
**DO NOT use this implementation in production without:**

1. **Proper TLS Certificate Management**
   - Replace self-signed certificates with CA-issued certificates
   - Implement certificate pinning or TOFU
   - Use proper hostname verification

2. **Rate Limiting**
   - Implement connection rate limits
   - Add message size limits
   - Protect against resource exhaustion

3. **Audit and Testing**
   - Professional security audit
   - Penetration testing
   - Formal verification of critical components

4. **Operational Security**
   - Secure key storage
   - Access controls on binaries
   - Logging and monitoring (without logging plaintext)

5. **Legal and Compliance**
   - Review export control regulations for cryptography
   - Understand jurisdictional requirements
   - Consider data retention laws

## Security Auditing

### Recommended Audit Areas

1. **Cryptographic Implementation**
   - Correct use of primitives
   - Key derivation and lifecycle
   - Nonce generation and uniqueness
   - Padding and constant-time operations

2. **Protocol Logic**
   - Handshake state machine
   - Ratchet advancement
   - Message authentication
   - Replay protection

3. **Memory Safety**
   - Proper zeroization
   - No key material leaks
   - Buffer handling
   - mlock coverage

4. **Network Layer**
   - TLS configuration
   - Connection handling
   - Error propagation
   - Timeout handling

5. **Side Channels**
   - Timing attacks
   - Error messages
   - Resource usage patterns

### Testing Recommendations

```bash
# Run all unit tests
cargo test --lib

# Run integration tests
cargo test --test integration_test

# Run benchmarks
cargo bench

# Check for common vulnerabilities
cargo audit

# Lint and format
cargo clippy -- -D warnings
cargo fmt --check
```

## Cryptographic Agility

The codebase is designed for algorithm replacement:

- `src/crypto/kyber.rs` - Post-quantum KEM (can swap for other NIST PQC algorithms)
- `src/crypto/symmetric.rs` - AEAD cipher (can swap for AES-GCM, etc.)
- `src/crypto/kdf.rs` - Key derivation (can add PBKDF2, Argon2, etc.)
- `src/crypto/ratchet.rs` - Forward secrecy (can modify parameters)

**Protocol Version Field**: All messages include version byte for future compatibility.

## Contact and Disclosure

### Responsible Disclosure
If you discover a security vulnerability:

1. **DO NOT** disclose publicly until patch is available
2. Email details to security contact (configure before production)
3. Include: version, steps to reproduce, impact assessment
4. Allow reasonable time for patch development

### Security Updates
- Monitor GitHub issues for security advisories
- Subscribe to release notifications
- Review CHANGELOG.md for security-relevant changes

## References

### Standards and Specifications
- **ML-KEM**: NIST FIPS 203 (Module-Lattice-Based Key-Encapsulation Mechanism)
- **XChaCha20-Poly1305**: [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439) + extended nonce
- **HKDF**: [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869)
- **Double Ratchet**: [Signal Protocol Specification](https://signal.org/docs/)
- **TLS 1.3**: [RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446)

### Academic Papers
- Bos et al., "CRYSTALS-Kyber: A CCA-Secure Module-Lattice-Based KEM" (2018)
- Perrin and Marlinspike, "The Double Ratchet Algorithm" (2016)
- Bernstein, "ChaCha, a variant of Salsa20" (2008)

### Security Research
- NIST Post-Quantum Cryptography Standardization Process
- Signal Protocol security analysis
- Rust memory safety guarantees

## Version History

### v0.1.0 (Current)
- Initial implementation
- Kyber-1024 key exchange
- XChaCha20-Poly1305 encryption
- Double Ratchet with 60s rotation
- Basic replay protection
- TLS 1.3 support (with self-signed certs)
- Integration test suite

### Future Roadmap
- Fix ratchet synchronization for consecutive messages
- Add proper certificate management
- Implement rate limiting
- Add out-of-order message handling
- Professional security audit
- Formal verification of protocol

---

**Last Updated**: 2025-09-30
**Version**: 0.1.0
**Status**: **DEMONSTRATION / RESEARCH USE ONLY - NOT PRODUCTION READY**
