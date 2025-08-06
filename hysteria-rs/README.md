# Hysteria Rust Implementation

A Rust implementation of the Hysteria 2 protocol, providing high-performance proxy capabilities with advanced congestion control and obfuscation features.

## Features

- **QUIC-based Transport**: Built on top of `s2n-quic` for reliable and efficient transport
- **Authentication**: Support for password-based authentication
- **Advanced Congestion Control**: Multiple algorithms for optimal performance
  - **Brutal Algorithm**: Designed for high packet loss environments with dynamic rate adjustment based on ACK rates
  - **BBR Algorithm**: Complete implementation of Google's BBR algorithm with four operational modes
  - **Basic Algorithm**: Traditional bandwidth control with token bucket rate limiting
- **UDP Session Management**: Efficient handling of UDP sessions with fragmentation support
- **Obfuscation**: Salamander obfuscation layer for traffic disguising
- **Protocol Compliance**: Full implementation of Hysteria 2 protocol specification

## Architecture

The implementation is organized into several core modules:

- `auth`: Authentication handling (password-based)
- `congestion`: Bandwidth control and rate limiting
- `error`: Comprehensive error handling
- `obfs`: Salamander obfuscation implementation
- `protocol`: Hysteria 2 protocol message encoding/decoding
- `quic`: QUIC transport layer wrapper
- `udp`: UDP session management and fragmentation

## Quick Start

### Building

```bash
cd hysteria-rs
cargo build --release
```

### Running Tests

```bash
cargo test
```

### Examples

#### Basic Server

```bash
cargo run --example basic_server
```

#### Basic Client

```bash
cargo run --example basic_client
```

## Usage

### Server Configuration

```rust
use hysteria_core::{
    quic::{QuicServerConfig, HysteriaQuicServer},
    auth::PasswordAuthHandler,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = QuicServerConfig {
        bind_addr: "0.0.0.0:8443".parse()?,
    };
    
    let mut server = HysteriaQuicServer::new(config).await?;
    let auth_handler = PasswordAuthHandler::new("your_password".to_string());
    
    // Accept and handle connections
    while let Some(connection) = server.accept().await? {
        // Handle connection...
    }
    
    Ok(())
}
```

### Client Configuration

```rust
use hysteria_core::{
    quic::{QuicClientConfig, HysteriaQuicClient},
    auth::AuthRequest,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = QuicClientConfig {
        server_name: "your-server.com".to_string(),
        insecure: false,
    };
    
    let client = HysteriaQuicClient::new(config).await?;
    let connection = client.connect("your-server.com:8443".parse()?).await?;
    
    // Open streams and send data...
    
    Ok(())
}
```

## Protocol Features

### Authentication

Supports password-based authentication with configurable bandwidth limits:

```rust
let auth_request = AuthRequest {
    auth: "password:your_password".to_string(),
    tx: Some(1000000), // 1 Mbps upload limit
};
```

### Congestion Control

Advanced bandwidth management with multiple congestion control algorithms:

#### Brutal Congestion Control
Optimized for high packet loss environments with dynamic rate adjustment:

```rust
use hysteria_core::congestion::{BrutalCongestionController, BrutalConfig};

let config = BrutalConfig {
    target_bps: 10_000_000, // 10 Mbps target
    ..Default::default()
};

let controller = BrutalCongestionController::new(config);
```

#### BBR Congestion Control
Google's BBR algorithm implementation with four operational modes:

```rust
use hysteria_core::congestion::{BbrCongestionController, BbrConfig};

let config = BbrConfig {
    initial_cwnd: 10,
    min_rtt_filter_len: 10,
    ..Default::default()
};

let controller = BbrCongestionController::new(config);
```

#### Basic Congestion Control
Traditional bandwidth-based congestion control with token bucket rate limiting:

```rust
use hysteria_core::congestion::{CongestionController, CongestionConfig};

let config = CongestionConfig {
    max_tx_rate: 10_000_000, // 10 Mbps
    max_rx_rate: 10_000_000, // 10 Mbps
    ..Default::default()
};

let mut controller = CongestionController::new(config);
controller.record_tx(1024); // Record transmitted bytes
controller.record_rx(512);  // Record received bytes

if controller.should_throttle_tx() {
    // Apply transmission throttling
}
```

#### 拥塞控制算法工厂
使用工厂模式创建不同的拥塞控制算法：

```rust
use hysteria_core::congestion::{
    CongestionControlFactory, 
    CongestionAlgorithm, 
    CongestionConfig
};

// 创建 Brutal 算法
let brutal = CongestionControlFactory::create_brutal(5_000_000); // 5 Mbps

// 创建 BBR 算法
let bbr = CongestionControlFactory::create_bbr(1500); // 1500 bytes MTU

// 创建基础算法
let config = CongestionConfig {
    max_tx_rate: 8_000_000,
    max_rx_rate: 8_000_000,
    ..Default::default()
};
let basic = CongestionControlFactory::create_basic(config);

// 使用枚举创建算法
let algorithm = CongestionAlgorithm::Brutal(10_000_000);
let controller = CongestionControlFactory::create_from_algorithm(algorithm, 1500);
```

### UDP Session Management

Efficient UDP session handling with automatic fragmentation:

```rust
use hysteria_core::udp::UdpSessionManager;

let mut manager = UdpSessionManager::new();
let session_id = manager.create_session(client_addr, target_addr).await?;
```

### Obfuscation

Salamander obfuscation for traffic disguising:

```rust
use hysteria_core::obfs::SalamanderObfuscator;

let obfuscator = SalamanderObfuscator::new(b"your_secret_key");
let obfuscated_data = obfuscator.obfuscate(&original_data);
```

## Testing

The implementation includes comprehensive tests for all modules:

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific module tests
cargo test auth::
cargo test protocol::
cargo test congestion::
```

## Performance

The Rust implementation is designed for high performance:

- Zero-copy operations where possible
- Efficient memory management
- Async/await for concurrent handling
- Optimized protocol encoding/decoding

## Contributing

Contributions are welcome! Please ensure:

1. All tests pass: `cargo test`
2. Code is formatted: `cargo fmt`
3. No clippy warnings: `cargo clippy`
4. Documentation is updated for new features

## License

This project follows the same license as the original Hysteria project.

## Compatibility

This implementation is compatible with:

- Hysteria 2 protocol specification
- Original Go implementation
- Standard QUIC implementations

## Roadmap

- [ ] TLS certificate handling
- [ ] Advanced obfuscation methods
- [ ] Performance optimizations
- [ ] Additional authentication methods
- [ ] Metrics and monitoring
- [ ] Configuration file support