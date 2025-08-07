# Hysteria CLI

Command line interface for Hysteria 2 proxy.

## Features

- **Client Mode**: Connect to Hysteria servers with SOCKS5/HTTP proxy support
- **Server Mode**: Run Hysteria server with authentication and masquerading
- **Configuration Generation**: Generate sample configuration files
- **Multiple Authentication Methods**: Password, userpass, and HTTP authentication
- **Bandwidth Control**: Configure upload/download bandwidth limits
- **Obfuscation Support**: Salamander obfuscation for traffic hiding
- **Comprehensive Logging**: Configurable log levels and formats

## Installation

```bash
cd hysteria-rs
cargo build --release --bin hysteria
```

The binary will be available at `target/release/hysteria`.

## Usage

### Generate Configuration

```bash
# Generate client configuration
hysteria gen-config -t client -o client.yaml

# Generate server configuration
hysteria gen-config -t server -o server.yaml
```

### Run Client

```bash
hysteria client -c client.yaml
```

### Run Server

```bash
hysteria server -c server.yaml
```

### Command Line Options

```bash
# Show help
hysteria --help

# Enable verbose logging
hysteria -v client -c client.yaml

# Set log level
hysteria --log-level debug client -c client.yaml
```

## Configuration

### Client Configuration Example

```yaml
server:
  addr: "example.com"
  port: 443
  sni: "example.com"
  insecure: false

auth:
  type: "password"
  password: "your_password_here"

bandwidth:
  up: "100 Mbps"
  down: "100 Mbps"

socks5:
  listen: "127.0.0.1:1080"
  disable_udp: false

http:
  listen: "127.0.0.1:8080"
```

### Server Configuration Example

```yaml
listen: ":443"
cert: "/path/to/cert.pem"
key: "/path/to/key.pem"

auth:
  type: "password"
  password: "your_password_here"

bandwidth:
  up: "1 Gbps"
  down: "1 Gbps"

masquerade:
  type: "proxy"
  proxy:
    url: "https://example.com"
    rewrite_host: true
```

## Authentication Methods

### Password Authentication

```yaml
auth:
  type: "password"
  password: "your_secret_password"
```

### User/Password Authentication

```yaml
auth:
  type: "userpass"
  userpass:
    - username: "user1"
      password: "pass1"
    - username: "user2"
      password: "pass2"
```

### HTTP Authentication

```yaml
auth:
  type: "http"
  http:
    url: "https://auth.example.com/validate"
    insecure: false
```

## Bandwidth Configuration

Supported units:
- `bps`, `b` - bits per second
- `kbps`, `k`, `kb` - kilobits per second
- `mbps`, `m`, `mb` - megabits per second
- `gbps`, `g`, `gb` - gigabits per second

Examples:
- `"100 Mbps"`
- `"1 Gbps"`
- `"500kbps"`

## Obfuscation

```yaml
obfs:
  type: "salamander"
  salamander:
    password: "obfs_password"
```

## Masquerading (Server Only)

### HTTP Proxy Masquerading

```yaml
masquerade:
  type: "proxy"
  proxy:
    url: "https://example.com"
    rewrite_host: true
```

### File Server Masquerading

```yaml
masquerade:
  type: "file"
  file:
    dir: "/var/www/html"
```

## Logging

```bash
# Set log level
hysteria --log-level debug client -c config.yaml

# Enable verbose mode
hysteria -v client -c config.yaml
```

Available log levels: `trace`, `debug`, `info`, `warn`, `error`

## Testing

```bash
# Run unit tests
cargo test

# Run integration tests
cargo test --test integration_tests
```

## Development

The CLI is built on top of the `hysteria_core` library and uses:

- `clap` for command line parsing
- `tokio` for async runtime
- `tracing` for logging
- `serde` for configuration serialization
- `anyhow` for error handling

## License

MIT License - see the LICENSE file for details.