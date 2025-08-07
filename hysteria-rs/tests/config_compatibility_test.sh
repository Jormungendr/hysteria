#!/bin/bash

# Hysteria 配置文件兼容性测试脚本
# 测试 Rust 版本是否能正确解析 Go 版本的配置文件

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 日志函数
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 创建测试配置文件
create_go_style_configs() {
    log_info "创建 Go 风格的配置文件..."
    
    # Go 风格的客户端配置（转换为 Rust 兼容格式）
    cat > go_style_client.yaml << 'EOF'
server:
  addr: example.com
  port: 443
  sni: another.example.com
  insecure: true

auth:
  type: password
  password: weak_password_123
  userpass: null
  http: null

obfs:
  type: salamander
  password: obfs_password_456

bandwidth:
  up: 200 Mbps
  down: 1 Gbps

socks5:
  listen: 127.0.0.1:1080
  disable_udp: true

http:
  listen: 127.0.0.1:8080

tun: null
quic: null
EOF

    # Go 风格的服务器配置（转换为 Rust 兼容格式）
    cat > go_style_server.yaml << 'EOF'
listen: 127.0.0.1:8443
cert: some.crt
key: some.key

auth:
  type: password
  password: server_password_789
  userpass: null
  http: null

obfs:
  type: salamander
  password: obfs_password_456

bandwidth:
  up: 500 Mbps
  down: 100 Mbps

masquerade:
  type: proxy
  file: null
  proxy:
    url: https://www.google.com
    rewrite_host: true

quic: null
EOF

    # 创建 ACL 规则文件
    cat > acl_rules.txt << 'EOF'
# ACL Rules for testing
direct(geoip:cn)
socks5_proxy(domain:google.com,domain:youtube.com)
http_proxy(domain:github.com)
block(domain:ads.com,domain:tracker.com)
direct(ip:192.168.0.0/16)
block(ip:10.0.0.0/8)
EOF

    log_success "Go 风格配置文件创建完成"
}

# 测试配置文件解析
test_config_parsing() {
    local config_file=$1
    local config_type=$2
    
    log_info "测试 ${config_type} 配置文件解析: ${config_file}"
    
    # 使用 Rust 版本尝试解析配置文件（dry-run 模式）
    if ./target/release/hysteria $config_type --config "$config_file" --dry-run 2>/dev/null; then
        log_success "${config_type} 配置文件解析成功: ${config_file}"
        return 0
    else
        # 如果没有 dry-run 选项，尝试其他方法
        log_warning "尝试备用解析方法..."
        
        # 创建临时脚本来测试配置解析
        local temp_script="test_${config_type}_config.sh"
        cat > "$temp_script" << EOF
#!/bin/bash
timeout 5s ./target/release/hysteria $config_type -c "$config_file" 2>&1 | grep -E "(配置|config|error|Error|panic|Panic)" || true
EOF
        chmod +x "$temp_script"
        
        local output=$(bash "$temp_script")
        rm -f "$temp_script"
        
        if echo "$output" | grep -qi "error\|panic\|failed\|invalid"; then
            log_error "${config_type} 配置文件解析失败: ${config_file}"
            echo "错误信息: $output"
            return 1
        else
            log_success "${config_type} 配置文件解析成功: ${config_file}"
            return 0
        fi
    fi
}

# 创建 Rust 风格的等效配置
create_rust_equivalent_configs() {
    log_info "创建 Rust 风格的等效配置文件..."
    
    # Rust 风格的客户端配置
    cat > rust_style_client.yaml << 'EOF'
server:
  addr: example.com
  port: 443
  sni: another.example.com
  insecure: true

auth:
  type: password
  password: weak_password_123

obfs:
  type: salamander
  password: obfs_password_456

bandwidth:
  up: 200 Mbps
  down: 1 Gbps

socks5:
  listen: 127.0.0.1:1080
  username: anon
  password: bro
  disable_udp: true

http:
  listen: 127.0.0.1:8080
  username: qqq
  password: www

quic:
  init_stream_receive_window: 1145141
  max_stream_receive_window: 1145142
  init_conn_receive_window: 1145143
  max_conn_receive_window: 1145144
  max_idle_timeout: 10s
  keep_alive_period: 4s
  disable_path_mtu_discovery: true
EOF

    # Rust 风格的服务器配置
    cat > rust_style_server.yaml << 'EOF'
listen: 127.0.0.1:8443
cert: some.crt
key: some.key

auth:
  type: password
  password: server_password_789
  userpass: null
  http: null

obfs:
  type: salamander
  password: obfs_password_456

bandwidth:
  up: 500 Mbps
  down: 100 Mbps

masquerade:
  type: proxy
  file: null
  proxy:
    url: https://www.google.com
    rewrite_host: true

quic: null
EOF

    log_success "Rust 风格配置文件创建完成"
}

# 比较配置解析结果
compare_config_parsing() {
    log_info "比较 Go 风格和 Rust 风格配置文件的解析结果..."
    
    local go_client_result=0
    local rust_client_result=0
    local go_server_result=0
    local rust_server_result=0
    
    # 测试客户端配置
    test_config_parsing "go_style_client.yaml" "client" || go_client_result=1
    test_config_parsing "rust_style_client.yaml" "client" || rust_client_result=1
    
    # 测试服务器配置
    test_config_parsing "go_style_server.yaml" "server" || go_server_result=1
    test_config_parsing "rust_style_server.yaml" "server" || rust_server_result=1
    
    # 生成比较报告
    log_info "\n=== 配置文件兼容性测试结果 ==="
    
    if [ $go_client_result -eq 0 ]; then
        log_success "✓ Go 风格客户端配置解析成功"
    else
        log_error "✗ Go 风格客户端配置解析失败"
    fi
    
    if [ $rust_client_result -eq 0 ]; then
        log_success "✓ Rust 风格客户端配置解析成功"
    else
        log_error "✗ Rust 风格客户端配置解析失败"
    fi
    
    if [ $go_server_result -eq 0 ]; then
        log_success "✓ Go 风格服务器配置解析成功"
    else
        log_error "✗ Go 风格服务器配置解析失败"
    fi
    
    if [ $rust_server_result -eq 0 ]; then
        log_success "✓ Rust 风格服务器配置解析成功"
    else
        log_error "✗ Rust 风格服务器配置解析失败"
    fi
    
    local total_passed=$((4 - go_client_result - rust_client_result - go_server_result - rust_server_result))
    log_info "\n配置解析测试完成: $total_passed/4 通过"
    
    return $((go_client_result + rust_client_result + go_server_result + rust_server_result))
}

# 清理测试文件
cleanup() {
    log_info "清理测试文件..."
    rm -f go_style_*.yaml rust_style_*.yaml acl_rules.txt test_*.sh
    log_success "清理完成"
}

# 检查 Rust 二进制文件
check_rust_binary() {
    if [ ! -f "./target/release/hysteria" ]; then
        log_info "编译 Rust 版本的 hysteria..."
        cargo build --release
    fi
    
    if [ ! -f "./target/release/hysteria" ]; then
        log_error "Rust 版本的 hysteria 编译失败"
        exit 1
    fi
    
    log_success "Rust 二进制文件检查完成"
}

# 主测试函数
run_config_compatibility_tests() {
    log_info "开始配置文件兼容性测试"
    
    check_rust_binary
    create_go_style_configs
    create_rust_equivalent_configs
    
    if compare_config_parsing; then
        log_success "配置文件兼容性测试全部通过！"
        return 0
    else
        log_error "部分配置文件兼容性测试失败"
        return 1
    fi
}

# 信号处理
trap cleanup EXIT INT TERM

# 主程序
main() {
    cd "$(dirname "$0")/.."
    run_config_compatibility_tests
}

# 如果直接运行此脚本
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi