#!/bin/bash

# Hysteria Rust-Go 兼容性测试脚本
# 测试 Rust 版本与 Go 版本之间的协议兼容性

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

# 检查依赖
check_dependencies() {
    log_info "检查依赖项..."
    
    # 检查 Go 版本的 hysteria
    if ! command -v ../app/hysteria &> /dev/null; then
        log_error "Go 版本的 hysteria 未找到，请先编译 Go 版本"
        exit 1
    fi
    
    # 检查 Rust 版本的 hysteria
    if [ ! -f "./target/release/hysteria" ]; then
        log_info "编译 Rust 版本的 hysteria..."
        cargo build --release
    fi
    
    # 检查测试证书
    if [ ! -f "test_cert.pem" ] || [ ! -f "test_key.pem" ]; then
        log_info "生成测试证书..."
        generate_test_cert
    fi
    
    log_success "依赖检查完成"
}

# 生成测试证书
generate_test_cert() {
    openssl req -x509 -newkey rsa:2048 -keyout test_key.pem -out test_cert.pem -days 365 -nodes \
        -subj "/C=US/ST=Test/L=Test/O=Test/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
}

# 创建测试配置文件
create_test_configs() {
    log_info "创建测试配置文件..."
    
    # Go 服务器配置
    cat > go_server_test.yaml << EOF
listen: :18443

tls:
  cert: test_cert.pem
  key: test_key.pem

auth: test_password_123

bandwidth:
  up: 100 mbps
  down: 100 mbps

masquerade:
  type: proxy
  proxy:
    url: https://www.google.com
    rewriteHost: true
EOF

    # Rust 服务器配置
    cat > rust_server_test.yaml << EOF
listen: :18444
cert: test_cert.pem
key: test_key.pem
auth:
  type: password
  password: test_password_123
bandwidth:
  up: 100 Mbps
  down: 100 Mbps
masquerade:
  type: proxy
  proxy:
    url: https://www.google.com
    rewrite_host: true
EOF

    # Go 客户端配置（连接到 Rust 服务器）
    cat > go_client_to_rust.yaml << EOF
server: 127.0.0.1:18444

auth: test_password_123

tls:
  insecure: true

bandwidth:
  up: 100 mbps
  down: 100 mbps

socks5:
  listen: 127.0.0.1:11080
EOF

    # Rust 客户端配置（连接到 Go 服务器）
    cat > rust_client_to_go.yaml << EOF
server:
  addr: 127.0.0.1
  port: 18443
  insecure: true
auth:
  type: password
  password: test_password_123
bandwidth:
  up: 100 Mbps
  down: 100 Mbps
socks5:
  listen: 127.0.0.1:11081
EOF

    log_success "测试配置文件创建完成"
}

# 启动服务器
start_server() {
    local server_type=$1
    local config_file=$2
    local port=$3
    
    log_info "启动 ${server_type} 服务器 (端口 ${port})..."
    
    if [ "$server_type" = "go" ]; then
        ../app/hysteria server -c "$config_file" &
    else
        ./target/release/hysteria server -c "$config_file" &
    fi
    
    local server_pid=$!
    echo $server_pid > "${server_type}_server.pid"
    
    # 等待服务器启动
    sleep 3
    
    # 检查服务器是否正在运行
    if ! kill -0 $server_pid 2>/dev/null; then
        log_error "${server_type} 服务器启动失败"
        return 1
    fi
    
    log_success "${server_type} 服务器启动成功 (PID: $server_pid)"
    return 0
}

# 启动客户端
start_client() {
    local client_type=$1
    local config_file=$2
    local socks_port=$3
    
    log_info "启动 ${client_type} 客户端 (SOCKS5 端口 ${socks_port})..."
    
    if [ "$client_type" = "go" ]; then
        ../app/hysteria client -c "$config_file" &
    else
        ./target/release/hysteria client -c "$config_file" &
    fi
    
    local client_pid=$!
    echo $client_pid > "${client_type}_client.pid"
    
    # 等待客户端启动
    sleep 3
    
    # 检查客户端是否正在运行
    if ! kill -0 $client_pid 2>/dev/null; then
        log_error "${client_type} 客户端启动失败"
        return 1
    fi
    
    log_success "${client_type} 客户端启动成功 (PID: $client_pid)"
    return 0
}

# 测试连接
test_connection() {
    local socks_port=$1
    local test_name="$2"
    
    log_info "测试连接: ${test_name}"
    
    # 测试 HTTP 请求
    if curl -s --socks5 "127.0.0.1:${socks_port}" --connect-timeout 10 --max-time 30 \
           "http://httpbin.org/ip" > /dev/null; then
        log_success "${test_name} - HTTP 连接测试通过"
        return 0
    else
        log_error "${test_name} - HTTP 连接测试失败"
        return 1
    fi
}

# 清理进程
cleanup() {
    log_info "清理测试环境..."
    
    # 停止所有测试进程
    for pid_file in *.pid; do
        if [ -f "$pid_file" ]; then
            local pid=$(cat "$pid_file")
            if kill -0 $pid 2>/dev/null; then
                kill $pid
                log_info "停止进程 $pid"
            fi
            rm -f "$pid_file"
        fi
    done
    
    # 清理测试文件
    rm -f *_test.yaml test_cert.pem test_key.pem
    
    log_success "清理完成"
}

# 主测试函数
run_compatibility_tests() {
    log_info "开始 Hysteria Rust-Go 兼容性测试"
    
    local test_results=()
    
    # 测试 1: Rust 客户端 -> Go 服务器
    log_info "\n=== 测试 1: Rust 客户端连接 Go 服务器 ==="
    
    if start_server "go" "go_server_test.yaml" "18443"; then
        if start_client "rust" "rust_client_to_go.yaml" "11081"; then
            if test_connection "11081" "Rust客户端->Go服务器"; then
                test_results+=("✓ Rust客户端->Go服务器")
            else
                test_results+=("✗ Rust客户端->Go服务器")
            fi
        else
            test_results+=("✗ Rust客户端->Go服务器 (客户端启动失败)")
        fi
    else
        test_results+=("✗ Rust客户端->Go服务器 (服务器启动失败)")
    fi
    
    # 停止当前测试的进程
    cleanup
    sleep 2
    
    # 测试 2: Go 客户端 -> Rust 服务器
    log_info "\n=== 测试 2: Go 客户端连接 Rust 服务器 ==="
    
    if start_server "rust" "rust_server_test.yaml" "18444"; then
        if start_client "go" "go_client_to_rust.yaml" "11080"; then
            if test_connection "11080" "Go客户端->Rust服务器"; then
                test_results+=("✓ Go客户端->Rust服务器")
            else
                test_results+=("✗ Go客户端->Rust服务器")
            fi
        else
            test_results+=("✗ Go客户端->Rust服务器 (客户端启动失败)")
        fi
    else
        test_results+=("✗ Go客户端->Rust服务器 (服务器启动失败)")
    fi
    
    # 显示测试结果
    log_info "\n=== 兼容性测试结果 ==="
    for result in "${test_results[@]}"; do
        if [[ $result == ✓* ]]; then
            log_success "$result"
        else
            log_error "$result"
        fi
    done
    
    # 统计成功率
    local total_tests=${#test_results[@]}
    local passed_tests=$(printf '%s\n' "${test_results[@]}" | grep -c '^✓' || true)
    
    log_info "\n测试完成: $passed_tests/$total_tests 通过"
    
    if [ $passed_tests -eq $total_tests ]; then
        log_success "所有兼容性测试通过！"
        return 0
    else
        log_error "部分兼容性测试失败"
        return 1
    fi
}

# 信号处理
trap cleanup EXIT INT TERM

# 主程序
main() {
    cd "$(dirname "$0")/.."
    
    check_dependencies
    create_test_configs
    run_compatibility_tests
}

# 如果直接运行此脚本
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi