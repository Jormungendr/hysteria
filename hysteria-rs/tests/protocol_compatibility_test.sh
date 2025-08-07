#!/bin/bash

# Hysteria 协议兼容性测试脚本
# 测试 Rust 版本和 Go 版本之间的实际网络通信兼容性

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

# 全局变量
RUST_SERVER_PID=""
GO_SERVER_PID=""
RUST_CLIENT_PID=""
GO_CLIENT_PID=""
TEST_PASSWORD="test_protocol_compat_123"
RUST_SERVER_PORT=18443
GO_SERVER_PORT=18444
SOCKS5_PORT_1=11080
SOCKS5_PORT_2=11081
HTTP_TEST_PORT=18080

# 检查依赖
check_dependencies() {
    log_info "检查依赖..."
    
    # 检查 Rust 二进制文件
    if [ ! -f "./target/release/hysteria" ]; then
        log_info "编译 Rust 版本的 hysteria..."
        cargo build --release
    fi
    
    if [ ! -f "./target/release/hysteria" ]; then
        log_error "Rust 版本的 hysteria 编译失败"
        exit 1
    fi
    
    # 检查 Go 版本
    if [ ! -f "../app/hysteria" ]; then
        log_info "编译 Go 版本的 hysteria..."
        cd ../app
        go build -o hysteria .
        cd ../hysteria-rs
    fi
    
    if [ ! -f "../app/hysteria" ]; then
        log_error "Go 版本的 hysteria 编译失败"
        exit 1
    fi
    
    # 检查 curl
    if ! command -v curl &> /dev/null; then
        log_error "curl 未安装，请先安装 curl"
        exit 1
    fi
    
    # 检查 nc (netcat)
    if ! command -v nc &> /dev/null; then
        log_warning "nc (netcat) 未安装，部分测试可能无法进行"
    fi
    
    log_success "依赖检查完成"
}

# 生成测试证书
generate_test_certificates() {
    log_info "生成测试证书..."
    
    if [ ! -f "test_cert.pem" ] || [ ! -f "test_key.pem" ]; then
        # 生成自签名证书
        openssl req -x509 -newkey rsa:2048 -keyout test_key.pem -out test_cert.pem -days 1 -nodes -subj "/CN=localhost" 2>/dev/null || {
            log_warning "无法生成证书，使用现有证书或跳过 TLS 测试"
            # 创建虚拟证书文件
            touch test_cert.pem test_key.pem
        }
    fi
    
    log_success "测试证书准备完成"
}

# 创建配置文件
create_test_configs() {
    log_info "创建测试配置文件..."
    
    # Rust 服务器配置
    cat > rust_server_test.yaml << EOF
listen: 127.0.0.1:${RUST_SERVER_PORT}
cert: test_cert.pem
key: test_key.pem
auth:
  type: password
  password: ${TEST_PASSWORD}
  userpass: null
  http: null
bandwidth:
  up: 100 Mbps
  down: 100 Mbps
masquerade:
  type: proxy
  file: null
  proxy:
    url: https://www.google.com
    rewrite_host: true
obfs: null
quic: null
EOF

    # Go 服务器配置
    cat > go_server_test.yaml << EOF
listen: 127.0.0.1:${GO_SERVER_PORT}
tls:
  cert: test_cert.pem
  key: test_key.pem
auth:
  type: password
  password: ${TEST_PASSWORD}
bandwidth:
  up: 100 mbps
  down: 100 mbps
masquerade:
  type: proxy
  proxy:
    url: https://www.google.com
    rewriteHost: true
EOF

    # Rust 客户端配置（连接到 Go 服务器）
    cat > rust_client_to_go.yaml << EOF
server:
  addr: 127.0.0.1
  port: ${GO_SERVER_PORT}
  sni: localhost
  insecure: true
auth:
  type: password
  password: ${TEST_PASSWORD}
  userpass: null
  http: null
bandwidth:
  up: 100 Mbps
  down: 100 Mbps
socks5:
  listen: 127.0.0.1:${SOCKS5_PORT_1}
  disable_udp: false
http:
  listen: 127.0.0.1:${HTTP_TEST_PORT}
tun: null
obfs: null
quic: null
EOF

    # Go 客户端配置（连接到 Rust 服务器）
    cat > go_client_to_rust.yaml << EOF
server: 127.0.0.1:${RUST_SERVER_PORT}
auth: ${TEST_PASSWORD}
tls:
  insecure: true
bandwidth:
  up: 100 mbps
  down: 100 mbps
socks5:
  listen: 127.0.0.1:${SOCKS5_PORT_2}
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
        /home/ric/dev/hysteria/app/hysteria server -c "$config_file" > "go_server_${port}.log" 2>&1 &
        GO_SERVER_PID=$!
    else
        /home/ric/dev/hysteria/hysteria-rs/target/release/hysteria server -c "$config_file" > "rust_server_${port}.log" 2>&1 &
        RUST_SERVER_PID=$!
    fi
    
    # 等待服务器启动
    sleep 3
    
    # 检查服务器是否启动成功
    if [ "$server_type" = "go" ]; then
        if ! kill -0 $GO_SERVER_PID 2>/dev/null; then
            log_error "${server_type} 服务器启动失败"
            log_error "服务器日志:"
            cat "go_server_${port}.log" 2>/dev/null || echo "无法读取日志文件"
            return 1
        fi
    else
        if ! kill -0 $RUST_SERVER_PID 2>/dev/null; then
            log_error "${server_type} 服务器启动失败"
            log_error "服务器日志:"
            cat "rust_server_${port}.log" 2>/dev/null || echo "无法读取日志文件"
            return 1
        fi
    fi
    
    # 检查服务器端口是否监听
    local max_attempts=10
    local attempt=0
    while [ $attempt -lt $max_attempts ]; do
        if netstat -ln 2>/dev/null | grep -q ":${port} " || ss -ln 2>/dev/null | grep -q ":${port} "; then
            break
        fi
        sleep 1
        ((attempt++))
    done
    
    if [ $attempt -eq $max_attempts ]; then
        log_error "${server_type} 服务器端口 ${port} 未监听"
        return 1
    fi
    
    log_success "${server_type} 服务器启动成功 (PID: $([ "$server_type" = "go" ] && echo $GO_SERVER_PID || echo $RUST_SERVER_PID))"
}

# 启动客户端
start_client() {
    local client_type=$1
    local config_file=$2
    local socks5_port=$3
    
    log_info "启动 ${client_type} 客户端 (SOCKS5 端口 ${socks5_port})..."
    
    if [ "$client_type" = "go" ]; then
        /home/ric/dev/hysteria/app/hysteria client -c "$config_file" > "go_client_${socks5_port}.log" 2>&1 &
        GO_CLIENT_PID=$!
    else
        /home/ric/dev/hysteria/hysteria-rs/target/release/hysteria client -c "$config_file" > "rust_client_${socks5_port}.log" 2>&1 &
        RUST_CLIENT_PID=$!
    fi
    
    # 等待客户端启动
    sleep 3
    
    # 检查客户端是否启动成功
    if [ "$client_type" = "go" ]; then
        if ! kill -0 $GO_CLIENT_PID 2>/dev/null; then
            log_error "${client_type} 客户端启动失败"
            log_error "客户端日志:"
            cat "go_client_${socks5_port}.log" 2>/dev/null || echo "无法读取日志文件"
            return 1
        fi
    else
        if ! kill -0 $RUST_CLIENT_PID 2>/dev/null; then
            log_error "${client_type} 客户端启动失败"
            log_error "客户端日志:"
            cat "rust_client_${socks5_port}.log" 2>/dev/null || echo "无法读取日志文件"
            return 1
        fi
    fi
    
    log_success "${client_type} 客户端启动成功 (PID: $([ "$client_type" = "go" ] && echo $GO_CLIENT_PID || echo $RUST_CLIENT_PID))"
}

# 测试连接
test_connection() {
    local test_name=$1
    local socks5_port=$2
    
    log_info "测试连接: ${test_name}"
    
    # 等待代理完全启动
    sleep 5
    
    # 检查 SOCKS5 端口是否监听
    if ! netstat -ln 2>/dev/null | grep -q ":${socks5_port} " && ! ss -ln 2>/dev/null | grep -q ":${socks5_port} "; then
        log_error "${test_name}: SOCKS5 端口 ${socks5_port} 未监听"
        return 1
    fi
    
    log_info "${test_name}: SOCKS5 端口 ${socks5_port} 正在监听"
    
    # 测试简单的 TCP 连接
    local test_url="http://httpbin.org/ip"
    local timeout=15
    
    log_info "${test_name}: 尝试通过 SOCKS5 代理访问 ${test_url}"
    
    local curl_output
    curl_output=$(curl --connect-timeout $timeout --max-time $timeout --socks5 "127.0.0.1:${socks5_port}" "$test_url" 2>&1)
    local curl_exit_code=$?
    
    if [ $curl_exit_code -eq 0 ]; then
        log_success "${test_name}: HTTP 连接测试成功"
        log_info "${test_name}: 响应内容: ${curl_output}"
        return 0
    else
        log_error "${test_name}: HTTP 连接测试失败 (退出码: ${curl_exit_code})"
        log_error "${test_name}: curl 错误信息: ${curl_output}"
        
        # 尝试更简单的连接测试
        if timeout 5 bash -c "echo 'test' | nc 127.0.0.1 ${socks5_port}" 2>/dev/null; then
            log_warning "${test_name}: SOCKS5 端口可连接，但代理功能可能有问题"
        else
            log_error "${test_name}: SOCKS5 端口连接失败"
        fi
        
        return 1
    fi
}

# 停止进程
stop_process() {
    local pid=$1
    local name=$2
    
    if [ -n "$pid" ] && kill -0 $pid 2>/dev/null; then
        log_info "停止 ${name} (PID: ${pid})..."
        kill $pid 2>/dev/null || true
        sleep 2
        if kill -0 $pid 2>/dev/null; then
            kill -9 $pid 2>/dev/null || true
        fi
    fi
}

# 清理环境
cleanup() {
    log_info "清理测试环境..."
    
    # 停止所有进程
    stop_process "$RUST_SERVER_PID" "Rust 服务器"
    stop_process "$GO_SERVER_PID" "Go 服务器"
    stop_process "$RUST_CLIENT_PID" "Rust 客户端"
    stop_process "$GO_CLIENT_PID" "Go 客户端"
    
    # 清理配置文件和日志
    rm -f *_server_test.yaml *_client_to_*.yaml
    rm -f *.log
    rm -f test_cert.pem test_key.pem
    
    log_success "清理完成"
}

# 运行协议兼容性测试
run_protocol_compatibility_tests() {
    log_info "开始协议兼容性测试"
    
    local test_results=()
    
    # 测试场景 1: Rust 客户端 -> Go 服务器
    log_info "\n=== 测试场景 1: Rust 客户端连接 Go 服务器 ==="
    
    if start_server "go" "go_server_test.yaml" "$GO_SERVER_PORT"; then
        if start_client "rust" "rust_client_to_go.yaml" "$SOCKS5_PORT_1"; then
            if test_connection "Rust客户端->Go服务器" "$SOCKS5_PORT_1"; then
                test_results+=("✓ Rust客户端->Go服务器: 成功")
            else
                test_results+=("✗ Rust客户端->Go服务器: 失败")
            fi
        else
            test_results+=("✗ Rust客户端->Go服务器: 客户端启动失败")
        fi
    else
        test_results+=("✗ Rust客户端->Go服务器: 服务器启动失败")
    fi
    
    # 停止第一组进程
    stop_process "$GO_SERVER_PID" "Go 服务器"
    stop_process "$RUST_CLIENT_PID" "Rust 客户端"
    sleep 2
    
    # 测试场景 2: Go 客户端 -> Rust 服务器
    log_info "\n=== 测试场景 2: Go 客户端连接 Rust 服务器 ==="
    
    if start_server "rust" "rust_server_test.yaml" "$RUST_SERVER_PORT"; then
        if start_client "go" "go_client_to_rust.yaml" "$SOCKS5_PORT_2"; then
            if test_connection "Go客户端->Rust服务器" "$SOCKS5_PORT_2"; then
                test_results+=("✓ Go客户端->Rust服务器: 成功")
            else
                test_results+=("✗ Go客户端->Rust服务器: 失败")
            fi
        else
            test_results+=("✗ Go客户端->Rust服务器: 客户端启动失败")
        fi
    else
        test_results+=("✗ Go客户端->Rust服务器: 服务器启动失败")
    fi
    
    # 生成测试报告
    log_info "\n=== 协议兼容性测试结果 ==="
    
    local passed=0
    local total=${#test_results[@]}
    
    for result in "${test_results[@]}"; do
        if [[ $result == ✓* ]]; then
            log_success "$result"
            ((passed++))
        else
            log_error "$result"
        fi
    done
    
    log_info "\n协议兼容性测试完成: $passed/$total 通过"
    
    if [ $passed -eq $total ]; then
        log_success "所有协议兼容性测试通过！"
        return 0
    else
        log_error "部分协议兼容性测试失败"
        return 1
    fi
}

# 信号处理
trap cleanup EXIT INT TERM

# 主程序
main() {
    cd "$(dirname "$0")/.."
    
    check_dependencies
    generate_test_certificates
    create_test_configs
    run_protocol_compatibility_tests
}

# 如果直接运行此脚本
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi