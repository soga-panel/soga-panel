#!/bin/bash

# Soga Panel 一键部署脚本
# 用于同时构建和部署前端和后端

set -e  # 遇到错误时退出

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 输出函数
print_info() {
    echo -e "${BLUE}[信息]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[成功]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[警告]${NC} $1"
}

print_error() {
    echo -e "${RED}[错误]${NC} $1"
}

# 检查命令是否存在
check_command() {
    if ! command -v "$1" &> /dev/null; then
        print_error "$1 命令不存在，请先安装"
        exit 1
    fi
}

# 检查必要的命令
print_info "检查必要的命令..."
check_command "pnpm"
check_command "wrangler"

# 获取当前时间戳
TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
print_info "部署开始时间: $TIMESTAMP"

# 构建并部署前端
print_info "开始构建前端..."
cd frontend

# 安装依赖
print_info "安装前端依赖..."
pnpm install

# 部署前端到 Cloudflare Pages
print_info "部署前端到 Cloudflare Pages..."
pnpm run deploy

print_success "前端部署完成"

# 返回根目录
cd ..

# 部署后端
print_info "开始部署后端..."
cd worker

# 部署后端到 Cloudflare Workers
print_info "部署后端到 Cloudflare Workers..."
pnpm run deploy

print_success "后端部署完成"

# 返回根目录
cd ..

# 完成
FINISH_TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
print_success "✨ 所有部署完成！"
print_info "开始时间: $TIMESTAMP"
print_info "结束时间: $FINISH_TIMESTAMP"
print_info "前端地址请查看 Cloudflare Pages 控制台"
print_info "后端地址请查看 Cloudflare Workers 控制台"