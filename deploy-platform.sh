#!/bin/bash

# OSINT Platform Build and Deployment Script
# Builds and deploys the complete multi-language OSINT platform

set -e

# Configuration
REGISTRY=${REGISTRY:-"osint-platform"}
VERSION=${VERSION:-"latest"}
ENVIRONMENT=${ENVIRONMENT:-"development"}
NAMESPACE=${NAMESPACE:-"osint-platform"}

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
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

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed or not in PATH"
        exit 1
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        log_error "Docker Compose is not installed or not in PATH"
        exit 1
    fi
    
    # Check kubectl for Kubernetes deployment
    if [[ "$ENVIRONMENT" == "production" ]] && ! command -v kubectl &> /dev/null; then
        log_error "kubectl is not installed but required for production deployment"
        exit 1
    fi
    
    # Check Go
    if ! command -v go &> /dev/null; then
        log_error "Go is not installed or not in PATH"
        exit 1
    fi
    
    # Check Rust
    if ! command -v cargo &> /dev/null; then
        log_error "Rust/Cargo is not installed or not in PATH"
        exit 1
    fi
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 is not installed or not in PATH"
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

# Build Go engine
build_go_engine() {
    log_info "Building Go scraping engine..."
    
    cd go-engine
    
    # Build the Go application
    CGO_ENABLED=0 GOOS=linux go build -a 
