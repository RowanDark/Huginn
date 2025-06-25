#!/bin/bash
set -e

echo "🚀 Huginn Repository Reorganization Script"
echo "=========================================="

Check if we're in the right directory
if [ ! -f "go.mod" ]; then
echo "❌ Error: Please run this script from the huginn repository root directory"
echo " Expected to find go.mod in current directory"
exit 1
fi

echo "📁 Creating new directory structure..."

Create the main directory structure
mkdir -p services/go-engine
mkdir -p services/rust-security
mkdir -p services/python-ai
mkdir -p docker
mkdir -p scripts
mkdir -p k8s
mkdir -p docs
mkdir -p config
mkdir -p monitoring/{prometheus,grafana/{dashboards,datasources}}
mkdir -p models
mkdir -p .github/workflows

echo "✅ Directory structure created"

echo "📦 Moving existing files to new locations..."

Move source code files
if [ -f "go-main-enginge.go" ]; then
echo " Moving go-main-enginge.go -> services/go-engine/main.go (fixing typo)"
mv go-main-enginge.go services/go-engine/main.go
fi

if [ -f "rust-security-main.rs" ]; then
echo " Moving rust-security-main.rs -> services/rust-security/main.rs"
mv rust-security-main.rs services/rust-security/main.rs
fi

if [ -f "python-ai-main.py" ]; then
echo " Moving python-ai-main.py -> services/python-ai/main.py"
mv python-ai-main.py services/python-ai/main.py
fi

Move Docker files
if [ -f "Dockerfile.worker" ]; then
echo " Moving Dockerfile.worker -> services/go-engine/Dockerfile"
mv Dockerfile.worker services/go-engine/Dockerfile
fi

if [ -f "Dockerfile.base" ]; then
echo " Moving Dockerfile.base -> docker/"
mv Dockerfile.base docker/
fi

Move scripts
if [ -f "build.sh" ]; then
echo " Moving build.sh -> scripts/"
mv build.sh scripts/
chmod +x scripts/build.sh
fi

if [ -f "docker-build.sh" ]; then
echo " Moving docker-build.sh -> scripts/"
mv docker-build.sh scripts/
chmod +x scripts/docker-build.sh
fi

if [ -f "deploy-platform.sh" ]; then
echo " Moving deploy-platform.sh -> scripts/"
mv deploy-platform.sh scripts/
chmod +x scripts/deploy-platform.sh
fi

Move Kubernetes files
if [ -f "k8s-go-engine-deploy.yml" ]; then
echo " Moving k8s-go-engine-deploy.yml -> k8s/go-engine-deploy.yml"
mv k8s-go-engine-deploy.yml k8s/go-engine-deploy.yml
fi

if [ -f "k8s-rust-python-deploy.yml" ]; then
echo " Moving k8s-rust-python-deploy.yml -> k8s/rust-python-deploy.yml"
mv k8s-rust-python-deploy.yml k8s/rust-python-deploy.yml
fi

if [ -f "deployment.yaml" ]; then
echo " Moving deployment.yaml -> k8s/"
mv deployment.yaml k8s/
fi

Move documentation
if [ -f "architecture.md" ]; then
echo " Moving architecture.md -> docs/"
mv architecture.md docs/
fi

if [ -f "readme.md" ]; then
echo " Moving readme.md -> README.md (proper capitalization)"
mv readme.md README.md
fi

echo "✅ File moves completed"

echo "📝 Creating service-specific configuration files..."

Create Go service go.mod
echo " Creating services/go-engine/go.mod"
cat > services/go-engine/go.mod << 'EOF'
module huginn-engine

go 1.21

require (
github.com/gin-gonic/gin v1.9.1
github.com/go-redis/redis/v8 v8.11.5
github.com/gocolly/colly/v2 v2.1.0
github.com/chromedp/chromedp v0.9.2
github.com/PuerkitoBio/goquery v1.8.1
github.com/gorilla/websocket v1.5.0
github.com/spf13/viper v1.17.0
github.com/spf13/cobra v1.7.0
github.com/sirupsen/logrus v1.9.3
github.com/google/uuid v1.4.0
github.com/prometheus/client_golang v1.17.0
golang.org/x/net v0.17.0
golang.org/x/time v0.4.0
gopkg.in/yaml.v3 v3.0.1
)
EOF

Create Rust service Cargo.toml
echo " Creating services/rust-security/Cargo.toml"
cat > services/rust-security/Cargo.toml << 'EOF'
[package]
name = "huginn-security"
version = "0.1.0"
edition = "2021"
description = "Advanced security and anti-detection module for Huginn OSINT platform"
license = "MIT"

[dependencies]
tokio = { version = "1.0", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
reqwest = { version = "0.11", features = ["json", "cookies", "rustls-tls"] }
redis = { version = "0.23", features = ["tokio-comp"] }
tracing = "0.1"
tracing-subscriber = "0.3"
uuid = { version = "1.0", features = ["v4"] }
rand = "0.8"
base64 = "0.21"
rustls = "0.21"
tokio-rustls = "0.24"
hyper = { version = "0.14", features = ["full"] }
hyper-rustls = "0.24"
warp = "0.3"
clap = { version = "4.0", features = ["derive"] }
config = "0.13"
anyhow = "1.0"
thiserror = "1.0"
chrono = { version = "0.4", features = ["serde"] }
EOF

Create Python service requirements.txt
echo " Creating services/python-ai/requirements.txt"
cat > services/python-ai/requirements.txt << 'EOF'
fastapi>=0.104.0
uvicorn[standard]>=0.24.0
redis>=5.0.0
transformers>=4.35.0
torch>=2.1.0,<2.2.0
numpy>=1.24.0
pandas>=2.1.0
scikit-learn>=1.3.0
spacy>=3.7.0
nltk>=3.8.0
stix2>=3.0.0
requests>=2.31.0
pydantic>=2.5.0
python-multipart>=0.0.6
aioredis>=2.0.0
httpx>=0.25.0
loguru>=0.7.0
python-dotenv>=1.0.0
sentence-transformers>=2.2.0
textblob>=0.17.0
yara-python>=4.3.0
python-magic>=0.4.0
pytz>=2023.3
EOF

Create Python service pyproject.toml
echo " Creating services/python-ai/pyproject.toml"
cat > services/python-ai/pyproject.toml << 'EOF'
[build-system]
requires = ["setuptools>=61.0", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "huginn-ai"
version = "0.1.0"
description = "AI and ML analysis module for Huginn OSINT platform"
license = {text = "MIT"}
readme = "README.md"
requires-python = ">=3.11"
dependencies = [
"fastapi>=0.104.0",
"uvicorn[standard]>=0.24.0",
"redis>=5.0.0",
"transformers>=4.35.0",
"torch>=2.1.0,<2.2.0",
"numpy>=1.24.0",
"pandas>=2.1.0",
"scikit-learn>=1.3.0",
"spacy>=3.7.0",
"nltk>=3.8.0",
"stix2>=3.0.0",
"requests>=2.31.0",
"pydantic>=2.5.0",
"python-multipart>=0.0.6",
"aioredis>=2.0.0",
"httpx>=0.25.0",
"loguru>=0.7.0",
"python-dotenv>=1.0.0",
"sentence-transformers>=2.2.0",
"textblob>=0.17.0",
"yara-python>=4.3.0",
"python-magic>=0.4.0",
"pytz>=2023.3",
]

[project.optional-dependencies]
dev = [
"pytest>=7.4.0",
"pytest-asyncio>=0.21.0",
"black>=23.0.0",
"isort>=5.12.0",
"flake8>=6.0.0",
"mypy>=1.6.0",
"pre-commit>=3.5.0",
]
EOF

Create service README files
echo " Creating service README files"
cat > services/go-engine/README.md << 'EOF'

Huginn Go Engine
High-performance core scraping engine with distributed worker pools.

Development
bash
cd services/go-engine
go mod tidy
go run main.go
Building
bash
go build -o huginn-engine main.go
EOF

cat > services/rust-security/README.md << 'EOF'

Huginn Rust Security Module
Advanced anti-detection, browser fingerprinting, and TLS management.

Development
bash
cd services/rust-security
cargo run
Building
bash
cargo build --release
EOF

cat > services/python-ai/README.md << 'EOF'

Huginn Python AI Module
Natural language processing, threat intelligence, and machine learning analysis.

Development
bash
cd services/python-ai
pip install -r requirements.txt
python main.py
Building
bash
pip install -e .
EOF

echo "✅ Service configuration files created"

echo "🔧 Updating file references..."

Update docker-compose.yml to use new paths
if [ -f "docker-compose.yml" ]; then
echo " Updating docker-compose.yml paths"
sed -i.bak 's|dockerfile: Dockerfile.worker|dockerfile: services/go-engine/Dockerfile|g' docker-compose.yml
sed -i.bak 's|dockerfile: Dockerfile.base|dockerfile: docker/Dockerfile.base|g' docker-compose.yml
rm -f docker-compose.yml.bak
fi

Update docker-compose-prod.yml to use new paths
if [ -f "docker-compose-prod.yml" ]; then
echo " Updating docker-compose-prod.yml paths"
sed -i.bak 's|dockerfile: Dockerfile.worker|dockerfile: services/go-engine/Dockerfile|g' docker-compose-prod.yml
sed -i.bak 's|dockerfile: Dockerfile.base|dockerfile: docker/Dockerfile.base|g' docker-compose-prod.yml
rm -f docker-compose-prod.yml.bak
fi

echo "✅ File references updated"

echo "📊 Creating final repository structure visualization..."

echo "
📁 Final Huginn Repository Structure:
huginn/
├── README.md ✅ (from readme.md)
├── docker-compose.yml ✅ (paths updated)
├── docker-compose-prod.yml ✅ (paths updated)
├── go.mod ✅ (existing)
├── services/ 🆕
│ ├── go-engine/ 🆕
│ │ ├── main.go ✅ (from go-main-enginge.go)
│ │ ├── go.mod 🆕
│ │ ├── Dockerfile ✅ (from Dockerfile.worker)
│ │ └── README.md 🆕
│ ├── rust-security/ 🆕
│ │ ├── main.rs ✅ (from rust-security-main.rs)
│ │ ├── Cargo.toml 🆕
│ │ └── README.md 🆕
│ └── python-ai/ 🆕
│ ├── main.py ✅ (from python-ai-main.py)
│ ├── requirements.txt 🆕
│ ├── pyproject.toml 🆕
│ └── README.md 🆕
├── docker/ 🆕
│ └── Dockerfile.base ✅ (from root)
├── scripts/ 🆕
│ ├── build.sh ✅ (from root)
│ ├── docker-build.sh ✅ (from root)
│ └── deploy-platform.sh ✅ (from root)
├── k8s/ 🆕
│ ├── go-engine-deploy.yml ✅ (from k8s-go-engine-deploy.yml)
│ ├── rust-python-deploy.yml ✅ (from k8s-rust-python-deploy.yml)
│ └── deployment.yaml ✅ (from root)
├── docs/ 🆕
│ └── architecture.md ✅ (from root)
├── config/ 🆕 (for configuration files)
├── monitoring/ 🆕 (for Prometheus/Grafana)
├── models/ 🆕 (for AI models)
└── .github/workflows/ 🆕 (for CI/CD)

Legend:
✅ = Moved/updated existing file
🆕 = New directory or file
"

echo "🎉 Repository reorganization completed successfully!"
echo ""
echo "Next steps:"
echo "1. Review the new structure and file locations"
echo "2. Test that docker-compose up works with the new paths"
echo "3. Update any remaining hardcoded paths in your code"
echo "4. Initialize git in the new structure if needed"
echo "5. Create .github/workflows/ci.yml for automated testing"
echo ""
echo "All your existing files have been preserved and properly organized!"
