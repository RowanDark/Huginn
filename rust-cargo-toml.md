[package]
name = "huginn-security"
version = "0.1.0"
edition = "2021"
description = "Advanced security and anti-detection module for Huginn OSINT platform"
license = "MIT"
authors = ["Your Name your.email@example.com"]

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
ring = "0.16"
webpki = "0.22"

[dev-dependencies]
tokio-test = "0.4"

[features]
default = []
advanced-tls = ["rustls", "tokio-rustls"]
proxy-support = ["reqwest/socks"]
