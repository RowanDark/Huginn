// Rust Security Service - Advanced Anti-Detection and Fingerprinting
// src/main.rs

use actix_web::{web, App, HttpServer, HttpResponse, Result, middleware::Logger};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tokio::time::{Duration, interval};
use rand::Rng;
use chrono::{DateTime, Utc};

mod fingerprint;
mod tls;
mod crypto;

use fingerprint::{BrowserFingerprint, FingerprintManager};
use tls::{TLSProfile, TLSManager};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityRequest {
    pub target: String,
    pub job_type: String,
    pub priority: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityMetadata {
    pub fingerprint: String,
    pub proxy_used: String,
    pub tls_profile: String,
    pub user_agent: String,
    pub detection_risk: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfiguration {
    pub headers: HashMap<String, String>,
    pub tls_config: TLSProfile,
    pub proxy_config: ProxyConfig,
    pub timing_config: TimingConfig,
    pub fingerprint_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub proxy_url: String,
    pub proxy_type: String,
    pub rotation_interval: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingConfig {
    pub request_delay_min: u64,
    pub request_delay_max: u64,
    pub page_load_delay: u64,
    pub human_simulation: bool,
}

#[derive(Debug, Clone)]
pub struct SecurityService {
    pub fingerprint_manager: Arc<RwLock<FingerprintManager>>,
    pub tls_manager: Arc<RwLock<TLSManager>>,
    pub proxy_pool: Arc<RwLock<Vec<ProxyConfig>>>,
    pub risk_assessor: Arc<RwLock<RiskAssessor>>,
}

#[derive(Debug, Clone)]
pub struct RiskAssessor {
    pub domain_risk_cache: HashMap<String, f64>,
    pub detection_patterns: Vec<DetectionPattern>,
}

#[derive(Debug, Clone)]
pub struct DetectionPattern {
    pub pattern_type: String,
    pub indicators: Vec<String>,
    pub risk_score: f64,
}

impl SecurityService {
    pub fn new() -> Self {
        SecurityService {
            fingerprint_manager: Arc::new(RwLock::new(FingerprintManager::new())),
            tls_manager: Arc::new(RwLock::new(TLSManager::new())),
            proxy_pool: Arc::new(RwLock::new(Vec::new())),
            risk_assessor: Arc::new(RwLock::new(RiskAssessor::new())),
        }
    }

    pub async fn configure_security(&self, request: SecurityRequest) -> Result<SecurityConfiguration, String> {
        // Assess risk for the target
        let risk_score = self.assess_target_risk(&request.target).await?;
        
        // Select appropriate fingerprint based on risk and job type
        let fingerprint = self.select_fingerprint(&request, risk_score).await?;
        
        // Get TLS configuration
        let tls_config = self.get_tls_configuration(&request, risk_score).await?;
        
        // Select proxy
        let proxy_config = self.select_proxy(&request, risk_score).await?;
        
        // Configure timing
        let timing_config = self.configure_timing(&request, risk_score).await?;
        
        // Build headers
        let headers = self.build_headers(&fingerprint, &request).await?;

        Ok(SecurityConfiguration {
            headers,
            tls_config,
            proxy_config,
            timing_config,
            fingerprint_id: fingerprint.id.clone(),
        })
    }

    async fn assess_target_risk(&self, target: &str) -> Result<f64, String> {
        let mut risk_assessor = self.risk_assessor.write().unwrap();
        
        // Check cache first
        if let Some(&cached_risk) = risk_assessor.domain_risk_cache.get(target) {
            return Ok(cached_risk);
        }

        // Assess risk based on various factors
        let mut risk_score = 0.0;

        // Domain analysis
        if target.contains("cloudflare") || target.contains("akamai") {
            risk_score += 0.3; // Higher risk for CDN-protected sites
        }

        if target.ends_with(".gov") || target.ends_with(".mil") {
            risk_score += 0.5; // Higher risk for government sites
        }

        // Known anti-bot services
        if target.contains("recaptcha") || target.contains("captcha") {
            risk_score += 0.4;
        }

        // Social media platforms (higher detection)
        if target.contains("facebook") || target.contains("twitter") || 
           target.contains("linkedin") || target.contains("instagram") {
            risk_score += 0.6;
        }

        // Clamp risk score between 0 and 1
        risk_score = risk_score.min(1.0).max(0.0);

        // Cache the result
        risk_assessor.domain_risk_cache.insert(target.to_string(), risk_score);

        Ok(risk_score)
    }

    async fn select_fingerprint(&self, request: &SecurityRequest, risk_score: f64) -> Result<BrowserFingerprint, String> {
        let fingerprint_manager = self.fingerprint_manager.read().unwrap();
        
        // Select fingerprint based on risk and job type
        let fingerprint_type = if risk_score > 0.7 {
            "stealth" // High-end browser simulation
        } else if risk_score > 0.4 {
            "standard" // Normal browser fingerprint
        } else {
            "simple" // Basic fingerprint
        };

        fingerprint_manager.get_fingerprint(fingerprint_type)
            .ok_or_else(|| "No suitable fingerprint available".to_string())
    }

    async fn get_tls_configuration(&self, _request: &SecurityRequest, risk_score: f64) -> Result<TLSProfile, String> {
        let tls_manager = self.tls_manager.read().unwrap();
        
        let profile_type = if risk_score > 0.6 {
            "chrome_latest" // Latest Chrome TLS profile
        } else {
            "firefox_standard" // Standard Firefox profile
        };

        tls_manager.get_profile(profile_type)
            .ok_or_else(|| "No suitable TLS profile available".to_string())
    }

    async fn select_proxy(&self, _request: &SecurityRequest, risk_score: f64) -> Result<ProxyConfig, String> {
        let proxy_pool = self.proxy_pool.read().unwrap();
        
        if proxy_pool.is_empty() {
            return Ok(ProxyConfig {
                proxy_url: "direct".to_string(),
                proxy_type: "direct".to_string(),
                rotation_interval: 300,
            });
        }

        // Select proxy based on risk score
        let proxy_index = if risk_score > 0.5 {
            // Use rotating residential proxies for high-risk targets
            rand::thread_rng().gen_range(0..proxy_pool.len())
        } else {
            // Use datacenter proxies for low-risk targets
            0
        };

        Ok(proxy_pool[proxy_index].clone())
    }

    async fn configure_timing(&self, _request: &SecurityRequest, risk_score: f64) -> Result<TimingConfig, String> {
        let (min_delay, max_delay, page_delay, human_sim) = if risk_score > 0.7 {
            (2000, 8000, 3000, true) // Slow, human-like timing
        } else if risk_score > 0.4 {
            (1000, 4000, 2000, true) // Moderate timing
        } else {
            (500, 2000, 1000, false) // Fast timing
        };

        Ok(TimingConfig {
            request_delay_min: min_delay,
            request_delay_max: max_delay,
            page_load_delay: page_delay,
            human_simulation: human_sim,
        })
    }

    async fn build_headers(&self, fingerprint: &BrowserFingerprint, _request: &SecurityRequest) -> Result<HashMap<String, String>, String> {
        let mut headers = HashMap::new();

        headers.insert("User-Agent".to_string(), fingerprint.user_agent.clone());
        headers.insert("Accept".to_string(), fingerprint.accept.clone());
        headers.insert("Accept-Language".to_string(), fingerprint.accept_language.clone());
        headers.insert("Accept-Encoding".to_string(), fingerprint.accept_encoding.clone());
        headers.insert("DNT".to_string(), fingerprint.dnt.clone());
        headers.insert("Connection".to_string(), "keep-alive".to_string());
        headers.insert("Upgrade-Insecure-Requests".to_string(), "1".to_string());

        // Add randomized additional headers
        if rand::thread_rng().gen_bool(0.7) {
            headers.insert("Cache-Control".to_string(), "max-age=0".to_string());
        }

        if rand::thread_rng().gen_bool(0.5) {
            headers.insert("Sec-Fetch-Dest".to_string(), "document".to_string());
            headers.insert("Sec-Fetch-Mode".to_string(), "navigate".to_string());
            headers.insert("Sec-Fetch-Site".to_string(), "none".to_string());
        }

        Ok(headers)
    }
}

impl RiskAssessor {
    pub fn new() -> Self {
        let detection_patterns = vec![
            DetectionPattern {
                pattern_type: "rate_limiting".to_string(),
                indicators: vec!["429".to_string(), "rate limit".to_string()],
                risk_score: 0.8,
            },
            DetectionPattern {
                pattern_type: "captcha".to_string(),
                indicators: vec!["captcha".to_string(), "recaptcha".to_string()],
                risk_score: 0.9,
            },
            DetectionPattern {
                pattern_type: "bot_detection".to_string(),
                indicators: vec!["bot detected".to_string(), "unusual traffic".to_string()],
                risk_score: 0.95,
            },
        ];

        RiskAssessor {
            domain_risk_cache: HashMap::new(),
            detection_patterns,
        }
    }
}

// HTTP handlers
async fn health() -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "healthy",
        "service": "rust-security",
        "timestamp": Utc::now()
    })))
}

async fn ready() -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "ready"
    })))
}

async fn configure_security(
    service: web::Data<SecurityService>,
    request: web::Json<SecurityRequest>,
) -> Result<HttpResponse> {
    match service.configure_security(request.into_inner()).await {
        Ok(config) => Ok(HttpResponse::Ok().json(config)),
        Err(error) => Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": error
        }))),
    }
}

async fn get_fingerprint(
    service: web::Data<SecurityService>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let fingerprint_type = path.into_inner();
    let fingerprint_manager = service.fingerprint_manager.read().unwrap();
    
    match fingerprint_manager.get_fingerprint(&fingerprint_type) {
        Some(fingerprint) => Ok(HttpResponse::Ok().json(fingerprint)),
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Fingerprint type not found"
        }))),
    }
}

async fn rotate_fingerprints(service: web::Data<SecurityService>) -> Result<HttpResponse> {
    let mut fingerprint_manager = service.fingerprint_manager.write().unwrap();
    fingerprint_manager.rotate_fingerprints();
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Fingerprints rotated successfully"
    })))
}

// Background tasks
async fn fingerprint_rotation_task(service: web::Data<SecurityService>) {
    let mut interval = interval(Duration::from_secs(300)); // 5 minutes

    loop {
        interval.tick().await;
        
        let mut fingerprint_manager = service.fingerprint_manager.write().unwrap();
        fingerprint_manager.rotate_fingerprints();
        
        println!("Fingerprints rotated at {}", Utc::now());
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    let security_service = web::Data::new(SecurityService::new());

    // Start background tasks
    let service_clone = security_service.clone();
    tokio::spawn(async move {
        fingerprint_rotation_task(service_clone).await;
    });

    println!("Starting Rust Security Service on 0.0.0.0:8081");

    HttpServer::new(move || {
        App::new()
            .app_data(security_service.clone())
            .wrap(Logger::default())
            .route("/health", web::get().to(health))
            .route("/ready", web::get().to(ready))
            .route("/security/configure", web::post().to(configure_security))
            .route("/fingerprint/{type}", web::get().to(get_fingerprint))
            .route("/fingerprint/rotate", web::post().to(rotate_fingerprints))
    })
    .bind("0.0.0.0:8081")?
    .run()
    .await
}
