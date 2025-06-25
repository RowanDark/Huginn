package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
)

// Enhanced OSINT scraper with multi-language integration
type OSINTEngine struct {
	redis           *redis.Client
	rustSecurityURL string
	pythonAIURL     string
	workerPool      *WorkerPool
	proxyManager    *ProxyManager
	antiDetect      *AntiDetectManager
	ctx             context.Context
	cancel          context.CancelFunc
}

// Job represents a scraping job with enhanced parameters
type Job struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"` // email, subdomain, social_media, general
	Target      string                 `json:"target"`
	Config      map[string]interface{} `json:"config"`
	Priority    int                    `json:"priority"`
	CreatedAt   time.Time             `json:"created_at"`
	Status      string                `json:"status"`
	Results     map[string]interface{} `json:"results,omitempty"`
	AIAnalysis  *AIAnalysisResult     `json:"ai_analysis,omitempty"`
	SecurityMeta *SecurityMetadata     `json:"security_meta,omitempty"`
}

// SecurityMetadata from Rust security service
type SecurityMetadata struct {
	Fingerprint   string `json:"fingerprint"`
	ProxyUsed     string `json:"proxy_used"`
	TLSProfile    string `json:"tls_profile"`
	UserAgent     string `json:"user_agent"`
	DetectionRisk string `json:"detection_risk"`
}

// AIAnalysisResult from Python AI service
type AIAnalysisResult struct {
	ThreatLevel      string                 `json:"threat_level"`
	Entities         []ExtractedEntity      `json:"entities"`
	Sentiment        string                 `json:"sentiment"`
	Classification   string                 `json:"classification"`
	IOCs             []IndicatorOfCompromise `json:"iocs"`
	RelatedCampaigns []string               `json:"related_campaigns"`
}

type ExtractedEntity struct {
	Type       string  `json:"type"`
	Value      string  `json:"value"`
	Confidence float64 `json:"confidence"`
}

type IndicatorOfCompromise struct {
	Type        string    `json:"type"`
	Value       string    `json:"value"`
	Confidence  float64   `json:"confidence"`
	ThreatType  string    `json:"threat_type"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
}

// WorkerPool manages concurrent scraping operations
type WorkerPool struct {
	workers    int
	jobQueue   chan *Job
	resultChan chan *Job
	quit       chan bool
	wg         sync.WaitGroup
	engine     *OSINTEngine
}

// ProxyManager handles proxy rotation and health
type ProxyManager struct {
	proxies     []Proxy
	currentIdx  int
	mu          sync.RWMutex
	healthCheck time.Duration
}

type Proxy struct {
	URL       string    `json:"url"`
	Type      string    `json:"type"`
	Health    string    `json:"health"`
	LastCheck time.Time `json:"last_check"`
	Failures  int       `json:"failures"`
}

// AntiDetectManager coordinates with Rust security service
type AntiDetectManager struct {
	securityURL string
	client      *http.Client
}

// NewOSINTEngine creates a new enhanced OSINT scraping engine
func NewOSINTEngine() *OSINTEngine {
	ctx, cancel := context.WithCancel(context.Background())
	
	// Redis connection
	rdb := redis.NewClient(&redis.Options{
		Addr: getEnv("REDIS_URL", "localhost:6379"),
		DB:   0,
	})

	engine := &OSINTEngine{
		redis:           rdb,
		rustSecurityURL: getEnv("RUST_SECURITY_URL", "http://localhost:8081"),
		pythonAIURL:     getEnv("PYTHON_AI_URL", "http://localhost:8082"),
		ctx:             ctx,
		cancel:          cancel,
	}

	// Initialize components
	engine.antiDetect = &AntiDetectManager{
		securityURL: engine.rustSecurityURL,
		client:      &http.Client{Timeout: 30 * time.Second},
	}

	engine.proxyManager = &ProxyManager{
		proxies:     []Proxy{},
		healthCheck: 5 * time.Minute,
	}

	engine.workerPool = &WorkerPool{
		workers:    getEnvInt("WORKER_POOL_SIZE", 10),
		jobQueue:   make(chan *Job, 1000),
		resultChan: make(chan *Job, 1000),
		quit:       make(chan bool),
		engine:     engine,
	}

	return engine
}

// Start initializes and starts the OSINT engine
func (e *OSINTEngine) Start() error {
	log.Println("Starting OSINT Engine with multi-language integration...")

	// Test connections to Rust and Python services
	if err := e.testServiceConnections(); err != nil {
		return fmt.Errorf("service connection test failed: %w", err)
	}

	// Start worker pool
	e.workerPool.Start()

	// Start proxy health checker
	go e.proxyManager.healthChecker()

	// Start result processor
	go e.processResults()

	log.Println("OSINT Engine started successfully")
	return nil
}

// testServiceConnections verifies connectivity to Rust and Python services
func (e *OSINTEngine) testServiceConnections() error {
	// Test Rust security service
	resp, err := http.Get(e.rustSecurityURL + "/health")
	if err != nil {
		return fmt.Errorf("rust security service unreachable: %w", err)
	}
	resp.Body.Close()

	// Test Python AI service
	resp, err = http.Get(e.pythonAIURL + "/health")
	if err != nil {
		return fmt.Errorf("python AI service unreachable: %w", err)
	}
	resp.Body.Close()

	log.Println("All service connections verified")
	return nil
}

// SubmitJob adds a new scraping job to the queue
func (e *OSINTEngine) SubmitJob(job *Job) error {
	job.ID = generateJobID()
	job.CreatedAt = time.Now()
	job.Status = "queued"

	// Store job in Redis
	jobData, err := json.Marshal(job)
	if err != nil {
		return err
	}

	err = e.redis.LPush(e.ctx, "job_queue", jobData).Err()
	if err != nil {
		return err
	}

	// Add to worker queue
	select {
	case e.workerPool.jobQueue <- job:
		log.Printf("Job %s queued successfully", job.ID)
	default:
		return fmt.Errorf("job queue full")
	}

	return nil
}

// ExecuteJob processes a single scraping job with full integration
func (e *OSINTEngine) ExecuteJob(job *Job) error {
	log.Printf("Executing job %s of type %s", job.ID, job.Type)

	// Step 1: Get security configuration from Rust service
	securityMeta, err := e.getSecurityConfiguration(job)
	if err != nil {
		log.Printf("Warning: Could not get security configuration: %v", err)
		// Continue with default security settings
	} else {
		job.SecurityMeta = securityMeta
	}

	// Step 2: Perform the actual scraping
	var results map[string]interface{}
	switch job.Type {
	case "email":
		results, err = e.scrapeEmails(job)
	case "subdomain":
		results, err = e.scrapeSubdomains(job)
	case "social_media":
		results, err = e.scrapeSocialMedia(job)
	case "general":
		results, err = e.scrapeGeneral(job)
	default:
		return fmt.Errorf("unknown job type: %s", job.Type)
	}

	if err != nil {
		job.Status = "failed"
		return err
	}

	job.Results = results

	// Step 3: Send results to Python AI service for analysis
	aiAnalysis, err := e.analyzeWithAI(job)
	if err != nil {
		log.Printf("Warning: AI analysis failed: %v", err)
		// Continue without AI analysis
	} else {
		job.AIAnalysis = aiAnalysis
	}

	job.Status = "completed"
	log.Printf("Job %s completed successfully", job.ID)

	return nil
}

// getSecurityConfiguration requests security parameters from Rust service
func (e *OSINTEngine) getSecurityConfiguration(job *Job) (*SecurityMetadata, error) {
	reqData := map[string]interface{}{
		"target":    job.Target,
		"job_type":  job.Type,
		"priority":  job.Priority,
	}

	jsonData, err := json.Marshal(reqData)
	if err != nil {
		return nil, err
	}

	resp, err := http.Post(
		e.rustSecurityURL+"/security/configure",
		"application/json",
		strings.NewReader(string(jsonData)),
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var securityMeta SecurityMetadata
	if err := json.NewDecoder(resp.Body).Decode(&securityMeta); err != nil {
		return nil, err
	}

	return &securityMeta, nil
}

// analyzeWithAI sends scraped data to Python AI service for analysis
func (e *OSINTEngine) analyzeWithAI(job *Job) (*AIAnalysisResult, error) {
	reqData := map[string]interface{}{
		"job_id":     job.ID,
		"job_type":   job.Type,
		"target":     job.Target,
		"results":    job.Results,
		"timestamp":  job.CreatedAt,
	}

	jsonData, err := json.Marshal(reqData)
	if err != nil {
		return nil, err
	}

	resp, err := http.Post(
		e.pythonAIURL+"/analyze",
		"application/json",
		strings.NewReader(string(jsonData)),
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var aiResult AIAnalysisResult
	if err := json.NewDecoder(resp.Body).Decode(&aiResult); err != nil {
		return nil, err
	}

	return &aiResult, nil
}

// Scraping methods with enhanced anti-detection
func (e *OSINTEngine) scrapeEmails(job *Job) (map[string]interface{}, error) {
	// Implementation with Rust security integration
	return map[string]interface{}{
		"emails_found": []string{},
		"domains":      []string{},
		"confidence":   0.0,
	}, nil
}

func (e *OSINTEngine) scrapeSubdomains(job *Job) (map[string]interface{}, error) {
	// Implementation with enhanced subdomain discovery
	return map[string]interface{}{
		"subdomains":    []string{},
		"active_hosts":  []string{},
		"technologies":  []string{},
	}, nil
}

func (e *OSINTEngine) scrapeSocialMedia(job *Job) (map[string]interface{}, error) {
	// Implementation with social media profiling
	return map[string]interface{}{
		"profiles":     []map[string]interface{}{},
		"connections":  []string{},
		"activity":     map[string]interface{}{},
	}, nil
}

func (e *OSINTEngine) scrapeGeneral(job *Job) (map[string]interface{}, error) {
	// General purpose scraping with intelligent content extraction
	return map[string]interface{}{
		"content":      "",
		"links":        []string{},
		"metadata":     map[string]interface{}{},
		"technologies": []string{},
	}, nil
}

// Worker pool implementation
func (wp *WorkerPool) Start() {
	for i := 0; i < wp.workers; i++ {
		wp.wg.Add(1)
		go wp.worker(i)
	}
	log.Printf("Started %d workers", wp.workers)
}

func (wp *WorkerPool) worker(id int) {
	defer wp.wg.Done()
	log.Printf("Worker %d started", id)

	for {
		select {
		case job := <-wp.jobQueue:
			log.Printf("Worker %d processing job %s", id, job.ID)
			err := wp.engine.ExecuteJob(job)
			if err != nil {
				job.Status = "failed"
				log.Printf("Worker %d: Job %s failed: %v", id, job.ID, err)
			}
			wp.resultChan <- job

		case <-wp.quit:
			log.Printf("Worker %d stopping", id)
			return
		}
	}
}

func (wp *WorkerPool) Stop() {
	close(wp.quit)
	wp.wg.Wait()
	close(wp.resultChan)
	log.Println("All workers stopped")
}

// Result processor
func (e *OSINTEngine) processResults() {
	for job := range e.workerPool.resultChan {
		// Store results in Redis
		jobData, err := json.Marshal(job)
		if err != nil {
			log.Printf("Error marshaling job results: %v", err)
			continue
		}

		// Store in completed jobs hash
		err = e.redis.HSet(e.ctx, "completed_jobs", job.ID, jobData).Err()
		if err != nil {
			log.Printf("Error storing job results: %v", err)
		}

		// Notify completion
		e.redis.Publish(e.ctx, "job_completed", job.ID)
		log.Printf("Job %s results processed and stored", job.ID)
	}
}

// HTTP API handlers
func (e *OSINTEngine) setupRoutes() *gin.Engine {
	r := gin.Default()

	// Health check
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "healthy", "timestamp": time.Now()})
	})

	// Submit job
	r.POST("/jobs", func(c *gin.Context) {
		var job Job
		if err := c.ShouldBindJSON(&job); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}

		if err := e.SubmitJob(&job); err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}

		c.JSON(201, gin.H{"job_id": job.ID, "status": "queued"})
	})

	// Get job status
	r.GET("/jobs/:id", func(c *gin.Context) {
		jobID := c.Param("id")
		
		jobData, err := e.redis.HGet(e.ctx, "completed_jobs", jobID).Result()
		if err != nil {
			c.JSON(404, gin.H{"error": "job not found"})
			return
		}

		var job Job
		if err := json.Unmarshal([]byte(jobData), &job); err != nil {
			c.JSON(500, gin.H{"error": "failed to parse job data"})
			return
		}

		c.JSON(200, job)
	})

	return r
}

// Utility functions
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func generateJobID() string {
	return fmt.Sprintf("job_%d_%s", time.Now().Unix(), 
		strings.ReplaceAll(uuid.New().String(), "-", "")[:8])
}

// Proxy health checker
func (pm *ProxyManager) healthChecker() {
	ticker := time.NewTicker(pm.healthCheck)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			pm.checkProxyHealth()
		}
	}
}

func (pm *ProxyManager) checkProxyHealth() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	for i := range pm.proxies {
		// Simple health check implementation
		client := &http.Client{
			Timeout: 10 * time.Second,
			// Configure proxy here
		}

		resp, err := client.Get("http://httpbin.org/ip")
		if err != nil {
			pm.proxies[i].Health = "unhealthy"
			pm.proxies[i].Failures++
		} else {
			resp.Body.Close()
			pm.proxies[i].Health = "healthy"
			pm.proxies[i].Failures = 0
		}
		pm.proxies[i].LastCheck = time.Now()
	}
}

// Main function
func main() {
	engine := NewOSINTEngine()
	
	// Start the engine
	if err := engine.Start(); err != nil {
		log.Fatalf("Failed to start OSINT engine: %v", err)
	}

	// Setup HTTP routes
	router := engine.setupRoutes()

	// Start HTTP server
	srv := &http.Server{
		Addr:    ":8080",
		Handler: router,
	}

	go func() {
		log.Println("Starting HTTP server on :8080")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server failed: %v", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down OSINT engine...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("HTTP server shutdown error: %v", err)
	}

	engine.workerPool.Stop()
	engine.cancel()

	log.Println("OSINT engine shutdown complete")
}
