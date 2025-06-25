# Python AI/NLP Service - Threat Intelligence and Natural Language Processing
# src/main.py

import asyncio
import json
import logging
import os
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import uvicorn
from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
import redis.asyncio as redis
import numpy as np
from transformers import (
    AutoTokenizer, AutoModelForSequenceClassification,
    AutoModelForTokenClassification, pipeline
)
import spacy
import hashlib
from collections import defaultdict

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load spaCy model for NLP
try:
    nlp = spacy.load("en_core_web_sm")
except OSError:
    logger.warning("spaCy model not found. Install with: python -m spacy download en_core_web_sm")
    nlp = None

class AnalysisRequest(BaseModel):
    job_id: str
    job_type: str
    target: str
    results: Dict[str, Any]
    timestamp: datetime

class ExtractedEntity(BaseModel):
    type: str
    value: str
    confidence: float

class IndicatorOfCompromise(BaseModel):
    type: str
    value: str
    confidence: float
    threat_type: str
    first_seen: datetime
    last_seen: datetime

class AIAnalysisResult(BaseModel):
    threat_level: str
    entities: List[ExtractedEntity]
    sentiment: str
    classification: str
    iocs: List[IndicatorOfCompromise]
    related_campaigns: List[str]

class ThreatIntelligenceEngine:
    def __init__(self):
        self.models = {}
        self.ioc_database = defaultdict(list)
        self.campaign_signatures = {}
        self.threat_patterns = {}
        self.setup_models()
        self.load_threat_intelligence()

    def setup_models(self):
        """Initialize AI/ML models for analysis"""
        try:
            # Sentiment analysis model
            self.models['sentiment'] = pipeline(
                "sentiment-analysis",
                model="cardiffnlp/twitter-roberta-base-sentiment-latest",
                return_all_scores=True
            )
            
            # Named Entity Recognition model
            self.models['ner'] = pipeline(
                "ner",
                model="dbmdz/bert-large-cased-finetuned-conll03-english",
                aggregation_strategy="simple"
            )
            
            # Threat classification model (using general classification for demo)
            self.models['threat_classifier'] = pipeline(
                "text-classification",
                model="martin-ha/toxic-comment-model",
                return_all_scores=True
            )
            
            logger.info("AI models loaded successfully")
            
        except Exception as e:
            logger.error(f"Error loading AI models: {e}")
            self.models = {}

    def load_threat_intelligence(self):
        """Load threat intelligence data and IOC patterns"""
        # IOC patterns for detection
        self.ioc_patterns = {
            'ip': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'domain': r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\b',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'hash_md5': r'\b[a-fA-F0-9]{32}\b',
            'hash_sha1': r'\b[a-fA-F0-9]{40}\b',
            'hash_sha256': r'\b[a-fA-F0-9]{64}\b',
            'url': r'https?://[^\s<>"{}|\\^`\[\]]+',
            'cve': r'CVE-\d{4}-\d{4,}',
        }
        
        # Known threat actor signatures
        self.campaign_signatures = {
            'apt29': ['cozy bear', 'the dukes', 'minidionis', 'cozyduke'],
            'apt28': ['fancy bear', 'pawn storm', 'sednit', 'tsar team'],
            'lazarus': ['hidden cobra', 'zinc', 'nickel academy'],
            'equation_group': ['equation', 'eagleeye', 'doublefantasy'],
        }
        
        # Threat level keywords
        self.threat_keywords = {
            'critical': ['exploit', 'zero-day', 'ransomware', 'backdoor', 'rootkit'],
            'high': ['malware', 'trojan', 'virus', 'worm', 'phishing'],
            'medium': ['suspicious', 'anomaly', 'unusual', 'unauthorized'],
            'low': ['informational', 'advisory', 'warning']
        }

    async def analyze_content(self, request: AnalysisRequest) -> AIAnalysisResult:
        """Main analysis function that processes scraped content"""
        logger.info(f"Starting AI analysis for job {request.job_id}")
        
        # Extract text content from results
        text_content = self.extract_text_content(request.results)
        
        # Perform various analyses
        entities = await self.extract_entities(text_content)
        sentiment = await self.analyze_sentiment(text_content)
        classification = await self.classify_threat(text_content)
        iocs = await self.extract_iocs(text_content)
        threat_level = await self.assess_threat_level(text_content, entities, iocs)
        campaigns = await self.identify_campaigns(text_content, entities)
        
        result = AIAnalysisResult(
            threat_level=threat_level,
            entities=entities,
            sentiment=sentiment,
            classification=classification,
            iocs=iocs,
            related_campaigns=campaigns
        )
        
        # Store analysis results for future correlation
        await self.store_analysis_results(request.job_id, result)
        
        logger.info(f"AI analysis completed for job {request.job_id}")
        return result

    def extract_text_content(self, results: Dict[str, Any]) -> str:
        """Extract meaningful text content from scraping results"""
        text_parts = []
        
        if isinstance(results, dict):
            for key, value in results.items():
                if isinstance(value, str):
                    text_parts.append(value)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, str):
                            text_parts.append(item)
                        elif isinstance(item, dict):
                            text_parts.append(str(item))
        
        return " ".join(text_parts)

    async def extract_entities(self, text: str) -> List[ExtractedEntity]:
        """Extract named entities from text using NLP models"""
        entities = []
        
        if not text or not self.models.get('ner'):
            return entities
        
        try:
            # Use transformer-based NER
            ner_results = self.models['ner'](text)
            
            for entity in ner_results:
                entities.append(ExtractedEntity(
                    type=entity['entity_group'],
                    value=entity['word'],
                    confidence=entity['score']
                ))
            
            # Use spaCy for additional entity extraction if available
            if nlp:
                doc = nlp(text)
                for ent in doc.ents:
                    entities.append(ExtractedEntity(
                        type=ent.label_,
                        value=ent.text,
                        confidence=0.8  # Default confidence for spaCy
                    ))
        
        except Exception as e:
            logger.error(f"Error in entity extraction: {e}")
        
        return entities

    async def analyze_sentiment(self, text: str) -> str:
        """Analyze sentiment of the text content"""
        if not text or not self.models.get('sentiment'):
            return "neutral"
        
        try:
            sentiment_results = self.models['sentiment'](text)
            
            # Get the highest scoring sentiment
            best_sentiment = max(sentiment_results, key=lambda x: x['score'])
            return best_sentiment['label'].lower()
        
        except Exception as e:
            logger.error(f"Error in sentiment analysis: {e}")
            return "neutral"

    async def classify_threat(self, text: str) -> str:
        """Classify the threat level of the content"""
        if not text or not self.models.get('threat_classifier'):
            return "unknown"
        
        try:
            classification_results = self.models['threat_classifier'](text)
            
            # Map results to threat classifications
            if any(result['label'] == 'TOXIC' and result['score'] > 0.7 
                   for result in classification_results):
                return "malicious"
            elif any(result['label'] == 'TOXIC' and result['score'] > 0.3 
                     for result in classification_results):
                return "suspicious"
            else:
                return "benign"
        
        except Exception as e:
            logger.error(f"Error in threat classification: {e}")
            return "unknown"

    async def extract_iocs(self, text: str) -> List[IndicatorOfCompromise]:
        """Extract Indicators of Compromise from text"""
        import re
        iocs = []
        current_time = datetime.utcnow()
        
        for ioc_type, pattern in self.ioc_patterns.items():
            matches = re.findall(pattern, text)
            
            for match in matches:
                # Basic validation and scoring
                confidence = self.calculate_ioc_confidence(ioc_type, match)
                threat_type = self.determine_threat_type(ioc_type, match)
                
                if confidence > 0.5:  # Only include high-confidence IOCs
                    ioc = IndicatorOfCompromise(
                        type=ioc_type,
                        value=match,
                        confidence=confidence,
                        threat_type=threat_type,
                        first_seen=current_time,
                        last_seen=current_time
                    )
                    iocs.append(ioc)
        
        return iocs

    def calculate_ioc_confidence(self, ioc_type: str, value: str) -> float:
        """Calculate confidence score for an IOC"""
        # Basic confidence scoring logic
        base_confidence = 0.7
        
        # Adjust based on IOC type
        if ioc_type in ['hash_md5', 'hash_sha1', 'hash_sha256']:
            return 0.95  # High confidence for hashes
        elif ioc_type == 'cve':
            return 0.9   # High confidence for CVEs
        elif ioc_type == 'ip':
            # Check if it's a private IP
            if self.is_private_ip(value):
                return 0.3
            return 0.8
        elif ioc_type == 'domain':
            # Check domain reputation (simplified)
            if any(tld in value for tld in ['.tk', '.ml', '.ga']):
                return 0.9  # Suspicious TLDs
            return base_confidence
        
        return base_confidence

    def is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        
        try:
            first_octet = int(parts[0])
            second_octet = int(parts[1])
            
            # Private IP ranges
            if first_octet == 10:
                return True
            elif first_octet == 172 and 16 <= second_octet <= 31:
                return True
            elif first_octet == 192 and second_octet == 168:
                return True
            elif ip.startswith('127.'):
                return True
            
            return False
        except ValueError:
            return False

    def determine_threat_type(self, ioc_type: str, value: str) -> str:
        """Determine the threat type based on IOC characteristics"""
        threat_type_mapping = {
            'hash_md5': 'malware',
            'hash_sha1': 'malware',
            'hash_sha256': 'malware',
            'ip': 'network',
            'domain': 'network',
            'url': 'network',
            'email': 'phishing',
            'cve': 'vulnerability'
        }
        
        return threat_type_mapping.get(ioc_type, 'unknown')

    async def assess_threat_level(self, text: str, entities: List[ExtractedEntity], 
                                  iocs: List[IndicatorOfCompromise]) -> str:
        """Assess overall threat level based on multiple factors"""
        score = 0
        
        # Score based on threat keywords
        text_lower = text.lower()
        for level, keywords in self.threat_keywords.items():
            for keyword in keywords:
                if keyword in text_lower:
                    if level == 'critical':
                        score += 10
                    elif level == 'high':
                        score += 7
                    elif level == 'medium':
                        score += 4
                    elif level == 'low':
                        score += 1
        
        # Score based on IOCs
        for ioc in iocs:
            if ioc.confidence > 0.8:
                score += 5
            elif ioc.confidence > 0.6:
                score += 3
            else:
                score += 1
        
        # Score based on entities
        for entity in entities:
            if entity.type in ['ORG', 'PERSON'] and entity.confidence > 0.8:
                score += 2
        
        # Determine threat level
        if score >= 20:
            return "critical"
        elif score >= 10:
            return "high"
        elif score >= 5:
            return "medium"
        elif score > 0:
            return "low"
        else:
            return "info"

    async def identify_campaigns(self, text: str, entities: List[ExtractedEntity]) -> List[str]:
        """Identify related threat campaigns"""
        campaigns = []
        text_lower = text.lower()
        
        # Check campaign signatures
        for campaign, signatures in self.campaign_signatures.items():
            for signature in signatures:
                if signature.lower() in text_lower:
                    campaigns.append(campaign)
                    break
        
        # Check entities for campaign indicators
        for entity in entities:
            entity_value_lower = entity.value.lower()
            for campaign, signatures in self.campaign_signatures.items():
                if any(sig in entity_value_lower for sig in signatures):
                    if campaign not in campaigns:
                        campaigns.append(campaign)
        
        return campaigns

    async def store_analysis_results(self, job_id: str, result: AIAnalysisResult):
        """Store analysis results for future correlation"""
        try:
            # Store in Redis for quick access
            redis_client = redis.from_url(os.getenv('REDIS_URL', 'redis://localhost:6379'))
            
            # Store full results
            await redis_client.hset(
                'ai_analysis_results',
                job_id,
                json.dumps(result.dict(), default=str)
            )
            
            # Store IOCs separately for correlation
            for ioc in result.iocs:
                await redis_client.sadd(f'ioc:{ioc.type}', ioc.value)
                await redis_client.hset(
                    f'ioc_details:{ioc.value}',
                    'first_seen', ioc.first_seen.isoformat(),
                    'last_seen', ioc.last_seen.isoformat(),
                    'confidence', str(ioc.confidence),
                    'threat_type', ioc.threat_type
                )
            
            await redis_client.close()
            
        except Exception as e:
            logger.error(f"Error storing analysis results: {e}")

# FastAPI app setup
app = FastAPI(title="OSINT AI/NLP Service", version="1.0.0")
threat_engine = ThreatIntelligenceEngine()

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "python-ai",
        "timestamp": datetime.utcnow(),
        "models_loaded": len(threat_engine.models)
    }

@app.get("/ready")
async def readiness_check():
    return {"status": "ready"}

@app.post("/analyze", response_model=AIAnalysisResult)
async def analyze_content(request: AnalysisRequest):
    try:
        result = await threat_engine.analyze_content(request)
        return result
    except Exception as e:
        logger.error(f"Error in analysis: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/iocs/{ioc_type}")
async def get_iocs_by_type(ioc_type: str):
    """Get stored IOCs by type"""
    try:
        redis_client = redis.from_url(os.getenv('REDIS_URL', 'redis://localhost:6379'))
        iocs = await redis_client.smembers(f'ioc:{ioc_type}')
        await redis_client.close()
        
        return {"ioc_type": ioc_type, "iocs": list(iocs)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/campaigns")
async def get_known_campaigns():
    """Get list of known threat campaigns"""
    return {"campaigns": list(threat_engine.campaign_signatures.keys())}

@app.post("/correlate")
async def correlate_indicators(ioc_values: List[str]):
    """Correlate indicators across stored analysis results"""
    try:
        redis_client = redis.from_url(os.getenv('REDIS_URL', 'redis://localhost:6379'))
        
        correlations = {}
        for ioc_value in ioc_values:
            details = await redis_client.hgetall(f'ioc_details:{ioc_value}')
            if details:
                correlations[ioc_value] = details
        
        await redis_client.close()
        return {"correlations": correlations}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8082,
        workers=int(os.getenv("WORKERS", "1")),
        reload=False
    )
