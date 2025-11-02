"""
Enhanced STIX-like schema definitions for threat intelligence normalization.

This module provides comprehensive data models for normalizing threat intelligence
from various sources into a common, standardized format based on STIX 2.1 patterns.
"""

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union, Literal

from pydantic import BaseModel, Field, field_validator, model_validator


class IndicatorType(str, Enum):
    """Standard indicator types based on STIX patterns."""
    
    # Network indicators
    IP = "ip"
    IPV4 = "ipv4-addr"
    IPV6 = "ipv6-addr"
    DOMAIN = "domain-name"
    URL = "url"
    EMAIL = "email-addr"
    
    # File indicators
    FILE_HASH = "file"
    MD5 = "file:hashes.MD5"
    SHA1 = "file:hashes.SHA-1"
    SHA256 = "file:hashes.SHA-256"
    
    # System indicators
    REGISTRY_KEY = "windows-registry-key"
    PROCESS = "process"
    SERVICE = "service"
    USER_ACCOUNT = "user-account"
    
    # Malware artifacts
    MUTEX = "mutex"
    FILE_PATH = "file:name"
    
    # Vulnerability identifiers
    CVE = "vulnerability"
    
    # Custom types
    YARA_RULE = "yara-rule"
    SIGMA_RULE = "sigma-rule"
    CERTIFICATE = "x509-certificate"


class ThreatType(str, Enum):
    """Threat classification types."""
    
    MALWARE = "malware"
    PHISHING = "phishing"
    SPAM = "spam"
    BOTNET = "botnet"
    C2 = "command-and-control"
    EXPLOIT = "exploit"
    BACKDOOR = "backdoor"
    TROJAN = "trojan"
    RANSOMWARE = "ransomware"
    SPYWARE = "spyware"
    ADWARE = "adware"
    SCAM = "scam"
    SUSPICIOUS = "suspicious-activity"
    UNKNOWN = "unknown"


class ConfidenceLevel(str, Enum):
    """Confidence level enumeration."""
    
    LOW = "low"           # 0-30
    MEDIUM = "medium"     # 31-70
    HIGH = "high"         # 71-90
    VERY_HIGH = "very-high"  # 91-100


class SeverityLevel(str, Enum):
    """Severity level enumeration."""
    
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TLPMarking(str, Enum):
    """Traffic Light Protocol markings."""
    
    RED = "TLP:RED"
    AMBER = "TLP:AMBER"
    GREEN = "TLP:GREEN"
    WHITE = "TLP:WHITE"


class GeographicLocation(BaseModel):
    """Geographic location information."""
    
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    accuracy_radius: Optional[int] = None


class NetworkContext(BaseModel):
    """Network-related context information."""
    
    asn: Optional[int] = None
    as_name: Optional[str] = None
    isp: Optional[str] = None
    organization: Optional[str] = None
    network: Optional[str] = None
    ports: List[int] = Field(default_factory=list)
    protocols: List[str] = Field(default_factory=list)
    geolocation: Optional[GeographicLocation] = None


class FileContext(BaseModel):
    """File-related context information."""
    
    size: Optional[int] = None
    mime_type: Optional[str] = None
    file_type: Optional[str] = None
    magic_header: Optional[str] = None
    ssdeep: Optional[str] = None
    imphash: Optional[str] = None
    pehash: Optional[str] = None
    entropy: Optional[float] = None
    digital_signatures: List[Dict[str, Any]] = Field(default_factory=list)


class MalwareContext(BaseModel):
    """Malware-specific context information."""
    
    family: Optional[str] = None
    variant: Optional[str] = None
    aliases: List[str] = Field(default_factory=list)
    capabilities: List[str] = Field(default_factory=list)
    yara_rules: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    kill_chain_phases: List[str] = Field(default_factory=list)


class SourceMetadata(BaseModel):
    """Source metadata and provenance information."""
    
    source_name: str
    collection_method: str
    collected_at: datetime
    source_url: Optional[str] = None
    source_confidence: Optional[int] = Field(None, ge=0, le=100)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    report_id: Optional[str] = None
    campaign: Optional[str] = None
    actor: Optional[str] = None


class IndicatorPattern(BaseModel):
    """STIX-like indicator pattern."""
    
    pattern_type: str = "stix"
    pattern_value: str
    
    @field_validator('pattern_value')
    @classmethod
    def validate_pattern(cls, v):
        """Validate that pattern follows STIX format."""
        # Basic validation - could be expanded
        if not v.strip().startswith('[') or not v.strip().endswith(']'):
            raise ValueError("STIX pattern must be enclosed in brackets")
        return v


class NormalizedIndicator(BaseModel):
    """
    Normalized threat intelligence indicator based on STIX 2.1 patterns.
    
    This is the unified format that all source-specific indicators
    are transformed into for consistent processing.
    """
    
    # Core identification
    id: str = Field(default_factory=lambda: f"indicator--{uuid.uuid4()}")
    type: Literal["indicator"] = Field(default="indicator")
    spec_version: Literal["2.1"] = Field(default="2.1")
    
    # Indicator classification
    indicator_type: IndicatorType
    value: str  # The actual indicator value (IP, hash, domain, etc.)
    pattern: Optional[IndicatorPattern] = None  # STIX pattern representation
    
    # Threat classification
    threat_types: List[ThreatType] = Field(default_factory=list)
    malware_families: List[str] = Field(default_factory=list)
    
    # Confidence and severity
    confidence: int = Field(..., ge=0, le=100)
    confidence_level: Optional[ConfidenceLevel] = None
    severity: SeverityLevel = SeverityLevel.MEDIUM
    
    # Temporal information
    created: datetime = Field(default_factory=datetime.utcnow)
    modified: datetime = Field(default_factory=datetime.utcnow)
    valid_from: datetime = Field(default_factory=datetime.utcnow)
    valid_until: Optional[datetime] = None
    
    # Context information
    network_context: Optional[NetworkContext] = None
    file_context: Optional[FileContext] = None
    malware_context: Optional[MalwareContext] = None
    
    # Labels and tags
    labels: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    
    # Source and provenance
    source_metadata: SourceMetadata
    related_indicators: List[str] = Field(default_factory=list)
    
    # Sharing and handling
    tlp_marking: TLPMarking = TLPMarking.WHITE
    external_references: List[Dict[str, Any]] = Field(default_factory=list)
    
    # Additional context
    description: Optional[str] = None
    context: Dict[str, Any] = Field(default_factory=dict)
    
    @model_validator(mode='after')
    def set_computed_fields(self):
        """Set confidence level and pattern based on other fields."""
        # Set confidence level based on confidence score
        if self.confidence >= 80:
            self.confidence_level = ConfidenceLevel.HIGH
        elif self.confidence >= 60:
            self.confidence_level = ConfidenceLevel.MEDIUM
        else:
            self.confidence_level = ConfidenceLevel.LOW
        
        # Generate STIX pattern if not provided
        if not self.pattern:
            self.pattern = self._generate_stix_pattern()
            
        return self
    
    def _generate_stix_pattern(self) -> Optional[IndicatorPattern]:
        """Generate STIX pattern based on indicator type and value."""        
        # Generate appropriate STIX pattern
        if self.indicator_type in [IndicatorType.IP, IndicatorType.IPV4, IndicatorType.IPV6]:
            pattern_value = f"[ipv4-addr:value = '{self.value}']"
        elif self.indicator_type == IndicatorType.DOMAIN:
            pattern_value = f"[domain-name:value = '{self.value}']"
        elif self.indicator_type == IndicatorType.URL:
            pattern_value = f"[url:value = '{self.value}']"
        elif self.indicator_type == IndicatorType.EMAIL:
            pattern_value = f"[email-addr:value = '{self.value}']"
        elif self.indicator_type in [IndicatorType.MD5, IndicatorType.SHA1, IndicatorType.SHA256]:
            hash_type = self.indicator_type.value.split(':')[-1] if ':' in self.indicator_type.value else 'SHA-256'
            pattern_value = f"[file:hashes.'{hash_type}' = '{self.value}']"
        else:
            # Generic pattern
            pattern_value = f"[x-custom-object:value = '{self.value}']"
        
        return IndicatorPattern(pattern_value=pattern_value)
    
    def to_stix_dict(self) -> Dict[str, Any]:
        """Convert to STIX 2.1 dictionary format."""
        stix_dict = {
            "id": self.id,
            "type": self.type,
            "spec_version": self.spec_version,
            "created": self.created.isoformat(),
            "modified": self.modified.isoformat(),
            "pattern": self.pattern.pattern_value,
            "pattern_type": self.pattern.pattern_type,
            "valid_from": self.valid_from.isoformat(),
            "labels": self.labels + [threat.value for threat in self.threat_types],
            "confidence": self.confidence,
            "object_marking_refs": [f"marking-definition--{self.tlp_marking.value.lower().replace(':', '-')}"]
        }
        
        if self.valid_until:
            stix_dict["valid_until"] = self.valid_until.isoformat()
        
        if self.external_references:
            stix_dict["external_references"] = self.external_references
        
        return stix_dict
    
    def to_misp_dict(self) -> Dict[str, Any]:
        """Convert to MISP attribute format."""
        return {
            "uuid": self.id.split("--")[1],
            "type": self.indicator_type.value,
            "value": self.value,
            "category": "Network activity" if self.indicator_type in [
                IndicatorType.IP, IndicatorType.DOMAIN, IndicatorType.URL
            ] else "Payload delivery",
            "to_ids": True,
            "timestamp": int(self.created.timestamp()),
            "distribution": 0 if self.tlp_marking == TLPMarking.RED else 3,
            "comment": self.description or "",
            "Tag": [{"name": tag} for tag in self.tags]
        }
    
    def calculate_risk_score(self) -> float:
        """Calculate a risk score based on multiple factors."""
        risk_score = 0.0
        
        # Base risk from confidence
        risk_score += (self.confidence / 100) * 40
        
        # Risk from severity
        severity_weights = {
            SeverityLevel.INFO: 0,
            SeverityLevel.LOW: 10,
            SeverityLevel.MEDIUM: 25,
            SeverityLevel.HIGH: 40,
            SeverityLevel.CRITICAL: 50
        }
        risk_score += severity_weights.get(self.severity, 0)
        
        # Risk from threat types
        high_risk_threats = [
            ThreatType.RANSOMWARE, ThreatType.BACKDOOR, ThreatType.C2
        ]
        if any(threat in high_risk_threats for threat in self.threat_types):
            risk_score += 10
        
        return min(risk_score, 100.0)


class NormalizationRule(BaseModel):
    """Rule for normalizing source-specific data."""
    
    source_name: str
    field_mappings: Dict[str, str]  # source_field -> normalized_field
    value_transformations: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    default_values: Dict[str, Any] = Field(default_factory=dict)
    ignore_fields: List[str] = Field(default_factory=list)
    
    
class NormalizationResult(BaseModel):
    """Result of a normalization operation."""
    
    success: bool
    indicator: Optional[NormalizedIndicator] = None
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    source_data: Dict[str, Any] = Field(default_factory=dict)