"""
Advanced risk assessment algorithms for threat intelligence scoring.

This module implements sophisticated risk assessment capabilities including
CVE criticality analysis, malware family danger classification, infrastructure
reputation assessment, and behavioral risk analysis.
"""

import logging
import statistics
import math
import re
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, Counter
import json

try:
    from ..normalizers.schema import NormalizedIndicator, IndicatorType
    from .engine import ThreatCategory, PriorityBand
except ImportError:
    from normalizers.schema import NormalizedIndicator, IndicatorType
    from scoring.engine import ThreatCategory, PriorityBand

logger = logging.getLogger(__name__)


class RiskLevel(Enum):
    """Risk level classifications."""
    CRITICAL = "critical"      # 0.9 - 1.0
    HIGH = "high"              # 0.7 - 0.89
    MEDIUM = "medium"          # 0.4 - 0.69
    LOW = "low"                # 0.1 - 0.39
    MINIMAL = "minimal"        # 0.0 - 0.09


class VulnerabilityCategory(Enum):
    """Vulnerability categories for risk assessment."""
    REMOTE_CODE_EXECUTION = "rce"
    PRIVILEGE_ESCALATION = "privesc"
    INFORMATION_DISCLOSURE = "info_disclosure"
    DENIAL_OF_SERVICE = "dos"
    AUTHENTICATION_BYPASS = "auth_bypass"
    INJECTION = "injection"
    BUFFER_OVERFLOW = "buffer_overflow"
    CRYPTOGRAPHIC = "crypto"
    CONFIGURATION = "config"
    UNKNOWN = "unknown"


@dataclass
class CVERiskProfile:
    """Risk profile for a CVE vulnerability."""
    
    cve_id: str
    cvss_v3_score: Optional[float] = None
    cvss_v2_score: Optional[float] = None
    
    # Vulnerability characteristics
    category: VulnerabilityCategory = VulnerabilityCategory.UNKNOWN
    attack_vector: str = "unknown"       # network, adjacent, local, physical
    attack_complexity: str = "unknown"   # low, high
    privileges_required: str = "unknown" # none, low, high
    user_interaction: str = "unknown"    # none, required
    
    # Exploitation context
    exploit_available: bool = False
    in_wild_exploitation: bool = False
    weaponized: bool = False
    
    # Risk factors
    risk_score: float = 0.0
    risk_level: RiskLevel = RiskLevel.MINIMAL
    risk_factors: List[str] = field(default_factory=list)
    
    # Temporal factors
    published_date: Optional[datetime] = None
    last_modified: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'cve_id': self.cve_id,
            'cvss_scores': {
                'v3_score': self.cvss_v3_score,
                'v2_score': self.cvss_v2_score
            },
            'characteristics': {
                'category': self.category.value,
                'attack_vector': self.attack_vector,
                'attack_complexity': self.attack_complexity,
                'privileges_required': self.privileges_required,
                'user_interaction': self.user_interaction
            },
            'exploitation': {
                'exploit_available': self.exploit_available,
                'in_wild_exploitation': self.in_wild_exploitation,
                'weaponized': self.weaponized
            },
            'risk_assessment': {
                'risk_score': self.risk_score,
                'risk_level': self.risk_level.value,
                'risk_factors': self.risk_factors
            },
            'temporal': {
                'published_date': self.published_date.isoformat() if self.published_date else None,
                'last_modified': self.last_modified.isoformat() if self.last_modified else None
            }
        }


@dataclass
class MalwareFamilyRisk:
    """Risk assessment for malware families."""
    
    family_name: str
    family_type: str = "unknown"  # trojan, ransomware, backdoor, etc.
    
    # Capability assessment
    capabilities: Set[str] = field(default_factory=set)
    persistence_mechanisms: Set[str] = field(default_factory=set)
    evasion_techniques: Set[str] = field(default_factory=set)
    
    # Impact assessment
    data_theft: bool = False
    system_destruction: bool = False
    financial_impact: bool = False
    operational_disruption: bool = False
    
    # Targeting
    targeted_sectors: Set[str] = field(default_factory=set)
    geographic_targeting: Set[str] = field(default_factory=set)
    
    # Risk scoring
    risk_score: float = 0.0
    risk_level: RiskLevel = RiskLevel.MINIMAL
    risk_factors: List[str] = field(default_factory=list)
    
    # Attribution
    attributed_groups: Set[str] = field(default_factory=set)
    sophistication_level: str = "low"  # low, medium, high, advanced
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'family_info': {
                'family_name': self.family_name,
                'family_type': self.family_type
            },
            'capabilities': {
                'capabilities': list(self.capabilities),
                'persistence_mechanisms': list(self.persistence_mechanisms),
                'evasion_techniques': list(self.evasion_techniques)
            },
            'impact': {
                'data_theft': self.data_theft,
                'system_destruction': self.system_destruction,
                'financial_impact': self.financial_impact,
                'operational_disruption': self.operational_disruption
            },
            'targeting': {
                'targeted_sectors': list(self.targeted_sectors),
                'geographic_targeting': list(self.geographic_targeting)
            },
            'risk_assessment': {
                'risk_score': self.risk_score,
                'risk_level': self.risk_level.value,
                'risk_factors': self.risk_factors
            },
            'attribution': {
                'attributed_groups': list(self.attributed_groups),
                'sophistication_level': self.sophistication_level
            }
        }


@dataclass
class InfrastructureRisk:
    """Risk assessment for infrastructure indicators."""
    
    indicator_value: str
    indicator_type: str
    
    # Infrastructure characteristics
    hosting_provider: Optional[str] = None
    asn: Optional[int] = None
    country: Optional[str] = None
    
    # Reputation factors
    reputation_sources: Dict[str, float] = field(default_factory=dict)
    blocklist_appearances: int = 0
    historical_malicious_activity: bool = False
    
    # Usage patterns
    c2_usage: bool = False
    malware_hosting: bool = False
    phishing_hosting: bool = False
    scanning_source: bool = False
    
    # Risk assessment
    risk_score: float = 0.0
    risk_level: RiskLevel = RiskLevel.MINIMAL
    risk_factors: List[str] = field(default_factory=list)
    
    # Temporal factors
    first_seen_malicious: Optional[datetime] = None
    last_seen_malicious: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'indicator': {
                'value': self.indicator_value,
                'type': self.indicator_type
            },
            'infrastructure': {
                'hosting_provider': self.hosting_provider,
                'asn': self.asn,
                'country': self.country
            },
            'reputation': {
                'reputation_sources': self.reputation_sources,
                'blocklist_appearances': self.blocklist_appearances,
                'historical_malicious_activity': self.historical_malicious_activity
            },
            'usage_patterns': {
                'c2_usage': self.c2_usage,
                'malware_hosting': self.malware_hosting,
                'phishing_hosting': self.phishing_hosting,
                'scanning_source': self.scanning_source
            },
            'risk_assessment': {
                'risk_score': self.risk_score,
                'risk_level': self.risk_level.value,
                'risk_factors': self.risk_factors
            },
            'temporal': {
                'first_seen_malicious': self.first_seen_malicious.isoformat() if self.first_seen_malicious else None,
                'last_seen_malicious': self.last_seen_malicious.isoformat() if self.last_seen_malicious else None
            }
        }


class CVERiskAnalyzer:
    """Analyzes CVE vulnerabilities for risk assessment."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize CVE risk analyzer."""
        self.config = config or {}
        
        # CVE category patterns
        self.category_patterns = {
            VulnerabilityCategory.REMOTE_CODE_EXECUTION: [
                'remote code execution', 'rce', 'code execution', 'arbitrary code',
                'command injection', 'execute arbitrary'
            ],
            VulnerabilityCategory.PRIVILEGE_ESCALATION: [
                'privilege escalation', 'elevation of privilege', 'gain privileges',
                'escalate privileges', 'root access'
            ],
            VulnerabilityCategory.INFORMATION_DISCLOSURE: [
                'information disclosure', 'information leak', 'data exposure',
                'sensitive information', 'memory disclosure'
            ],
            VulnerabilityCategory.DENIAL_OF_SERVICE: [
                'denial of service', 'dos', 'crash', 'hang', 'resource exhaustion'
            ],
            VulnerabilityCategory.AUTHENTICATION_BYPASS: [
                'authentication bypass', 'bypass authentication', 'auth bypass',
                'login bypass', 'access control'
            ],
            VulnerabilityCategory.INJECTION: [
                'sql injection', 'xss', 'cross-site scripting', 'ldap injection',
                'command injection', 'code injection'
            ],
            VulnerabilityCategory.BUFFER_OVERFLOW: [
                'buffer overflow', 'stack overflow', 'heap overflow',
                'memory corruption', 'boundary error'
            ],
            VulnerabilityCategory.CRYPTOGRAPHIC: [
                'cryptographic', 'encryption', 'certificate', 'ssl', 'tls',
                'hash collision', 'weak encryption'
            ]
        }
        
        # High-risk CVE characteristics
        self.high_risk_vectors = {'network'}
        self.high_risk_complexity = {'low'}
        self.high_risk_privileges = {'none'}
        self.high_risk_interaction = {'none'}
        
        logger.debug("CVE risk analyzer initialized")
    
    def analyze_cve_risk(self, 
                        cve_id: str,
                        cve_data: Dict[str, Any]) -> CVERiskProfile:
        """Analyze risk for a specific CVE."""
        
        profile = CVERiskProfile(cve_id=cve_id)
        
        # Extract CVSS scores
        profile.cvss_v3_score = cve_data.get('cvss_v3_score')
        profile.cvss_v2_score = cve_data.get('cvss_v2_score')
        
        # Extract vulnerability characteristics
        profile.attack_vector = cve_data.get('attack_vector', 'unknown').lower()
        profile.attack_complexity = cve_data.get('attack_complexity', 'unknown').lower()
        profile.privileges_required = cve_data.get('privileges_required', 'unknown').lower()
        profile.user_interaction = cve_data.get('user_interaction', 'unknown').lower()
        
        # Determine vulnerability category
        description = cve_data.get('description', '').lower()
        profile.category = self._categorize_vulnerability(description)
        
        # Check exploitation status
        profile.exploit_available = cve_data.get('exploit_available', False)
        profile.in_wild_exploitation = cve_data.get('in_wild_exploitation', False)
        profile.weaponized = cve_data.get('weaponized', False)
        
        # Extract dates
        if cve_data.get('published_date'):
            try:
                profile.published_date = datetime.fromisoformat(cve_data['published_date'].replace('Z', '+00:00'))
            except:
                pass
        
        if cve_data.get('last_modified'):
            try:
                profile.last_modified = datetime.fromisoformat(cve_data['last_modified'].replace('Z', '+00:00'))
            except:
                pass
        
        # Calculate risk score
        profile.risk_score, profile.risk_factors = self._calculate_cve_risk_score(profile)
        profile.risk_level = self._determine_risk_level(profile.risk_score)
        
        return profile
    
    def _categorize_vulnerability(self, description: str) -> VulnerabilityCategory:
        """Categorize vulnerability based on description."""
        
        description_lower = description.lower()
        
        for category, patterns in self.category_patterns.items():
            if any(pattern in description_lower for pattern in patterns):
                return category
        
        return VulnerabilityCategory.UNKNOWN
    
    def _calculate_cve_risk_score(self, profile: CVERiskProfile) -> Tuple[float, List[str]]:
        """Calculate risk score for CVE."""
        
        risk_factors = []
        risk_components = []
        
        # Base CVSS score (primary factor)
        cvss_score = profile.cvss_v3_score or profile.cvss_v2_score
        if cvss_score is not None:
            # Normalize CVSS (0-10) to (0-1)
            base_risk = cvss_score / 10.0
            risk_components.append(base_risk * 0.5)  # 50% weight
            risk_factors.append(f"cvss_score_{cvss_score}")
        else:
            # No CVSS, use category-based scoring
            base_risk = self._get_category_base_risk(profile.category)
            risk_components.append(base_risk * 0.5)
            risk_factors.append(f"category_risk_{profile.category.value}_{base_risk:.2f}")
        
        # Attack vector risk
        vector_risk = 0.3  # Default
        if profile.attack_vector in self.high_risk_vectors:
            vector_risk = 0.8
            risk_factors.append("high_risk_attack_vector_network")
        elif profile.attack_vector == 'adjacent':
            vector_risk = 0.6
            risk_factors.append("medium_risk_attack_vector_adjacent")
        elif profile.attack_vector == 'local':
            vector_risk = 0.4
            risk_factors.append("low_risk_attack_vector_local")
        
        risk_components.append(vector_risk * 0.2)  # 20% weight
        
        # Attack complexity risk (inverted - low complexity = high risk)
        complexity_risk = 0.5  # Default
        if profile.attack_complexity == 'low':
            complexity_risk = 0.8
            risk_factors.append("low_attack_complexity")
        elif profile.attack_complexity == 'high':
            complexity_risk = 0.3
            risk_factors.append("high_attack_complexity")
        
        risk_components.append(complexity_risk * 0.1)  # 10% weight
        
        # Privileges required (inverted - none required = high risk)
        privileges_risk = 0.5  # Default
        if profile.privileges_required == 'none':
            privileges_risk = 0.9
            risk_factors.append("no_privileges_required")
        elif profile.privileges_required == 'low':
            privileges_risk = 0.6
            risk_factors.append("low_privileges_required")
        elif profile.privileges_required == 'high':
            privileges_risk = 0.3
            risk_factors.append("high_privileges_required")
        
        risk_components.append(privileges_risk * 0.1)  # 10% weight
        
        # Exploitation status (major risk multiplier)
        exploitation_multiplier = 1.0
        
        if profile.in_wild_exploitation:
            exploitation_multiplier = 1.5
            risk_factors.append("active_exploitation_in_wild")
        elif profile.weaponized:
            exploitation_multiplier = 1.3
            risk_factors.append("weaponized_exploit_available")
        elif profile.exploit_available:
            exploitation_multiplier = 1.2
            risk_factors.append("public_exploit_available")
        
        # Age factor (newer CVEs are riskier)
        age_multiplier = 1.0
        if profile.published_date:
            age = datetime.utcnow() - profile.published_date
            if age <= timedelta(days=30):
                age_multiplier = 1.2
                risk_factors.append("recently_published_cve")
            elif age <= timedelta(days=90):
                age_multiplier = 1.1
                risk_factors.append("recent_cve")
        
        # Calculate final risk score
        base_score = sum(risk_components)
        final_score = base_score * exploitation_multiplier * age_multiplier
        
        # Ensure score is in valid range
        final_score = max(0.0, min(1.0, final_score))
        
        return final_score, risk_factors
    
    def _get_category_base_risk(self, category: VulnerabilityCategory) -> float:
        """Get base risk score for vulnerability category."""
        
        category_risks = {
            VulnerabilityCategory.REMOTE_CODE_EXECUTION: 0.9,
            VulnerabilityCategory.PRIVILEGE_ESCALATION: 0.8,
            VulnerabilityCategory.AUTHENTICATION_BYPASS: 0.7,
            VulnerabilityCategory.INJECTION: 0.7,
            VulnerabilityCategory.BUFFER_OVERFLOW: 0.8,
            VulnerabilityCategory.INFORMATION_DISCLOSURE: 0.5,
            VulnerabilityCategory.DENIAL_OF_SERVICE: 0.4,
            VulnerabilityCategory.CRYPTOGRAPHIC: 0.6,
            VulnerabilityCategory.CONFIGURATION: 0.3,
            VulnerabilityCategory.UNKNOWN: 0.4
        }
        
        return category_risks.get(category, 0.4)
    
    def _determine_risk_level(self, risk_score: float) -> RiskLevel:
        """Determine risk level from score."""
        
        if risk_score >= 0.9:
            return RiskLevel.CRITICAL
        elif risk_score >= 0.7:
            return RiskLevel.HIGH
        elif risk_score >= 0.4:
            return RiskLevel.MEDIUM
        elif risk_score >= 0.1:
            return RiskLevel.LOW
        else:
            return RiskLevel.MINIMAL


class MalwareRiskAnalyzer:
    """Analyzes malware families for risk assessment."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize malware risk analyzer."""
        self.config = config or {}
        
        # Malware type risk levels
        self.type_risk_levels = {
            'ransomware': 1.0,
            'rootkit': 0.9,
            'backdoor': 0.8,
            'trojan': 0.7,
            'worm': 0.6,
            'spyware': 0.6,
            'keylogger': 0.5,
            'adware': 0.3,
            'pup': 0.2
        }
        
        # High-risk capabilities
        self.high_risk_capabilities = {
            'file_encryption', 'data_exfiltration', 'credential_theft',
            'remote_access', 'lateral_movement', 'persistence',
            'anti_analysis', 'process_injection', 'rootkit_capabilities'
        }
        
        # Sophisticated evasion techniques
        self.advanced_evasion = {
            'polymorphic', 'metamorphic', 'packing', 'obfuscation',
            'anti_vm', 'anti_debug', 'code_injection', 'living_off_land'
        }
        
        logger.debug("Malware risk analyzer initialized")
    
    def analyze_malware_risk(self, 
                           family_name: str,
                           malware_data: Dict[str, Any]) -> MalwareFamilyRisk:
        """Analyze risk for a malware family."""
        
        profile = MalwareFamilyRisk(family_name=family_name)
        
        # Extract family type
        profile.family_type = malware_data.get('family_type', 'unknown').lower()
        
        # Extract capabilities
        profile.capabilities = set(malware_data.get('capabilities', []))
        profile.persistence_mechanisms = set(malware_data.get('persistence_mechanisms', []))
        profile.evasion_techniques = set(malware_data.get('evasion_techniques', []))
        
        # Extract impact information
        profile.data_theft = malware_data.get('data_theft', False)
        profile.system_destruction = malware_data.get('system_destruction', False)
        profile.financial_impact = malware_data.get('financial_impact', False)
        profile.operational_disruption = malware_data.get('operational_disruption', False)
        
        # Extract targeting information
        profile.targeted_sectors = set(malware_data.get('targeted_sectors', []))
        profile.geographic_targeting = set(malware_data.get('geographic_targeting', []))
        
        # Extract attribution
        profile.attributed_groups = set(malware_data.get('attributed_groups', []))
        profile.sophistication_level = malware_data.get('sophistication_level', 'low')
        
        # Calculate risk score
        profile.risk_score, profile.risk_factors = self._calculate_malware_risk_score(profile)
        profile.risk_level = self._determine_risk_level(profile.risk_score)
        
        return profile
    
    def _calculate_malware_risk_score(self, profile: MalwareFamilyRisk) -> Tuple[float, List[str]]:
        """Calculate risk score for malware family."""
        
        risk_factors = []
        risk_components = []
        
        # Base type risk (40% weight)
        type_risk = self.type_risk_levels.get(profile.family_type, 0.4)
        risk_components.append(type_risk * 0.4)
        risk_factors.append(f"malware_type_{profile.family_type}_{type_risk:.2f}")
        
        # Capability assessment (25% weight)
        capability_score = 0.0
        high_risk_count = 0
        
        for capability in profile.capabilities:
            capability_lower = capability.lower()
            if any(high_risk in capability_lower for high_risk in self.high_risk_capabilities):
                high_risk_count += 1
        
        if high_risk_count > 0:
            capability_score = min(high_risk_count * 0.15, 0.9)
            risk_factors.append(f"high_risk_capabilities_{high_risk_count}")
        
        risk_components.append(capability_score * 0.25)
        
        # Impact assessment (20% weight)
        impact_score = 0.0
        impact_factors = []
        
        if profile.system_destruction:
            impact_score += 0.3
            impact_factors.append("system_destruction")
        
        if profile.financial_impact:
            impact_score += 0.25
            impact_factors.append("financial_impact")
        
        if profile.data_theft:
            impact_score += 0.2
            impact_factors.append("data_theft")
        
        if profile.operational_disruption:
            impact_score += 0.15
            impact_factors.append("operational_disruption")
        
        if impact_factors:
            risk_factors.extend([f"impact_{factor}" for factor in impact_factors])
        
        risk_components.append(min(impact_score, 1.0) * 0.2)
        
        # Evasion sophistication (10% weight)
        evasion_score = 0.0
        advanced_count = 0
        
        for technique in profile.evasion_techniques:
            technique_lower = technique.lower()
            if any(advanced in technique_lower for advanced in self.advanced_evasion):
                advanced_count += 1
        
        if advanced_count > 0:
            evasion_score = min(advanced_count * 0.1, 0.8)
            risk_factors.append(f"advanced_evasion_{advanced_count}")
        
        risk_components.append(evasion_score * 0.1)
        
        # Attribution and sophistication (5% weight)
        attribution_score = 0.0
        
        if profile.attributed_groups:
            # Known threat group attribution increases risk
            attribution_score = 0.3
            risk_factors.append(f"attributed_groups_{len(profile.attributed_groups)}")
        
        if profile.sophistication_level in ['high', 'advanced']:
            attribution_score += 0.4
            risk_factors.append(f"sophistication_{profile.sophistication_level}")
        
        risk_components.append(min(attribution_score, 1.0) * 0.05)
        
        # Calculate final score
        final_score = sum(risk_components)
        
        # Ensure score is in valid range
        final_score = max(0.0, min(1.0, final_score))
        
        return final_score, risk_factors
    
    def _determine_risk_level(self, risk_score: float) -> RiskLevel:
        """Determine risk level from score."""
        
        if risk_score >= 0.9:
            return RiskLevel.CRITICAL
        elif risk_score >= 0.7:
            return RiskLevel.HIGH
        elif risk_score >= 0.4:
            return RiskLevel.MEDIUM
        elif risk_score >= 0.1:
            return RiskLevel.LOW
        else:
            return RiskLevel.MINIMAL


class InfrastructureRiskAnalyzer:
    """Analyzes infrastructure indicators for risk assessment."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize infrastructure risk analyzer."""
        self.config = config or {}
        
        # High-risk countries (for hosting malicious infrastructure)
        self.high_risk_countries = {
            'CN', 'RU', 'KP', 'IR'  # China, Russia, North Korea, Iran
        }
        
        # Suspicious hosting providers (patterns)
        self.suspicious_provider_patterns = [
            'bulletproof', 'offshore', 'anonymous', 'privacy'
        ]
        
        # High-risk ASN ranges (known for malicious activity)
        self.high_risk_asns = set()  # Would be populated from threat intel
        
        logger.debug("Infrastructure risk analyzer initialized")
    
    def analyze_infrastructure_risk(self, 
                                  indicator_value: str,
                                  indicator_type: str,
                                  infra_data: Dict[str, Any]) -> InfrastructureRisk:
        """Analyze risk for an infrastructure indicator."""
        
        profile = InfrastructureRisk(
            indicator_value=indicator_value,
            indicator_type=indicator_type
        )
        
        # Extract infrastructure details
        profile.hosting_provider = infra_data.get('hosting_provider')
        profile.asn = infra_data.get('asn')
        profile.country = infra_data.get('country')
        
        # Extract reputation data
        profile.reputation_sources = infra_data.get('reputation_sources', {})
        profile.blocklist_appearances = infra_data.get('blocklist_appearances', 0)
        profile.historical_malicious_activity = infra_data.get('historical_malicious_activity', False)
        
        # Extract usage patterns
        profile.c2_usage = infra_data.get('c2_usage', False)
        profile.malware_hosting = infra_data.get('malware_hosting', False)
        profile.phishing_hosting = infra_data.get('phishing_hosting', False)
        profile.scanning_source = infra_data.get('scanning_source', False)
        
        # Extract temporal data
        if infra_data.get('first_seen_malicious'):
            try:
                profile.first_seen_malicious = datetime.fromisoformat(
                    infra_data['first_seen_malicious'].replace('Z', '+00:00')
                )
            except:
                pass
        
        if infra_data.get('last_seen_malicious'):
            try:
                profile.last_seen_malicious = datetime.fromisoformat(
                    infra_data['last_seen_malicious'].replace('Z', '+00:00')
                )
            except:
                pass
        
        # Calculate risk score
        profile.risk_score, profile.risk_factors = self._calculate_infrastructure_risk_score(profile)
        profile.risk_level = self._determine_risk_level(profile.risk_score)
        
        return profile
    
    def _calculate_infrastructure_risk_score(self, profile: InfrastructureRisk) -> Tuple[float, List[str]]:
        """Calculate risk score for infrastructure."""
        
        risk_factors = []
        risk_components = []
        
        # Reputation scoring (40% weight)
        reputation_score = self._calculate_reputation_score(profile, risk_factors)
        risk_components.append(reputation_score * 0.4)
        
        # Usage pattern scoring (30% weight)
        usage_score = 0.0
        
        if profile.c2_usage:
            usage_score += 0.4
            risk_factors.append("c2_infrastructure")
        
        if profile.malware_hosting:
            usage_score += 0.3
            risk_factors.append("malware_hosting")
        
        if profile.phishing_hosting:
            usage_score += 0.25
            risk_factors.append("phishing_hosting")
        
        if profile.scanning_source:
            usage_score += 0.15
            risk_factors.append("scanning_activity")
        
        risk_components.append(min(usage_score, 1.0) * 0.3)
        
        # Geographic risk (15% weight)
        geo_score = 0.0
        
        if profile.country in self.high_risk_countries:
            geo_score = 0.6
            risk_factors.append(f"high_risk_country_{profile.country}")
        
        risk_components.append(geo_score * 0.15)
        
        # Hosting provider risk (10% weight)
        provider_score = 0.0
        
        if profile.hosting_provider:
            provider_lower = profile.hosting_provider.lower()
            if any(pattern in provider_lower for pattern in self.suspicious_provider_patterns):
                provider_score = 0.7
                risk_factors.append("suspicious_hosting_provider")
        
        risk_components.append(provider_score * 0.1)
        
        # Historical activity (5% weight)
        history_score = 0.0
        
        if profile.historical_malicious_activity:
            history_score = 0.8
            risk_factors.append("historical_malicious_activity")
        
        if profile.blocklist_appearances > 0:
            blocklist_score = min(profile.blocklist_appearances * 0.1, 0.6)
            history_score = max(history_score, blocklist_score)
            risk_factors.append(f"blocklist_appearances_{profile.blocklist_appearances}")
        
        risk_components.append(history_score * 0.05)
        
        # Calculate final score
        final_score = sum(risk_components)
        
        # Ensure score is in valid range
        final_score = max(0.0, min(1.0, final_score))
        
        return final_score, risk_factors
    
    def _calculate_reputation_score(self, profile: InfrastructureRisk, risk_factors: List[str]) -> float:
        """Calculate reputation-based risk score."""
        
        if not profile.reputation_sources:
            return 0.3  # Default for unknown reputation
        
        # Aggregate reputation scores from multiple sources
        reputation_scores = []
        
        for source, score in profile.reputation_sources.items():
            # Normalize different reputation scales to 0-1 (higher = more malicious)
            if isinstance(score, (int, float)):
                if score <= -80:  # Very negative (malicious)
                    normalized_score = 1.0
                elif score <= -50:
                    normalized_score = 0.8
                elif score <= -20:
                    normalized_score = 0.6
                elif score <= 0:
                    normalized_score = 0.4
                else:  # Positive (benign)
                    normalized_score = 0.2
                
                reputation_scores.append(normalized_score)
                risk_factors.append(f"reputation_{source}_{score}_{normalized_score:.2f}")
        
        if reputation_scores:
            # Use weighted average with emphasis on most malicious scores
            reputation_scores.sort(reverse=True)
            
            if len(reputation_scores) == 1:
                return reputation_scores[0]
            else:
                # Weight most malicious score more heavily
                weights = [0.6, 0.3, 0.1][:len(reputation_scores)]
                weights.extend([0.05] * (len(reputation_scores) - len(weights)))
                
                weighted_sum = sum(score * weight for score, weight in zip(reputation_scores, weights))
                weight_sum = sum(weights[:len(reputation_scores)])
                
                return weighted_sum / weight_sum
        
        return 0.3  # Default
    
    def _determine_risk_level(self, risk_score: float) -> RiskLevel:
        """Determine risk level from score."""
        
        if risk_score >= 0.9:
            return RiskLevel.CRITICAL
        elif risk_score >= 0.7:
            return RiskLevel.HIGH
        elif risk_score >= 0.4:
            return RiskLevel.MEDIUM
        elif risk_score >= 0.1:
            return RiskLevel.LOW
        else:
            return RiskLevel.MINIMAL


class RiskAssessmentOrchestrator:
    """Orchestrates comprehensive risk assessment across all domains."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize risk assessment orchestrator."""
        self.config = config or {}
        
        # Initialize analyzers
        self.cve_analyzer = CVERiskAnalyzer(self.config.get('cve_analysis', {}))
        self.malware_analyzer = MalwareRiskAnalyzer(self.config.get('malware_analysis', {}))
        self.infrastructure_analyzer = InfrastructureRiskAnalyzer(self.config.get('infrastructure_analysis', {}))
        
        logger.info("Risk assessment orchestrator initialized")
    
    def assess_indicator_risk(self, indicator: NormalizedIndicator) -> Dict[str, Any]:
        """Perform comprehensive risk assessment for an indicator."""
        
        assessment = {
            'indicator_id': indicator.id,
            'indicator_value': indicator.value,
            'indicator_type': indicator.type,
            'risk_profiles': {},
            'overall_risk': {
                'score': 0.0,
                'level': RiskLevel.MINIMAL.value,
                'primary_factors': []
            },
            'assessment_timestamp': datetime.utcnow().isoformat()
        }
        
        risk_scores = []
        primary_factors = []
        
        try:
            # CVE risk assessment
            cve_data = indicator.properties.get('cve_data', {})
            if cve_data:
                for cve_id, cve_info in cve_data.items():
                    cve_profile = self.cve_analyzer.analyze_cve_risk(cve_id, cve_info)
                    assessment['risk_profiles'][f'cve_{cve_id}'] = cve_profile.to_dict()
                    risk_scores.append(cve_profile.risk_score)
                    if cve_profile.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
                        primary_factors.extend(cve_profile.risk_factors[:2])
            
            # Malware risk assessment
            malware_families = indicator.properties.get('malware_families', [])
            malware_data = indicator.properties.get('malware_data', {})
            
            for family in malware_families:
                if family in malware_data:
                    malware_profile = self.malware_analyzer.analyze_malware_risk(family, malware_data[family])
                    assessment['risk_profiles'][f'malware_{family}'] = malware_profile.to_dict()
                    risk_scores.append(malware_profile.risk_score)
                    if malware_profile.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
                        primary_factors.extend(malware_profile.risk_factors[:2])
            
            # Infrastructure risk assessment
            infra_data = {
                'hosting_provider': indicator.properties.get('hosting_provider'),
                'asn': indicator.properties.get('asn'),
                'country': indicator.properties.get('country'),
                'reputation_sources': indicator.properties.get('reputation_sources', {}),
                'blocklist_appearances': indicator.properties.get('blocklist_appearances', 0),
                'historical_malicious_activity': indicator.properties.get('historical_malicious_activity', False),
                'c2_usage': any('c2' in tag.lower() for tag in indicator.properties.get('tags', [])),
                'malware_hosting': any('malware' in tag.lower() for tag in indicator.properties.get('tags', [])),
                'phishing_hosting': any('phish' in tag.lower() for tag in indicator.properties.get('tags', [])),
                'scanning_source': any('scan' in tag.lower() for tag in indicator.properties.get('tags', []))
            }
            
            infra_profile = self.infrastructure_analyzer.analyze_infrastructure_risk(
                indicator.value, indicator.type, infra_data
            )
            assessment['risk_profiles']['infrastructure'] = infra_profile.to_dict()
            risk_scores.append(infra_profile.risk_score)
            if infra_profile.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
                primary_factors.extend(infra_profile.risk_factors[:2])
            
            # Calculate overall risk
            if risk_scores:
                # Use maximum risk as overall score (pessimistic approach)
                overall_score = max(risk_scores)
                assessment['overall_risk']['score'] = overall_score
                assessment['overall_risk']['level'] = self._determine_overall_risk_level(overall_score).value
                assessment['overall_risk']['primary_factors'] = list(set(primary_factors))[:5]  # Top 5 unique factors
            
        except Exception as e:
            logger.error(f"Risk assessment failed for indicator {indicator.id}: {e}", exc_info=True)
            assessment['error'] = str(e)
        
        return assessment
    
    def batch_assess_risks(self, indicators: List[NormalizedIndicator]) -> List[Dict[str, Any]]:
        """Perform risk assessment for multiple indicators."""
        
        logger.info(f"Batch risk assessment for {len(indicators)} indicators")
        
        assessments = []
        
        for i, indicator in enumerate(indicators):
            try:
                assessment = self.assess_indicator_risk(indicator)
                assessments.append(assessment)
                
                # Log progress for large batches
                if (i + 1) % 50 == 0:
                    logger.debug(f"Assessed {i + 1}/{len(indicators)} indicators")
                    
            except Exception as e:
                logger.error(f"Failed to assess indicator {indicator.id}: {e}")
                # Create minimal error assessment
                error_assessment = {
                    'indicator_id': indicator.id,
                    'indicator_value': indicator.value,
                    'indicator_type': indicator.type,
                    'error': str(e),
                    'overall_risk': {
                        'score': 0.0,
                        'level': RiskLevel.MINIMAL.value,
                        'primary_factors': ['assessment_error']
                    },
                    'assessment_timestamp': datetime.utcnow().isoformat()
                }
                assessments.append(error_assessment)
        
        logger.info(f"Risk assessment completed for {len(assessments)} indicators")
        return assessments
    
    def _determine_overall_risk_level(self, risk_score: float) -> RiskLevel:
        """Determine overall risk level from score."""
        
        if risk_score >= 0.9:
            return RiskLevel.CRITICAL
        elif risk_score >= 0.7:
            return RiskLevel.HIGH
        elif risk_score >= 0.4:
            return RiskLevel.MEDIUM
        elif risk_score >= 0.1:
            return RiskLevel.LOW
        else:
            return RiskLevel.MINIMAL
    
    def get_risk_statistics(self) -> Dict[str, Any]:
        """Get risk assessment system statistics."""
        
        return {
            'analyzers': {
                'cve_analyzer': bool(self.cve_analyzer),
                'malware_analyzer': bool(self.malware_analyzer),
                'infrastructure_analyzer': bool(self.infrastructure_analyzer)
            },
            'configuration': self.config
        }