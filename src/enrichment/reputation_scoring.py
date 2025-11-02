"""
Reputation scoring engine for threat intelligence indicators.

This module provides comprehensive reputation scoring by aggregating
information from multiple sources and calculating composite scores.
"""

import logging
import statistics
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum
from dataclasses import dataclass

logger = logging.getLogger(__name__)


class ReputationCategory(Enum):
    """Reputation categories for indicators."""
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious" 
    NEUTRAL = "neutral"
    TRUSTED = "trusted"
    UNKNOWN = "unknown"


class ReputationSource(Enum):
    """Sources of reputation information."""
    GEOLOCATION = "geolocation"
    DNS = "dns"
    ASN = "asn"
    BLOCKLIST = "blocklist"
    BEHAVIORAL = "behavioral"
    COMMUNITY = "community"
    HISTORICAL = "historical"
    THREAT_INTEL = "threat_intel"


@dataclass
class ReputationFactor:
    """Individual reputation factor contribution."""
    source: ReputationSource
    factor_name: str
    score: float  # -100 to +100 (negative = bad, positive = good)
    weight: float  # 0.0 to 1.0 importance weight
    description: str
    confidence: float = 1.0  # 0.0 to 1.0 confidence in this factor
    
    def weighted_score(self) -> float:
        """Calculate weighted score contribution."""
        return (self.score * self.weight * self.confidence)


class ReputationResult:
    """Result object for reputation scoring."""
    
    def __init__(self, indicator_value: str, indicator_type: str):
        self.indicator_value = indicator_value
        self.indicator_type = indicator_type
        self.success = False
        
        # Core reputation metrics
        self.reputation_score = 0.0  # -100 to +100
        self.confidence_score = 0.0  # 0 to 100
        self.category = ReputationCategory.UNKNOWN
        
        # Risk assessment
        self.risk_level = "unknown"  # low, medium, high, critical
        self.threat_types = []
        
        # Factor breakdown
        self.reputation_factors = []
        self.positive_factors = []
        self.negative_factors = []
        
        # Source information
        self.sources_consulted = []
        self.sources_successful = []
        
        # Metadata
        self.calculation_method = None
        self.timestamp = datetime.utcnow()
        self.error = None
    
    def add_factor(self, factor: ReputationFactor):
        """Add a reputation factor to the calculation."""
        self.reputation_factors.append(factor)
        
        if factor.score > 0:
            self.positive_factors.append(factor)
        elif factor.score < 0:
            self.negative_factors.append(factor)
    
    def calculate_final_score(self):
        """Calculate final reputation score from all factors."""
        if not self.reputation_factors:
            self.reputation_score = 0.0
            self.confidence_score = 0.0
            return
        
        # Calculate weighted average of all factors
        total_weighted_score = 0.0
        total_weight = 0.0
        
        for factor in self.reputation_factors:
            weighted_contribution = factor.weighted_score()
            total_weighted_score += weighted_contribution
            total_weight += factor.weight * factor.confidence
        
        # Normalize score
        if total_weight > 0:
            self.reputation_score = max(-100, min(100, total_weighted_score / total_weight * 100))
        else:
            self.reputation_score = 0.0
        
        # Calculate confidence based on source diversity and factor confidence
        source_diversity = len(set(f.source for f in self.reputation_factors))
        avg_confidence = statistics.mean(f.confidence for f in self.reputation_factors)
        factor_count = len(self.reputation_factors)
        
        # Confidence increases with more diverse sources and factors
        self.confidence_score = min(100, avg_confidence * 70 + source_diversity * 10 + min(factor_count * 5, 20))
        
        # Determine category based on score
        self._categorize_reputation()
        
        # Set risk level
        self._assess_risk_level()
        
        self.success = True
    
    def _categorize_reputation(self):
        """Categorize reputation based on numeric score."""
        if self.reputation_score >= 60:
            self.category = ReputationCategory.TRUSTED
        elif self.reputation_score >= 20:
            self.category = ReputationCategory.NEUTRAL
        elif self.reputation_score >= -20:
            self.category = ReputationCategory.SUSPICIOUS
        else:
            self.category = ReputationCategory.MALICIOUS
    
    def _assess_risk_level(self):
        """Assess risk level based on reputation score and negative factors."""
        critical_factors = [f for f in self.negative_factors if f.score <= -80]
        high_risk_factors = [f for f in self.negative_factors if -80 < f.score <= -50]
        
        if critical_factors or self.reputation_score <= -70:
            self.risk_level = "critical"
        elif high_risk_factors or self.reputation_score <= -40:
            self.risk_level = "high"
        elif self.reputation_score <= -10:
            self.risk_level = "medium"
        else:
            self.risk_level = "low"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            'indicator_value': self.indicator_value,
            'indicator_type': self.indicator_type,
            'success': self.success,
            'reputation_score': round(self.reputation_score, 2),
            'confidence_score': round(self.confidence_score, 2),
            'category': self.category.value,
            'risk_level': self.risk_level,
            'threat_types': self.threat_types,
            'reputation_factors': [
                {
                    'source': f.source.value,
                    'factor_name': f.factor_name,
                    'score': f.score,
                    'weight': f.weight,
                    'description': f.description,
                    'confidence': f.confidence,
                    'weighted_contribution': f.weighted_score()
                }
                for f in self.reputation_factors
            ],
            'sources_consulted': list(self.sources_consulted),
            'sources_successful': list(self.sources_successful),
            'calculation_method': self.calculation_method,
            'timestamp': self.timestamp.isoformat(),
            'error': self.error
        }


class GeolocationReputationScorer:
    """Reputation scoring based on geolocation data."""
    
    def __init__(self):
        # Country risk scores (based on common threat intelligence patterns)
        self.country_risk_scores = {
            # High-risk countries (common C2 locations)
            'CN': -30, 'RU': -25, 'KP': -40, 'IR': -35,
            
            # Medium-high risk
            'UA': -15, 'RO': -10, 'BG': -10, 'VN': -15,
            
            # Medium risk
            'BR': -5, 'IN': -5, 'ID': -5, 'TR': -5,
            
            # Low-medium risk
            'PL': 0, 'CZ': 0, 'HU': 0, 'GR': 0,
            
            # Trusted countries
            'US': 20, 'CA': 20, 'GB': 15, 'DE': 15, 'FR': 15,
            'AU': 15, 'JP': 15, 'NL': 15, 'SE': 15, 'CH': 20,
            'NO': 15, 'DK': 15, 'FI': 15, 'SG': 10, 'KR': 10
        }
    
    def score_geolocation(self, geo_data: Dict[str, Any]) -> List[ReputationFactor]:
        """Score reputation based on geolocation data."""
        factors = []
        
        if not geo_data.get('success'):
            return factors
        
        # Country-based scoring
        country_code = geo_data.get('country_code')
        if country_code:
            country_score = self.country_risk_scores.get(country_code, 0)
            
            factors.append(ReputationFactor(
                source=ReputationSource.GEOLOCATION,
                factor_name="country_reputation",
                score=country_score,
                weight=0.3,
                description=f"Country reputation for {country_code}",
                confidence=0.8
            ))
        
        # Anonymous proxy detection
        if geo_data.get('is_anonymous_proxy'):
            factors.append(ReputationFactor(
                source=ReputationSource.GEOLOCATION,
                factor_name="anonymous_proxy",
                score=-50,
                weight=0.6,
                description="IP is an anonymous proxy",
                confidence=0.9
            ))
        
        # Satellite provider (often used for obfuscation)
        if geo_data.get('is_satellite_provider'):
            factors.append(ReputationFactor(
                source=ReputationSource.GEOLOCATION,
                factor_name="satellite_provider",
                score=-20,
                weight=0.3,
                description="IP uses satellite internet provider",
                confidence=0.7
            ))
        
        return factors


class DNSReputationScorer:
    """Reputation scoring based on DNS data."""
    
    def score_dns(self, dns_data: Dict[str, Any]) -> List[ReputationFactor]:
        """Score reputation based on DNS data."""
        factors = []
        
        # Domain reputation
        reputation_data = dns_data.get('reputation')
        if reputation_data and reputation_data.get('success'):
            rep_score = reputation_data.get('reputation_score', 50)
            
            # Convert 0-100 scale to -100 to +100 scale
            normalized_score = (rep_score - 50) * 2
            
            factors.append(ReputationFactor(
                source=ReputationSource.DNS,
                factor_name="domain_reputation",
                score=normalized_score,
                weight=0.5,
                description=f"Domain reputation score: {rep_score}/100",
                confidence=0.8
            ))
            
            # Malicious/suspicious flags
            if reputation_data.get('is_malicious'):
                factors.append(ReputationFactor(
                    source=ReputationSource.DNS,
                    factor_name="malicious_domain",
                    score=-90,
                    weight=0.8,
                    description="Domain flagged as malicious",
                    confidence=0.9
                ))
            
            elif reputation_data.get('is_suspicious'):
                factors.append(ReputationFactor(
                    source=ReputationSource.DNS,
                    factor_name="suspicious_domain",
                    score=-40,
                    weight=0.6,
                    description="Domain flagged as suspicious",
                    confidence=0.7
                ))
        
        # Blocklist matches
        blocklist_matches = dns_data.get('blocklist_matches', [])
        if blocklist_matches:
            # Score based on number of blocklist hits
            blocklist_score = -20 * min(len(blocklist_matches), 4)  # Cap at -80
            
            factors.append(ReputationFactor(
                source=ReputationSource.BLOCKLIST,
                factor_name="blocklist_matches",
                score=blocklist_score,
                weight=0.7,
                description=f"Found on {len(blocklist_matches)} blocklists",
                confidence=0.8
            ))
        
        # DNS resolution success (lack of DNS can be suspicious for domains)
        if not dns_data.get('dns_success') and dns_data.get('domain'):
            factors.append(ReputationFactor(
                source=ReputationSource.DNS,
                factor_name="no_dns_records",
                score=-15,
                weight=0.3,
                description="Domain has no DNS records",
                confidence=0.6
            ))
        
        return factors


class ASNReputationScorer:
    """Reputation scoring based on ASN data."""
    
    def __init__(self):
        # ASN categories with reputation modifiers
        self.asn_categories = {
            'cloud_provider': 10,  # Generally more trusted
            'cdn': 15,             # CDNs are usually legitimate
            'hosting': -10,        # Hosting can be abused
            'isp': 5,             # Neutral to slightly positive
            'other': 0            # Neutral
        }
    
    def score_asn(self, asn_data: Dict[str, Any]) -> List[ReputationFactor]:
        """Score reputation based on ASN data."""
        factors = []
        
        if not asn_data.get('asn_lookup_success'):
            return factors
        
        # Network category scoring
        network_category = asn_data.get('network_category')
        if network_category and network_category in self.asn_categories:
            category_score = self.asn_categories[network_category]
            
            factors.append(ReputationFactor(
                source=ReputationSource.ASN,
                factor_name="network_category",
                score=category_score,
                weight=0.3,
                description=f"Network category: {network_category}",
                confidence=0.7
            ))
        
        # Known good ASNs (major cloud providers, CDNs)
        asn_org = asn_data.get('network_owner', '').lower()
        if asn_org:
            trusted_orgs = [
                'google', 'amazon', 'microsoft', 'cloudflare', 
                'akamai', 'fastly', 'apple', 'facebook'
            ]
            
            if any(org in asn_org for org in trusted_orgs):
                factors.append(ReputationFactor(
                    source=ReputationSource.ASN,
                    factor_name="trusted_asn_org",
                    score=25,
                    weight=0.4,
                    description=f"Trusted ASN organization: {asn_org}",
                    confidence=0.8
                ))
        
        return factors


class ReputationScoringEngine:
    """Main reputation scoring engine."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize reputation scoring engine.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        
        # Initialize component scorers
        self.geo_scorer = GeolocationReputationScorer()
        self.dns_scorer = DNSReputationScorer()
        self.asn_scorer = ASNReputationScorer()
        
        logger.info("Reputation scoring engine initialized")
    
    def score_indicator(self, indicator_value: str, indicator_type: str, 
                       enrichment_data: Dict[str, Any]) -> ReputationResult:
        """
        Calculate comprehensive reputation score for an indicator.
        
        Args:
            indicator_value: The indicator value (IP, domain, etc.)
            indicator_type: Type of indicator
            enrichment_data: Dictionary containing enrichment results
            
        Returns:
            ReputationResult object
        """
        result = ReputationResult(indicator_value, indicator_type)
        result.calculation_method = "weighted_factor_aggregation"
        
        try:
            # Collect reputation factors from all sources
            all_factors = []
            
            # Geolocation-based factors
            geo_data = enrichment_data.get('geolocation')
            if geo_data:
                geo_factors = self.geo_scorer.score_geolocation(geo_data)
                all_factors.extend(geo_factors)
                result.sources_consulted.append('geolocation')
                if geo_factors:
                    result.sources_successful.append('geolocation')
            
            # DNS-based factors
            dns_data = enrichment_data.get('dns')
            if dns_data:
                dns_factors = self.dns_scorer.score_dns(dns_data)
                all_factors.extend(dns_factors)
                result.sources_consulted.append('dns')
                if dns_factors:
                    result.sources_successful.append('dns')
            
            # ASN-based factors
            asn_data = enrichment_data.get('asn')
            if asn_data:
                asn_factors = self.asn_scorer.score_asn(asn_data)
                all_factors.extend(asn_factors)
                result.sources_consulted.append('asn')
                if asn_factors:
                    result.sources_successful.append('asn')
            
            # Add all factors to result
            for factor in all_factors:
                result.add_factor(factor)
            
            # Calculate final score
            result.calculate_final_score()
            
            logger.debug(f"Reputation scored for {indicator_value}: {result.reputation_score}")
            
        except Exception as e:
            result.error = f"Reputation scoring error: {e}"
            logger.error(f"Reputation scoring error for {indicator_value}: {e}")
        
        return result
    
    def score_batch(self, indicators: List[Dict[str, Any]]) -> Dict[str, ReputationResult]:
        """
        Score reputation for multiple indicators.
        
        Args:
            indicators: List of indicator dictionaries with enrichment data
            
        Returns:
            Dictionary mapping indicator values to ReputationResult objects
        """
        results = {}
        
        for indicator_data in indicators:
            try:
                indicator_value = indicator_data.get('value', '')
                indicator_type = indicator_data.get('type', '')
                enrichment_data = indicator_data.get('enrichment', {})
                
                if indicator_value:
                    result = self.score_indicator(indicator_value, indicator_type, enrichment_data)
                    results[indicator_value] = result
                    
            except Exception as e:
                result = ReputationResult(
                    indicator_data.get('value', 'unknown'), 
                    indicator_data.get('type', 'unknown')
                )
                result.error = str(e)
                results[indicator_data.get('value', 'unknown')] = result
                logger.error(f"Batch reputation scoring error: {e}")
        
        return results
    
    def get_reputation_summary(self, results: Dict[str, ReputationResult]) -> Dict[str, Any]:
        """
        Generate summary statistics for a batch of reputation results.
        
        Args:
            results: Dictionary of reputation results
            
        Returns:
            Summary statistics dictionary
        """
        if not results:
            return {'total_indicators': 0}
        
        successful_results = [r for r in results.values() if r.success]
        
        if not successful_results:
            return {
                'total_indicators': len(results),
                'successful_scores': 0,
                'average_score': 0,
                'category_distribution': {}
            }
        
        # Calculate statistics
        scores = [r.reputation_score for r in successful_results]
        categories = [r.category.value for r in successful_results]
        risk_levels = [r.risk_level for r in successful_results]
        
        # Category distribution
        category_dist = {}
        for category in categories:
            category_dist[category] = category_dist.get(category, 0) + 1
        
        # Risk level distribution
        risk_dist = {}
        for risk in risk_levels:
            risk_dist[risk] = risk_dist.get(risk, 0) + 1
        
        return {
            'total_indicators': len(results),
            'successful_scores': len(successful_results),
            'average_score': round(statistics.mean(scores), 2),
            'median_score': round(statistics.median(scores), 2),
            'min_score': round(min(scores), 2),
            'max_score': round(max(scores), 2),
            'category_distribution': category_dist,
            'risk_level_distribution': risk_dist,
            'high_risk_count': sum(1 for r in successful_results if r.risk_level in ['high', 'critical']),
            'malicious_count': sum(1 for r in successful_results if r.category == ReputationCategory.MALICIOUS)
        }