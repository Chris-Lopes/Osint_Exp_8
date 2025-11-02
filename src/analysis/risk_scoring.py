"""
Risk scoring framework for threat intelligence analysis.

This module implements composite risk scoring that combines reputation,
correlation strength, temporal factors, and cluster analysis to provide
comprehensive threat assessment scores.
"""

import logging
import math
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass
from enum import Enum
from collections import defaultdict, Counter

try:
    from ..normalizers.schema import NormalizedIndicator, IndicatorType
    from .correlation import CorrelationResult, CorrelationType, CorrelationStrength
    from .clustering import IndicatorCluster, ClusterType, ClusterQuality
except ImportError:
    from normalizers.schema import NormalizedIndicator, IndicatorType
    from analysis.correlation import CorrelationResult, CorrelationType, CorrelationStrength
    from analysis.clustering import IndicatorCluster, ClusterType, ClusterQuality

logger = logging.getLogger(__name__)


class RiskLevel(Enum):
    """Risk levels for threat indicators."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class ThreatCategory(Enum):
    """Categories of threats."""
    MALWARE = "malware"
    PHISHING = "phishing"
    C2_INFRASTRUCTURE = "c2_infrastructure"
    BOTNET = "botnet"
    APT_ACTIVITY = "apt_activity"
    SCANNING = "scanning"
    EXPLOITATION = "exploitation"
    DATA_EXFILTRATION = "data_exfiltration"
    UNKNOWN = "unknown"


@dataclass
class RiskFactor:
    """Individual risk factor component."""
    name: str
    score: float  # 0.0 to 1.0
    weight: float  # Importance weight
    confidence: float  # Confidence in this factor
    evidence: Dict[str, Any]
    
    def weighted_score(self) -> float:
        """Get weighted score."""
        return self.score * self.weight * self.confidence


@dataclass
class RiskAssessment:
    """Comprehensive risk assessment for an indicator."""
    indicator_id: str
    risk_score: float  # 0.0 to 1.0
    risk_level: RiskLevel
    threat_category: ThreatCategory
    confidence: float
    
    # Risk factor breakdown
    risk_factors: List[RiskFactor]
    
    # Context information
    assessment_timestamp: datetime
    cluster_memberships: List[str]  # Cluster IDs this indicator belongs to
    correlation_count: int
    temporal_context: Dict[str, Any]
    
    # Recommendations
    priority_score: int  # 1-100
    recommended_actions: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            'indicator_id': self.indicator_id,
            'risk_score': self.risk_score,
            'risk_level': self.risk_level.value,
            'threat_category': self.threat_category.value,
            'confidence': self.confidence,
            'risk_factors': [
                {
                    'name': rf.name,
                    'score': rf.score,
                    'weight': rf.weight,
                    'confidence': rf.confidence,
                    'weighted_score': rf.weighted_score(),
                    'evidence': rf.evidence
                }
                for rf in self.risk_factors
            ],
            'assessment_timestamp': self.assessment_timestamp.isoformat(),
            'cluster_memberships': self.cluster_memberships,
            'correlation_count': self.correlation_count,
            'temporal_context': self.temporal_context,
            'priority_score': self.priority_score,
            'recommended_actions': self.recommended_actions
        }


class BaseRiskScorer:
    """Base class for risk scoring components."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize base scorer."""
        self.config = config or {}
        self.weight = self.config.get('weight', 1.0)
    
    def calculate_risk_factors(self, indicator: NormalizedIndicator,
                             context: Dict[str, Any]) -> List[RiskFactor]:
        """Calculate risk factors for this scorer."""
        raise NotImplementedError


class ReputationRiskScorer(BaseRiskScorer):
    """Risk scoring based on reputation data."""
    
    def calculate_risk_factors(self, indicator: NormalizedIndicator,
                             context: Dict[str, Any]) -> List[RiskFactor]:
        """Calculate reputation-based risk factors."""
        factors = []
        
        # Get reputation data from enrichment
        enrichment = indicator.context.get('enrichment', {})
        reputation_data = enrichment.get('reputation', {})
        
        if not reputation_data or not reputation_data.get('success'):
            # No reputation data - neutral risk
            factors.append(RiskFactor(
                name="reputation_unknown",
                score=0.3,
                weight=0.5,
                confidence=0.4,
                evidence={'reason': 'no_reputation_data_available'}
            ))
            return factors
        
        rep_score = reputation_data.get('reputation_score', 0)
        category = reputation_data.get('category', 'unknown')
        
        # Convert reputation score to risk score
        if rep_score <= -80:
            risk_score = 0.95
            risk_confidence = 0.9
        elif rep_score <= -50:
            risk_score = 0.8
            risk_confidence = 0.8
        elif rep_score <= -20:
            risk_score = 0.6
            risk_confidence = 0.7
        elif rep_score < 0:
            risk_score = 0.4
            risk_confidence = 0.6
        else:
            risk_score = 0.2
            risk_confidence = 0.5
        
        factors.append(RiskFactor(
            name="reputation_score",
            score=risk_score,
            weight=self.weight,
            confidence=risk_confidence,
            evidence={
                'reputation_score': rep_score,
                'category': category,
                'is_malicious': reputation_data.get('is_malicious', False),
                'is_suspicious': reputation_data.get('is_suspicious', False)
            }
        ))
        
        # Specific threat indicators
        if reputation_data.get('is_malicious'):
            factors.append(RiskFactor(
                name="malicious_indicator",
                score=0.9,
                weight=1.2,
                confidence=0.85,
                evidence={'malicious_classification': True}
            ))
        
        if reputation_data.get('is_phishing'):
            factors.append(RiskFactor(
                name="phishing_indicator",
                score=0.85,
                weight=1.1,
                confidence=0.8,
                evidence={'phishing_classification': True}
            ))
        
        # Blocklist matches
        blocklist_matches = reputation_data.get('blocklist_matches', [])
        if blocklist_matches:
            factors.append(RiskFactor(
                name="blocklist_presence",
                score=0.8,
                weight=1.0,
                confidence=0.9,
                evidence={
                    'blocklist_count': len(blocklist_matches),
                    'blocklists': blocklist_matches[:5]  # Limit for readability
                }
            ))
        
        return factors


class CorrelationRiskScorer(BaseRiskScorer):
    """Risk scoring based on correlation analysis."""
    
    def calculate_risk_factors(self, indicator: NormalizedIndicator,
                             context: Dict[str, Any]) -> List[RiskFactor]:
        """Calculate correlation-based risk factors."""
        factors = []
        correlations = context.get('correlations', [])
        
        if not correlations:
            return factors
        
        # Analyze correlation patterns
        correlation_scores = [c.score for c in correlations]
        correlation_types = [c.correlation_type for c in correlations]
        correlation_strengths = [c.strength for c in correlations]
        
        # High correlation count increases risk
        correlation_count = len(correlations)
        if correlation_count >= 10:
            count_risk = 0.8
        elif correlation_count >= 5:
            count_risk = 0.6
        elif correlation_count >= 2:
            count_risk = 0.4
        else:
            count_risk = 0.2
        
        factors.append(RiskFactor(
            name="correlation_count",
            score=count_risk,
            weight=0.7,
            confidence=0.8,
            evidence={
                'correlation_count': correlation_count,
                'avg_correlation_score': sum(correlation_scores) / len(correlation_scores)
            }
        ))
        
        # Strong correlations increase risk
        strong_correlations = [c for c in correlations 
                             if c.strength in {CorrelationStrength.STRONG, CorrelationStrength.VERY_STRONG}]
        
        if strong_correlations:
            strong_ratio = len(strong_correlations) / len(correlations)
            factors.append(RiskFactor(
                name="strong_correlations",
                score=min(strong_ratio * 0.8, 0.8),
                weight=0.9,
                confidence=0.85,
                evidence={
                    'strong_correlation_count': len(strong_correlations),
                    'strong_correlation_ratio': strong_ratio
                }
            ))
        
        # Network correlations (infrastructure connections)
        network_correlations = [c for c in correlations if c.correlation_type == CorrelationType.NETWORK]
        if network_correlations:
            network_risk = min(len(network_correlations) * 0.15, 0.7)
            factors.append(RiskFactor(
                name="network_correlations",
                score=network_risk,
                weight=0.8,
                confidence=0.75,
                evidence={
                    'network_correlation_count': len(network_correlations),
                    'infrastructure_connections': True
                }
            ))
        
        return factors


class TemporalRiskScorer(BaseRiskScorer):
    """Risk scoring based on temporal patterns."""
    
    def calculate_risk_factors(self, indicator: NormalizedIndicator,
                             context: Dict[str, Any]) -> List[RiskFactor]:
        """Calculate temporal-based risk factors."""
        factors = []
        
        try:
            indicator_time = datetime.fromisoformat(indicator.created.replace('Z', '+00:00'))
            current_time = datetime.utcnow().replace(tzinfo=indicator_time.tzinfo)
            age = current_time - indicator_time
        except:
            return factors
        
        # Recent indicators are higher risk
        if age <= timedelta(hours=1):
            recency_risk = 0.8
            recency_confidence = 0.9
        elif age <= timedelta(hours=6):
            recency_risk = 0.6
            recency_confidence = 0.8
        elif age <= timedelta(days=1):
            recency_risk = 0.4
            recency_confidence = 0.7
        elif age <= timedelta(days=7):
            recency_risk = 0.2
            recency_confidence = 0.6
        else:
            recency_risk = 0.1
            recency_confidence = 0.5
        
        factors.append(RiskFactor(
            name="temporal_recency",
            score=recency_risk,
            weight=0.6,
            confidence=recency_confidence,
            evidence={
                'age_hours': age.total_seconds() / 3600,
                'is_recent': age <= timedelta(days=1)
            }
        ))
        
        # Temporal clustering (burst activity)
        clusters = context.get('clusters', [])
        temporal_clusters = [c for c in clusters if c.cluster_type == ClusterType.TEMPORAL_BURST]
        
        if temporal_clusters:
            # High burst activity increases risk
            burst_intensity = max(
                c.cluster_features.get('burst_intensity_per_hour', 0)
                for c in temporal_clusters
            )
            
            if burst_intensity >= 10:
                burst_risk = 0.9
            elif burst_intensity >= 5:
                burst_risk = 0.7
            elif burst_intensity >= 2:
                burst_risk = 0.5
            else:
                burst_risk = 0.3
            
            factors.append(RiskFactor(
                name="temporal_burst_activity",
                score=burst_risk,
                weight=0.8,
                confidence=0.8,
                evidence={
                    'burst_intensity': burst_intensity,
                    'burst_cluster_count': len(temporal_clusters)
                }
            ))
        
        return factors


class ClusterRiskScorer(BaseRiskScorer):
    """Risk scoring based on cluster membership."""
    
    def calculate_risk_factors(self, indicator: NormalizedIndicator,
                             context: Dict[str, Any]) -> List[RiskFactor]:
        """Calculate cluster-based risk factors."""
        factors = []
        clusters = context.get('clusters', [])
        
        if not clusters:
            return factors
        
        # High-quality clusters increase risk
        high_quality_clusters = [c for c in clusters if c.quality == ClusterQuality.HIGH]
        if high_quality_clusters:
            factors.append(RiskFactor(
                name="high_quality_cluster_membership",
                score=0.7,
                weight=1.0,
                confidence=0.85,
                evidence={
                    'high_quality_cluster_count': len(high_quality_clusters),
                    'cluster_types': [c.cluster_type.value for c in high_quality_clusters]
                }
            ))
        
        # Campaign clusters are high risk
        campaign_clusters = [c for c in clusters if c.cluster_type == ClusterType.CAMPAIGN]
        if campaign_clusters:
            factors.append(RiskFactor(
                name="campaign_cluster_membership",
                score=0.8,
                weight=1.1,
                confidence=0.9,
                evidence={
                    'campaign_cluster_count': len(campaign_clusters),
                    'largest_campaign_size': max(len(c.indicator_ids) for c in campaign_clusters)
                }
            ))
        
        # Infrastructure clusters
        infra_clusters = [c for c in clusters if c.cluster_type == ClusterType.INFRASTRUCTURE]
        if infra_clusters:
            factors.append(RiskFactor(
                name="infrastructure_cluster_membership",
                score=0.6,
                weight=0.9,
                confidence=0.8,
                evidence={
                    'infrastructure_cluster_count': len(infra_clusters),
                    'infrastructure_size': sum(len(c.indicator_ids) for c in infra_clusters)
                }
            ))
        
        # Malware family clusters
        malware_clusters = [c for c in clusters if c.cluster_type == ClusterType.MALWARE_FAMILY]
        if malware_clusters:
            factors.append(RiskFactor(
                name="malware_family_cluster_membership",
                score=0.85,
                weight=1.2,
                confidence=0.9,
                evidence={
                    'malware_cluster_count': len(malware_clusters),
                    'malware_family_indicators': sum(len(c.indicator_ids) for c in malware_clusters)
                }
            ))
        
        return factors


class SourceCredibilityScorer(BaseRiskScorer):
    """Risk scoring based on source credibility and confidence."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize source credibility scorer."""
        super().__init__(config)
        
        # Source credibility ratings (can be configured)
        self.source_credibility = self.config.get('source_credibility', {
            'virustotal': 0.9,
            'abuse_ch': 0.85,
            'alienvault_otx': 0.8,
            'urlhaus': 0.8,
            'malware_bazaar': 0.85,
            'phishtank': 0.75,
            'openphish': 0.7,
            'threatfox': 0.8,
            'default': 0.5
        })
    
    def calculate_risk_factors(self, indicator: NormalizedIndicator,
                             context: Dict[str, Any]) -> List[RiskFactor]:
        """Calculate source credibility risk factors."""
        factors = []
        
        # Source credibility
        source_cred = self.source_credibility.get(indicator.source_metadata.source_name, 
                                                 self.source_credibility['default'])
        
        # High credibility sources with low confidence indicators are suspicious
        if source_cred >= 0.8 and indicator.confidence >= 80:
            credibility_risk = 0.7
        elif source_cred >= 0.7 and indicator.confidence >= 70:
            credibility_risk = 0.5
        elif source_cred >= 0.5 and indicator.confidence >= 60:
            credibility_risk = 0.3
        else:
            credibility_risk = 0.2
        
        factors.append(RiskFactor(
            name="source_credibility",
            score=credibility_risk,
            weight=0.7,
            confidence=source_cred,
            evidence={
                'source': indicator.source_metadata.source_name,
                'source_credibility': source_cred,
                'indicator_confidence': indicator.confidence
            }
        ))
        
        return factors


class GeographicRiskScorer(BaseRiskScorer):
    """Risk scoring based on geographic context."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize geographic risk scorer."""
        super().__init__(config)
        
        # High-risk geographic regions (can be configured)
        self.high_risk_countries = set(self.config.get('high_risk_countries', [
            'CN', 'RU', 'KP', 'IR'  # Example high-risk countries
        ]))
        
        self.medium_risk_countries = set(self.config.get('medium_risk_countries', [
            'PK', 'BD', 'VN', 'IN'  # Example medium-risk countries
        ]))
    
    def calculate_risk_factors(self, indicator: NormalizedIndicator,
                             context: Dict[str, Any]) -> List[RiskFactor]:
        """Calculate geographic risk factors."""
        factors = []
        
        # Get geolocation data
        enrichment = indicator.context.get('enrichment', {})
        geo_data = enrichment.get('geolocation', {})
        
        if not geo_data or not geo_data.get('success'):
            return factors
        
        country = geo_data.get('country_code') or geo_data.get('country', '')
        
        if country in self.high_risk_countries:
            geo_risk = 0.8
            risk_level = 'high'
        elif country in self.medium_risk_countries:
            geo_risk = 0.5
            risk_level = 'medium'
        else:
            geo_risk = 0.2
            risk_level = 'low'
        
        factors.append(RiskFactor(
            name="geographic_risk",
            score=geo_risk,
            weight=0.6,
            confidence=0.7,
            evidence={
                'country': geo_data.get('country', 'Unknown'),
                'country_code': country,
                'risk_level': risk_level,
                'city': geo_data.get('city', 'Unknown')
            }
        ))
        
        return factors


class CompositeRiskScorer:
    """Main composite risk scoring engine."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize composite risk scorer."""
        self.config = config or {}
        
        # Initialize component scorers
        self.scorers = {
            'reputation': ReputationRiskScorer(self.config.get('reputation', {})),
            'correlation': CorrelationRiskScorer(self.config.get('correlation', {})),
            'temporal': TemporalRiskScorer(self.config.get('temporal', {})),
            'cluster': ClusterRiskScorer(self.config.get('cluster', {})),
            'source': SourceCredibilityScorer(self.config.get('source', {})),
            'geographic': GeographicRiskScorer(self.config.get('geographic', {}))
        }
        
        # Risk level thresholds
        self.risk_thresholds = {
            RiskLevel.CRITICAL: self.config.get('critical_threshold', 0.8),
            RiskLevel.HIGH: self.config.get('high_threshold', 0.6),
            RiskLevel.MEDIUM: self.config.get('medium_threshold', 0.4),
            RiskLevel.LOW: self.config.get('low_threshold', 0.2)
        }
        
        logger.info("Composite risk scorer initialized")
    
    def assess_risk(self, indicator: NormalizedIndicator,
                   correlations: List[CorrelationResult],
                   clusters: List[IndicatorCluster]) -> RiskAssessment:
        """Perform comprehensive risk assessment."""
        context = {
            'correlations': correlations,
            'clusters': clusters
        }
        
        # Collect all risk factors
        all_risk_factors = []
        
        for scorer_name, scorer in self.scorers.items():
            try:
                factors = scorer.calculate_risk_factors(indicator, context)
                all_risk_factors.extend(factors)
            except Exception as e:
                logger.error(f"Error in {scorer_name} scorer: {e}")
        
        # Calculate composite risk score
        risk_score = self._calculate_composite_score(all_risk_factors)
        
        # Determine risk level
        risk_level = self._determine_risk_level(risk_score)
        
        # Determine threat category
        threat_category = self._determine_threat_category(indicator, all_risk_factors, clusters)
        
        # Calculate overall confidence
        confidence = self._calculate_confidence(all_risk_factors)
        
        # Generate temporal context
        temporal_context = self._generate_temporal_context(indicator, correlations, clusters)
        
        # Calculate priority score
        priority_score = self._calculate_priority_score(risk_score, confidence, len(correlations))
        
        # Generate recommendations
        recommendations = self._generate_recommendations(risk_level, threat_category, all_risk_factors)
        
        return RiskAssessment(
            indicator_id=indicator.id,
            risk_score=risk_score,
            risk_level=risk_level,
            threat_category=threat_category,
            confidence=confidence,
            risk_factors=all_risk_factors,
            assessment_timestamp=datetime.utcnow(),
            cluster_memberships=[c.id for c in clusters],
            correlation_count=len(correlations),
            temporal_context=temporal_context,
            priority_score=priority_score,
            recommended_actions=recommendations
        )
    
    def _calculate_composite_score(self, risk_factors: List[RiskFactor]) -> float:
        """Calculate composite risk score from individual factors."""
        if not risk_factors:
            return 0.0
        
        # Weighted average with confidence adjustment
        total_weighted_score = sum(factor.weighted_score() for factor in risk_factors)
        total_weight = sum(factor.weight * factor.confidence for factor in risk_factors)
        
        if total_weight == 0:
            return 0.0
        
        base_score = total_weighted_score / total_weight
        
        # Apply factor diversity bonus (having multiple types of risk factors)
        factor_types = len(set(factor.name.split('_')[0] for factor in risk_factors))
        diversity_bonus = min(factor_types * 0.05, 0.15)  # Up to 15% bonus
        
        # Apply high-confidence factor bonus
        high_conf_factors = [f for f in risk_factors if f.confidence >= 0.8]
        confidence_bonus = min(len(high_conf_factors) * 0.02, 0.1)  # Up to 10% bonus
        
        composite_score = base_score + diversity_bonus + confidence_bonus
        
        return min(max(composite_score, 0.0), 1.0)
    
    def _determine_risk_level(self, risk_score: float) -> RiskLevel:
        """Determine risk level from composite score."""
        if risk_score >= self.risk_thresholds[RiskLevel.CRITICAL]:
            return RiskLevel.CRITICAL
        elif risk_score >= self.risk_thresholds[RiskLevel.HIGH]:
            return RiskLevel.HIGH
        elif risk_score >= self.risk_thresholds[RiskLevel.MEDIUM]:
            return RiskLevel.MEDIUM
        elif risk_score >= self.risk_thresholds[RiskLevel.LOW]:
            return RiskLevel.LOW
        else:
            return RiskLevel.INFORMATIONAL
    
    def _determine_threat_category(self, indicator: NormalizedIndicator,
                                 risk_factors: List[RiskFactor],
                                 clusters: List[IndicatorCluster]) -> ThreatCategory:
        """Determine threat category based on analysis."""
        # Check for explicit malware indicators
        malware_evidence = [f for f in risk_factors if 'malware' in f.name or f.evidence.get('is_malicious')]
        if malware_evidence:
            return ThreatCategory.MALWARE
        
        # Check for phishing indicators
        phishing_evidence = [f for f in risk_factors if 'phishing' in f.name or f.evidence.get('is_phishing')]
        if phishing_evidence:
            return ThreatCategory.PHISHING
        
        # Check cluster types
        cluster_types = [c.cluster_type for c in clusters]
        
        if ClusterType.MALWARE_FAMILY in cluster_types:
            return ThreatCategory.MALWARE
        elif ClusterType.INFRASTRUCTURE in cluster_types:
            return ThreatCategory.C2_INFRASTRUCTURE
        elif ClusterType.CAMPAIGN in cluster_types:
            return ThreatCategory.APT_ACTIVITY
        
        # Check indicator type patterns
        if indicator.indicator_type in {IndicatorType.MD5, IndicatorType.SHA1, IndicatorType.SHA256}:
            return ThreatCategory.MALWARE
        
        # Network indicators with high correlation could be C2
        network_correlations = sum(1 for f in risk_factors if 'network' in f.name)
        if (indicator.indicator_type in {IndicatorType.IP, IndicatorType.IPV4, IndicatorType.DOMAIN} and
            network_correlations > 0):
            return ThreatCategory.C2_INFRASTRUCTURE
        
        return ThreatCategory.UNKNOWN
    
    def _calculate_confidence(self, risk_factors: List[RiskFactor]) -> float:
        """Calculate overall confidence in the risk assessment."""
        if not risk_factors:
            return 0.3
        
        # Weighted average of individual factor confidences
        weighted_confidence = sum(f.confidence * f.weight for f in risk_factors)
        total_weight = sum(f.weight for f in risk_factors)
        
        base_confidence = weighted_confidence / total_weight if total_weight > 0 else 0.3
        
        # Bonus for multiple independent factors
        factor_count_bonus = min(len(risk_factors) * 0.05, 0.2)
        
        return min(base_confidence + factor_count_bonus, 1.0)
    
    def _generate_temporal_context(self, indicator: NormalizedIndicator,
                                 correlations: List[CorrelationResult],
                                 clusters: List[IndicatorCluster]) -> Dict[str, Any]:
        """Generate temporal context information."""
        context = {}
        
        try:
            indicator_time = datetime.fromisoformat(indicator.created.replace('Z', '+00:00'))
            current_time = datetime.utcnow().replace(tzinfo=indicator_time.tzinfo)
            
            context['indicator_age_hours'] = (current_time - indicator_time).total_seconds() / 3600
            context['is_recent'] = (current_time - indicator_time) <= timedelta(days=1)
        except:
            pass
        
        # Temporal correlation analysis
        temporal_correlations = [c for c in correlations if c.correlation_type == CorrelationType.TEMPORAL]
        if temporal_correlations:
            context['temporal_correlation_count'] = len(temporal_correlations)
            context['avg_temporal_correlation_score'] = sum(c.score for c in temporal_correlations) / len(temporal_correlations)
        
        # Temporal clustering
        temporal_clusters = [c for c in clusters if c.cluster_type == ClusterType.TEMPORAL_BURST]
        if temporal_clusters:
            context['temporal_cluster_count'] = len(temporal_clusters)
            context['max_burst_intensity'] = max(
                c.cluster_features.get('burst_intensity_per_hour', 0)
                for c in temporal_clusters
            )
        
        return context
    
    def _calculate_priority_score(self, risk_score: float, confidence: float, 
                                correlation_count: int) -> int:
        """Calculate priority score (1-100)."""
        # Base priority from risk score
        base_priority = risk_score * 70
        
        # Confidence adjustment
        confidence_adjustment = confidence * 20
        
        # Correlation activity bonus
        correlation_bonus = min(correlation_count * 2, 10)
        
        priority = base_priority + confidence_adjustment + correlation_bonus
        
        return min(max(int(priority), 1), 100)
    
    def _generate_recommendations(self, risk_level: RiskLevel, 
                                threat_category: ThreatCategory,
                                risk_factors: List[RiskFactor]) -> List[str]:
        """Generate actionable recommendations."""
        recommendations = []
        
        # Risk level based recommendations
        if risk_level == RiskLevel.CRITICAL:
            recommendations.extend([
                "Immediately block this indicator across all security controls",
                "Investigate for active threats in environment",
                "Review related indicators and clusters for broader campaign"
            ])
        elif risk_level == RiskLevel.HIGH:
            recommendations.extend([
                "Add to high-priority watch lists",
                "Consider blocking in security controls",
                "Monitor for related activity"
            ])
        elif risk_level == RiskLevel.MEDIUM:
            recommendations.extend([
                "Add to monitoring systems",
                "Review in context of other threat intelligence"
            ])
        
        # Threat category specific recommendations
        if threat_category == ThreatCategory.MALWARE:
            recommendations.append("Scan endpoints for malware presence")
        elif threat_category == ThreatCategory.PHISHING:
            recommendations.append("Review email security and user training")
        elif threat_category == ThreatCategory.C2_INFRASTRUCTURE:
            recommendations.append("Monitor network traffic to/from this indicator")
        
        # Risk factor specific recommendations
        for factor in risk_factors:
            if factor.name == "temporal_burst_activity" and factor.score > 0.7:
                recommendations.append("Investigate coordinated attack campaign")
            elif factor.name == "malware_family_cluster_membership":
                recommendations.append("Deploy malware family specific detections")
        
        return recommendations
    
    def batch_risk_assessment(self, indicators: List[NormalizedIndicator],
                            correlations_by_indicator: Dict[str, List[CorrelationResult]],
                            clusters_by_indicator: Dict[str, List[IndicatorCluster]]) -> List[RiskAssessment]:
        """Perform batch risk assessment."""
        assessments = []
        
        logger.info(f"Starting batch risk assessment for {len(indicators)} indicators")
        
        for indicator in indicators:
            try:
                indicator_correlations = correlations_by_indicator.get(indicator.id, [])
                indicator_clusters = clusters_by_indicator.get(indicator.id, [])
                
                assessment = self.assess_risk(indicator, indicator_correlations, indicator_clusters)
                assessments.append(assessment)
                
            except Exception as e:
                logger.error(f"Risk assessment failed for indicator {indicator.id}: {e}")
        
        logger.info(f"Completed {len(assessments)} risk assessments")
        return assessments