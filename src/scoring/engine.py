"""
Advanced scoring engine for threat intelligence prioritization.

This module implements sophisticated multi-factor risk scoring that combines
threat severity, temporal decay, confidence weighting, and priority band
classification to provide actionable threat prioritization for SOC teams.
"""

import logging
import statistics
import math
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, Counter
import json

try:
    from ..normalizers.schema import NormalizedIndicator, IndicatorType
    from ..correlation.engine import GraphNode, GraphRelationship, CorrelationResult
except ImportError:
    from normalizers.schema import NormalizedIndicator, IndicatorType
    from correlation.engine import GraphNode, GraphRelationship, CorrelationResult

logger = logging.getLogger(__name__)


class PriorityBand(Enum):
    """Priority classification bands."""
    P1_CRITICAL = "P1"     # Immediate response required
    P2_HIGH = "P2"         # High priority, same day response
    P3_MEDIUM = "P3"       # Medium priority, 1-3 days
    P4_LOW = "P4"          # Low priority, monitoring
    UNCLASSIFIED = "UC"    # Insufficient data for classification


class ThreatCategory(Enum):
    """Categories of threats for specialized scoring."""
    MALWARE = "malware"
    PHISHING = "phishing"
    C2_INFRASTRUCTURE = "c2_infrastructure"
    VULNERABILITY = "vulnerability"
    DATA_EXFILTRATION = "data_exfiltration"
    RECONNAISSANCE = "reconnaissance"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE = "persistence"
    UNKNOWN = "unknown"


class ScoreComponent(Enum):
    """Components contributing to overall threat score."""
    BASE_SEVERITY = "base_severity"           # Inherent threat severity
    TEMPORAL_FACTOR = "temporal_factor"       # Time-based decay and freshness
    CONFIDENCE_FACTOR = "confidence_factor"   # Trust and validation confidence
    CORRELATION_FACTOR = "correlation_factor" # Relationship context
    BEHAVIORAL_FACTOR = "behavioral_factor"   # Behavioral analysis
    REPUTATION_FACTOR = "reputation_factor"   # Source and infrastructure reputation
    IMPACT_FACTOR = "impact_factor"          # Potential business impact


@dataclass
class ScoringWeights:
    """Configurable weights for scoring components."""
    
    base_severity: float = 0.30
    temporal_factor: float = 0.15
    confidence_factor: float = 0.15
    correlation_factor: float = 0.15
    behavioral_factor: float = 0.10
    reputation_factor: float = 0.10
    impact_factor: float = 0.05
    
    def __post_init__(self):
        """Validate weights sum to 1.0."""
        total = sum([
            self.base_severity, self.temporal_factor, self.confidence_factor,
            self.correlation_factor, self.behavioral_factor, self.reputation_factor,
            self.impact_factor
        ])
        
        if not 0.95 <= total <= 1.05:  # Allow small floating point variance
            raise ValueError(f"Scoring weights must sum to 1.0, got {total}")
    
    def normalize(self) -> 'ScoringWeights':
        """Normalize weights to sum to 1.0."""
        total = sum([
            self.base_severity, self.temporal_factor, self.confidence_factor,
            self.correlation_factor, self.behavioral_factor, self.reputation_factor,
            self.impact_factor
        ])
        
        if total == 0:
            raise ValueError("Cannot normalize zero weights")
        
        return ScoringWeights(
            base_severity=self.base_severity / total,
            temporal_factor=self.temporal_factor / total,
            confidence_factor=self.confidence_factor / total,
            correlation_factor=self.correlation_factor / total,
            behavioral_factor=self.behavioral_factor / total,
            reputation_factor=self.reputation_factor / total,
            impact_factor=self.impact_factor / total
        )


@dataclass
class ScoreBreakdown:
    """Detailed breakdown of threat score components."""
    
    # Component scores (0.0 - 1.0)
    base_severity_score: float = 0.0
    temporal_score: float = 0.0
    confidence_score: float = 0.0
    correlation_score: float = 0.0
    behavioral_score: float = 0.0
    reputation_score: float = 0.0
    impact_score: float = 0.0
    
    # Weighted contributions
    weighted_scores: Dict[str, float] = field(default_factory=dict)
    
    # Final scores
    raw_score: float = 0.0
    normalized_score: float = 0.0
    priority_band: PriorityBand = PriorityBand.UNCLASSIFIED
    
    # Metadata
    score_timestamp: Optional[datetime] = None
    score_version: str = "1.0"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'component_scores': {
                'base_severity': self.base_severity_score,
                'temporal': self.temporal_score,
                'confidence': self.confidence_score,
                'correlation': self.correlation_score,
                'behavioral': self.behavioral_score,
                'reputation': self.reputation_score,
                'impact': self.impact_score
            },
            'weighted_scores': self.weighted_scores,
            'final_scores': {
                'raw_score': self.raw_score,
                'normalized_score': self.normalized_score,
                'priority_band': self.priority_band.value
            },
            'metadata': {
                'score_timestamp': self.score_timestamp.isoformat() if self.score_timestamp else None,
                'score_version': self.score_version
            }
        }


@dataclass
class ThreatScore:
    """Complete threat score for an indicator."""
    
    indicator_id: str
    indicator_value: str
    indicator_type: str
    
    # Scoring results
    score_breakdown: ScoreBreakdown = field(default_factory=ScoreBreakdown)
    
    # Classification
    threat_category: ThreatCategory = ThreatCategory.UNKNOWN
    priority_band: PriorityBand = PriorityBand.UNCLASSIFIED
    
    # Context
    contributing_factors: List[str] = field(default_factory=list)
    escalation_triggers: List[str] = field(default_factory=list)
    
    # Temporal tracking
    first_scored: Optional[datetime] = None
    last_updated: Optional[datetime] = None
    score_history: List[float] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'indicator_info': {
                'indicator_id': self.indicator_id,
                'indicator_value': self.indicator_value,
                'indicator_type': self.indicator_type
            },
            'scoring': self.score_breakdown.to_dict(),
            'classification': {
                'threat_category': self.threat_category.value,
                'priority_band': self.priority_band.value
            },
            'context': {
                'contributing_factors': self.contributing_factors,
                'escalation_triggers': self.escalation_triggers
            },
            'temporal': {
                'first_scored': self.first_scored.isoformat() if self.first_scored else None,
                'last_updated': self.last_updated.isoformat() if self.last_updated else None,
                'score_history': self.score_history
            }
        }


class BaseSeverityCalculator:
    """Calculates base threat severity from indicator properties."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize base severity calculator."""
        self.config = config or {}
        
        # Severity mappings
        self.indicator_type_severity = {
            IndicatorType.FILE_HASH: 0.8,
            IndicatorType.IP_ADDRESS: 0.7,
            IndicatorType.DOMAIN: 0.7,
            IndicatorType.URL: 0.6,
            IndicatorType.EMAIL: 0.5,
            IndicatorType.USER_AGENT: 0.3,
            IndicatorType.CERTIFICATE: 0.6,
            IndicatorType.MUTEX: 0.7,
            IndicatorType.REGISTRY_KEY: 0.6
        }
        
        # Malware family severity
        self.malware_family_severity = {
            # High severity families
            'ransomware': 1.0, 'rootkit': 0.9, 'backdoor': 0.8, 'trojan': 0.7,
            # Medium severity families  
            'spyware': 0.6, 'adware': 0.4, 'pup': 0.3,
            # Unknown
            'unknown': 0.5
        }
        
        # CVE severity mappings (CVSS to normalized)
        self.cvss_to_severity = {
            (9.0, 10.0): 1.0,    # Critical
            (7.0, 8.9): 0.8,     # High
            (4.0, 6.9): 0.6,     # Medium
            (0.1, 3.9): 0.3,     # Low
            (0.0, 0.0): 0.1      # None/Info
        }
        
        logger.debug("Base severity calculator initialized")
    
    def calculate_base_severity(self, indicator: NormalizedIndicator) -> Tuple[float, List[str]]:
        """Calculate base severity score for an indicator."""
        
        contributing_factors = []
        severity_scores = []
        
        # Indicator type baseline
        indicator_type = IndicatorType(indicator.type) if hasattr(IndicatorType, indicator.type.upper()) else None
        if indicator_type and indicator_type in self.indicator_type_severity:
            type_severity = self.indicator_type_severity[indicator_type]
            severity_scores.append(type_severity)
            contributing_factors.append(f"indicator_type_{indicator_type.value}_{type_severity:.2f}")
        
        # Malware family analysis
        malware_families = indicator.properties.get('malware_families', [])
        if malware_families:
            family_severities = []
            for family in malware_families:
                family_lower = family.lower()
                for known_family, severity in self.malware_family_severity.items():
                    if known_family in family_lower:
                        family_severities.append(severity)
                        contributing_factors.append(f"malware_family_{known_family}_{severity:.2f}")
                        break
            
            if family_severities:
                # Use maximum malware family severity
                max_family_severity = max(family_severities)
                severity_scores.append(max_family_severity)
        
        # CVE severity analysis
        cve_scores = indicator.properties.get('cvss_scores', [])
        if cve_scores:
            cvss_severities = []
            for cvss_score in cve_scores:
                if isinstance(cvss_score, (int, float)):
                    for (min_cvss, max_cvss), severity in self.cvss_to_severity.items():
                        if min_cvss <= cvss_score <= max_cvss:
                            cvss_severities.append(severity)
                            contributing_factors.append(f"cvss_{cvss_score}_{severity:.2f}")
                            break
            
            if cvss_severities:
                # Use maximum CVSS severity
                max_cvss_severity = max(cvss_severities)
                severity_scores.append(max_cvss_severity)
        
        # Tag-based severity boosters
        tags = indicator.properties.get('tags', [])
        if tags:
            severity_boosters = []
            
            high_severity_tags = {
                'apt', 'targeted', 'zero-day', 'exploit', 'c2', 'command-control',
                'ransomware', 'banking', 'stealer', 'credential'
            }
            
            medium_severity_tags = {
                'malicious', 'suspicious', 'phishing', 'scam', 'fraud'
            }
            
            for tag in tags:
                tag_lower = tag.lower()
                if any(high_tag in tag_lower for high_tag in high_severity_tags):
                    severity_boosters.append(0.3)
                    contributing_factors.append(f"high_severity_tag_{tag}")
                elif any(med_tag in tag_lower for med_tag in medium_severity_tags):
                    severity_boosters.append(0.2)
                    contributing_factors.append(f"medium_severity_tag_{tag}")
            
            if severity_boosters:
                # Apply tag boost (but don't let tags alone determine severity)
                tag_boost = min(sum(severity_boosters), 0.4)  # Cap at 0.4
                if severity_scores:
                    # Boost existing severity
                    severity_scores = [score + tag_boost for score in severity_scores]
                else:
                    # Tags alone provide some severity
                    severity_scores.append(0.3 + tag_boost)
        
        # Reputation-based severity
        reputation_score = indicator.properties.get('reputation_score', 0)
        if reputation_score < -50:  # Very negative reputation
            reputation_severity = 0.8
            severity_scores.append(reputation_severity)
            contributing_factors.append(f"negative_reputation_{reputation_score}_{reputation_severity:.2f}")
        elif reputation_score < -20:  # Moderate negative reputation
            reputation_severity = 0.6
            severity_scores.append(reputation_severity)
            contributing_factors.append(f"moderate_reputation_{reputation_score}_{reputation_severity:.2f}")
        
        # Calculate final base severity
        if severity_scores:
            # Use weighted average with emphasis on highest score
            severity_scores.sort(reverse=True)
            
            if len(severity_scores) == 1:
                base_severity = severity_scores[0]
            else:
                # Weight highest score more heavily
                weights = [0.6, 0.3, 0.1][:len(severity_scores)]
                weights = weights + [0.05] * (len(severity_scores) - len(weights))  # Diminishing returns
                
                weighted_sum = sum(score * weight for score, weight in zip(severity_scores, weights))
                weight_sum = sum(weights[:len(severity_scores)])
                base_severity = weighted_sum / weight_sum
        else:
            # Default severity for unknown indicators
            base_severity = 0.2
            contributing_factors.append("default_unknown_0.20")
        
        # Ensure score is in valid range
        base_severity = max(0.0, min(1.0, base_severity))
        
        return base_severity, contributing_factors


class TemporalScoring:
    """Handles temporal aspects of threat scoring."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize temporal scoring."""
        self.config = config or {}
        
        # Temporal configuration
        self.freshness_window = timedelta(days=self.config.get('freshness_window_days', 7))
        self.decay_half_life = timedelta(days=self.config.get('decay_half_life_days', 30))
        self.max_age_penalty = self.config.get('max_age_penalty', 0.7)  # Maximum decay
        
        logger.debug("Temporal scoring initialized")
    
    def calculate_temporal_score(self, 
                                indicator: NormalizedIndicator,
                                current_time: Optional[datetime] = None) -> Tuple[float, List[str]]:
        """Calculate temporal score based on freshness and decay."""
        
        if current_time is None:
            current_time = datetime.utcnow()
        
        contributing_factors = []
        
        # Get indicator timestamps
        first_observed = indicator.first_observed
        last_observed = indicator.last_observed or first_observed
        
        if not first_observed:
            # No temporal information available
            return 0.5, ["no_temporal_data"]
        
        # Calculate age and freshness
        age = current_time - first_observed
        recency = current_time - last_observed
        
        # Freshness component (higher score for recent observations)
        if recency <= self.freshness_window:
            # Very fresh
            freshness_score = 1.0 - (recency.total_seconds() / self.freshness_window.total_seconds()) * 0.3
            contributing_factors.append(f"fresh_observation_{recency.days}d_{freshness_score:.2f}")
        else:
            # Apply freshness penalty
            days_stale = (recency - self.freshness_window).days
            freshness_penalty = min(days_stale * 0.02, 0.4)  # Max 40% penalty
            freshness_score = 1.0 - freshness_penalty
            contributing_factors.append(f"stale_observation_{days_stale}d_{freshness_score:.2f}")
        
        # Decay component (exponential decay based on age)
        if age <= self.decay_half_life:
            # Within half-life, minimal decay
            decay_factor = 1.0 - (age.total_seconds() / self.decay_half_life.total_seconds()) * 0.1
        else:
            # Exponential decay after half-life
            half_lives = age.total_seconds() / self.decay_half_life.total_seconds()
            decay_factor = math.pow(0.5, half_lives - 1)  # Start decay after first half-life
            decay_factor = max(decay_factor, 1.0 - self.max_age_penalty)  # Floor
        
        contributing_factors.append(f"age_decay_{age.days}d_{decay_factor:.2f}")
        
        # Observation frequency boost (multiple recent observations)
        observation_count = indicator.properties.get('observation_count', 1)
        if observation_count > 1:
            # Boost for multiple observations (indicates ongoing activity)
            frequency_boost = min(math.log10(observation_count) * 0.1, 0.2)  # Max 20% boost
            freshness_score += frequency_boost
            contributing_factors.append(f"multiple_observations_{observation_count}_{frequency_boost:.2f}")
        
        # Combine freshness and decay (weighted average)
        temporal_score = (freshness_score * 0.7) + (decay_factor * 0.3)
        
        # Ensure score is in valid range
        temporal_score = max(0.0, min(1.0, temporal_score))
        
        return temporal_score, contributing_factors


class CorrelationScoring:
    """Scores threats based on correlation context."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize correlation scoring."""
        self.config = config or {}
        
        # Correlation weights
        self.relationship_weights = {
            'infrastructure_sharing': 0.8,
            'behavioral_similarity': 0.6,
            'temporal_correlation': 0.5,
            'technique_usage': 0.7,
            'attribution': 0.9,
            'related': 0.3
        }
        
        logger.debug("Correlation scoring initialized")
    
    def calculate_correlation_score(self, 
                                   indicator_id: str,
                                   correlation_result: Optional[CorrelationResult] = None) -> Tuple[float, List[str]]:
        """Calculate correlation score based on graph relationships."""
        
        if not correlation_result or not correlation_result.relationships:
            return 0.3, ["no_correlation_data"]  # Default for isolated indicators
        
        contributing_factors = []
        correlation_scores = []
        
        # Find relationships involving this indicator
        indicator_relationships = []
        for rel in correlation_result.relationships.values():
            if rel.source_node_id == indicator_id or rel.target_node_id == indicator_id:
                indicator_relationships.append(rel)
        
        if not indicator_relationships:
            return 0.3, ["no_relationships_found"]
        
        # Analyze relationship quality and quantity
        relationship_types = Counter()
        total_confidence = 0
        high_confidence_count = 0
        
        for rel in indicator_relationships:
            rel_type = rel.relationship_type.value if hasattr(rel.relationship_type, 'value') else str(rel.relationship_type)
            relationship_types[rel_type] += 1
            
            total_confidence += rel.confidence
            if rel.confidence > 0.7:
                high_confidence_count += 1
        
        # Base correlation score from relationship count
        relationship_count = len(indicator_relationships)
        base_correlation = min(relationship_count * 0.1, 0.8)  # Cap at 0.8
        contributing_factors.append(f"relationship_count_{relationship_count}_{base_correlation:.2f}")
        
        # Quality bonus from relationship types
        quality_bonus = 0
        for rel_type, count in relationship_types.items():
            weight = self.relationship_weights.get(rel_type, 0.2)
            type_bonus = min(count * weight * 0.1, weight * 0.3)  # Diminishing returns
            quality_bonus += type_bonus
            contributing_factors.append(f"relationship_type_{rel_type}_{count}_{type_bonus:.2f}")
        
        # Confidence bonus
        if indicator_relationships:
            avg_confidence = total_confidence / len(indicator_relationships)
            confidence_bonus = (avg_confidence - 0.5) * 0.2  # Bonus/penalty around 0.5 baseline
            contributing_factors.append(f"avg_confidence_{avg_confidence:.2f}_{confidence_bonus:.2f}")
        else:
            confidence_bonus = 0
        
        # High-confidence relationship bonus
        if high_confidence_count > 0:
            hc_bonus = min(high_confidence_count * 0.05, 0.15)
            quality_bonus += hc_bonus
            contributing_factors.append(f"high_confidence_relationships_{high_confidence_count}_{hc_bonus:.2f}")
        
        # Community/clustering bonus (if indicator is part of large connected component)
        # This would require graph analysis from correlation results
        
        # Calculate final correlation score
        correlation_score = base_correlation + quality_bonus + confidence_bonus
        
        # Ensure score is in valid range
        correlation_score = max(0.0, min(1.0, correlation_score))
        
        return correlation_score, contributing_factors


class AdvancedScoringEngine:
    """Main scoring engine integrating all scoring components."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize advanced scoring engine."""
        self.config = config or {}
        
        # Initialize scoring components
        self.base_severity_calc = BaseSeverityCalculator(
            self.config.get('base_severity', {})
        )
        
        self.temporal_scoring = TemporalScoring(
            self.config.get('temporal', {})
        )
        
        self.correlation_scoring = CorrelationScoring(
            self.config.get('correlation', {})
        )
        
        # Scoring configuration
        self.weights = ScoringWeights(**self.config.get('weights', {}))
        
        # Priority band thresholds
        self.priority_thresholds = {
            PriorityBand.P1_CRITICAL: self.config.get('p1_threshold', 0.85),
            PriorityBand.P2_HIGH: self.config.get('p2_threshold', 0.70),
            PriorityBand.P3_MEDIUM: self.config.get('p3_threshold', 0.45),
            PriorityBand.P4_LOW: self.config.get('p4_threshold', 0.20)
        }
        
        logger.info("Advanced scoring engine initialized")
    
    def calculate_threat_score(self, 
                             indicator: NormalizedIndicator,
                             correlation_result: Optional[CorrelationResult] = None,
                             current_time: Optional[datetime] = None) -> ThreatScore:
        """Calculate comprehensive threat score for an indicator."""
        
        if current_time is None:
            current_time = datetime.utcnow()
        
        # Initialize threat score object
        threat_score = ThreatScore(
            indicator_id=indicator.id,
            indicator_value=indicator.value,
            indicator_type=indicator.type,
            first_scored=current_time,
            last_updated=current_time
        )
        
        # Initialize score breakdown
        breakdown = ScoreBreakdown(score_timestamp=current_time)
        
        # Calculate component scores
        all_contributing_factors = []
        
        try:
            # Base severity
            base_severity, base_factors = self.base_severity_calc.calculate_base_severity(indicator)
            breakdown.base_severity_score = base_severity
            all_contributing_factors.extend([f"base_severity: {f}" for f in base_factors])
            
            # Temporal scoring
            temporal_score, temporal_factors = self.temporal_scoring.calculate_temporal_score(
                indicator, current_time
            )
            breakdown.temporal_score = temporal_score
            all_contributing_factors.extend([f"temporal: {f}" for f in temporal_factors])
            
            # Confidence scoring (from indicator properties)
            confidence_score = self._calculate_confidence_score(indicator)
            breakdown.confidence_score = confidence_score
            all_contributing_factors.append(f"confidence: source_reliability_{confidence_score:.2f}")
            
            # Correlation scoring
            correlation_score, correlation_factors = self.correlation_scoring.calculate_correlation_score(
                indicator.id, correlation_result
            )
            breakdown.correlation_score = correlation_score
            all_contributing_factors.extend([f"correlation: {f}" for f in correlation_factors])
            
            # Behavioral scoring (simplified for now)
            behavioral_score = self._calculate_behavioral_score(indicator)
            breakdown.behavioral_score = behavioral_score
            all_contributing_factors.append(f"behavioral: analysis_{behavioral_score:.2f}")
            
            # Reputation scoring
            reputation_score = self._calculate_reputation_score(indicator)
            breakdown.reputation_score = reputation_score
            all_contributing_factors.append(f"reputation: score_{reputation_score:.2f}")
            
            # Impact scoring (business context)
            impact_score = self._calculate_impact_score(indicator)
            breakdown.impact_score = impact_score
            all_contributing_factors.append(f"impact: business_context_{impact_score:.2f}")
            
            # Calculate weighted scores
            weighted_scores = {
                'base_severity': base_severity * self.weights.base_severity,
                'temporal': temporal_score * self.weights.temporal_factor,
                'confidence': confidence_score * self.weights.confidence_factor,
                'correlation': correlation_score * self.weights.correlation_factor,
                'behavioral': behavioral_score * self.weights.behavioral_factor,
                'reputation': reputation_score * self.weights.reputation_factor,
                'impact': impact_score * self.weights.impact_factor
            }
            
            breakdown.weighted_scores = weighted_scores
            
            # Calculate final score
            raw_score = sum(weighted_scores.values())
            normalized_score = max(0.0, min(1.0, raw_score))
            
            breakdown.raw_score = raw_score
            breakdown.normalized_score = normalized_score
            
            # Determine priority band
            priority_band = self._determine_priority_band(normalized_score)
            breakdown.priority_band = priority_band
            
            # Set results in threat score
            threat_score.score_breakdown = breakdown
            threat_score.priority_band = priority_band
            threat_score.contributing_factors = all_contributing_factors
            threat_score.threat_category = self._classify_threat_category(indicator)
            
            # Check for escalation triggers
            threat_score.escalation_triggers = self._check_escalation_triggers(
                indicator, normalized_score, correlation_result
            )
            
            logger.debug(f"Scored indicator {indicator.id}: {normalized_score:.3f} ({priority_band.value})")
            
        except Exception as e:
            logger.error(f"Scoring failed for indicator {indicator.id}: {e}", exc_info=True)
            # Set minimal score on error
            breakdown.normalized_score = 0.1
            breakdown.priority_band = PriorityBand.UNCLASSIFIED
            threat_score.score_breakdown = breakdown
            threat_score.contributing_factors = [f"scoring_error: {str(e)}"]
        
        return threat_score
    
    def _calculate_confidence_score(self, indicator: NormalizedIndicator) -> float:
        """Calculate confidence score from indicator properties."""
        
        # Source reliability
        source_reliability = indicator.properties.get('source_reliability', 0.5)
        
        # Validation status
        validation_score = indicator.properties.get('validation_score', 0.5)
        
        # Observation count (more observations = higher confidence)
        observation_count = indicator.properties.get('observation_count', 1)
        observation_factor = min(math.log10(observation_count + 1) * 0.2, 0.3)
        
        # Combine confidence factors
        confidence = (source_reliability * 0.5) + (validation_score * 0.3) + (observation_factor * 0.2)
        
        return max(0.0, min(1.0, confidence))
    
    def _calculate_behavioral_score(self, indicator: NormalizedIndicator) -> float:
        """Calculate behavioral analysis score."""
        
        # Tag-based behavioral analysis
        tags = indicator.properties.get('tags', [])
        behavioral_indicators = {
            'persistent', 'evasive', 'encrypted', 'obfuscated', 'polymorphic',
            'targeted', 'apt', 'sophisticated', 'multi-stage'
        }
        
        behavioral_score = 0.3  # Base score
        
        for tag in tags:
            tag_lower = tag.lower()
            if any(behavior in tag_lower for behavior in behavioral_indicators):
                behavioral_score += 0.1
        
        # MITRE techniques indicate sophisticated behavior
        techniques = indicator.properties.get('mitre_techniques', [])
        if techniques:
            technique_score = min(len(techniques) * 0.05, 0.3)
            behavioral_score += technique_score
        
        return max(0.0, min(1.0, behavioral_score))
    
    def _calculate_reputation_score(self, indicator: NormalizedIndicator) -> float:
        """Calculate reputation-based score."""
        
        # Direct reputation score
        reputation = indicator.properties.get('reputation_score', 0)
        
        # Convert reputation to 0-1 scale (assuming reputation is -100 to +100)
        if reputation <= -80:
            return 1.0  # Very bad reputation
        elif reputation <= -50:
            return 0.8
        elif reputation <= -20:
            return 0.6
        elif reputation <= 0:
            return 0.4
        else:
            return 0.2  # Neutral or positive reputation
    
    def _calculate_impact_score(self, indicator: NormalizedIndicator) -> float:
        """Calculate potential business impact score."""
        
        # Industry targeting
        targeted_industries = indicator.properties.get('targeted_industries', [])
        if targeted_industries:
            # Higher score if targeting critical industries
            critical_industries = {'finance', 'healthcare', 'government', 'energy', 'utilities'}
            if any(industry.lower() in critical_industries for industry in targeted_industries):
                return 0.8
            else:
                return 0.6
        
        # Asset targeting
        targeted_assets = indicator.properties.get('targeted_assets', [])
        if targeted_assets:
            critical_assets = {'server', 'database', 'domain_controller', 'backup'}
            if any(asset.lower() in critical_assets for asset in targeted_assets):
                return 0.7
        
        # Default impact
        return 0.5
    
    def _determine_priority_band(self, score: float) -> PriorityBand:
        """Determine priority band from normalized score."""
        
        if score >= self.priority_thresholds[PriorityBand.P1_CRITICAL]:
            return PriorityBand.P1_CRITICAL
        elif score >= self.priority_thresholds[PriorityBand.P2_HIGH]:
            return PriorityBand.P2_HIGH
        elif score >= self.priority_thresholds[PriorityBand.P3_MEDIUM]:
            return PriorityBand.P3_MEDIUM
        elif score >= self.priority_thresholds[PriorityBand.P4_LOW]:
            return PriorityBand.P4_LOW
        else:
            return PriorityBand.UNCLASSIFIED
    
    def _classify_threat_category(self, indicator: NormalizedIndicator) -> ThreatCategory:
        """Classify threat into category for specialized handling."""
        
        tags = [tag.lower() for tag in indicator.properties.get('tags', [])]
        malware_families = [family.lower() for family in indicator.properties.get('malware_families', [])]
        
        # Malware category
        if any('malware' in tag or 'trojan' in tag or 'virus' in tag for tag in tags):
            return ThreatCategory.MALWARE
        
        if any('ransomware' in family or 'backdoor' in family for family in malware_families):
            return ThreatCategory.MALWARE
        
        # Phishing category
        if any('phish' in tag or 'scam' in tag for tag in tags):
            return ThreatCategory.PHISHING
        
        # C2 Infrastructure
        if any('c2' in tag or 'command' in tag or 'control' in tag for tag in tags):
            return ThreatCategory.C2_INFRASTRUCTURE
        
        # Vulnerability
        if any('cve' in tag or 'vuln' in tag or 'exploit' in tag for tag in tags):
            return ThreatCategory.VULNERABILITY
        
        # Reconnaissance
        if any('recon' in tag or 'scan' in tag for tag in tags):
            return ThreatCategory.RECONNAISSANCE
        
        return ThreatCategory.UNKNOWN
    
    def _check_escalation_triggers(self, 
                                 indicator: NormalizedIndicator,
                                 score: float,
                                 correlation_result: Optional[CorrelationResult] = None) -> List[str]:
        """Check for conditions that should trigger escalation."""
        
        triggers = []
        
        # High score threshold
        if score >= 0.9:
            triggers.append("critical_score_threshold")
        
        # Zero-day indicators
        tags = [tag.lower() for tag in indicator.properties.get('tags', [])]
        if any('zero-day' in tag or '0day' in tag for tag in tags):
            triggers.append("zero_day_indicator")
        
        # APT attribution
        if any('apt' in tag for tag in tags):
            triggers.append("apt_attribution")
        
        # Recent observation of old indicator
        if indicator.first_observed and indicator.last_observed:
            age = datetime.utcnow() - indicator.first_observed
            recency = datetime.utcnow() - indicator.last_observed
            
            if age > timedelta(days=90) and recency < timedelta(hours=24):
                triggers.append("old_indicator_reactivated")
        
        # High correlation connectivity
        if correlation_result and correlation_result.relationships:
            related_count = sum(1 for rel in correlation_result.relationships.values()
                              if rel.source_node_id == indicator.id or rel.target_node_id == indicator.id)
            if related_count >= 5:
                triggers.append("highly_connected_indicator")
        
        # Multiple malware families
        malware_families = indicator.properties.get('malware_families', [])
        if len(malware_families) >= 3:
            triggers.append("multiple_malware_families")
        
        return triggers
    
    def batch_score_indicators(self, 
                             indicators: List[NormalizedIndicator],
                             correlation_result: Optional[CorrelationResult] = None) -> List[ThreatScore]:
        """Score multiple indicators efficiently."""
        
        start_time = datetime.utcnow()
        threat_scores = []
        
        logger.info(f"Batch scoring {len(indicators)} indicators")
        
        for i, indicator in enumerate(indicators):
            try:
                threat_score = self.calculate_threat_score(indicator, correlation_result, start_time)
                threat_scores.append(threat_score)
                
                # Log progress for large batches
                if (i + 1) % 100 == 0:
                    logger.debug(f"Scored {i + 1}/{len(indicators)} indicators")
                    
            except Exception as e:
                logger.error(f"Failed to score indicator {indicator.id}: {e}")
                # Create minimal error score
                error_score = ThreatScore(
                    indicator_id=indicator.id,
                    indicator_value=indicator.value,
                    indicator_type=indicator.type,
                    first_scored=start_time,
                    last_updated=start_time
                )
                error_score.score_breakdown.normalized_score = 0.0
                error_score.priority_band = PriorityBand.UNCLASSIFIED
                error_score.contributing_factors = [f"scoring_error: {str(e)}"]
                threat_scores.append(error_score)
        
        execution_time = (datetime.utcnow() - start_time).total_seconds()
        logger.info(f"Batch scoring completed: {len(threat_scores)} scores in {execution_time:.2f}s")
        
        return threat_scores
    
    def get_scoring_statistics(self) -> Dict[str, Any]:
        """Get scoring engine statistics and configuration."""
        
        return {
            'configuration': {
                'weights': {
                    'base_severity': self.weights.base_severity,
                    'temporal_factor': self.weights.temporal_factor,
                    'confidence_factor': self.weights.confidence_factor,
                    'correlation_factor': self.weights.correlation_factor,
                    'behavioral_factor': self.weights.behavioral_factor,
                    'reputation_factor': self.weights.reputation_factor,
                    'impact_factor': self.weights.impact_factor
                },
                'priority_thresholds': {
                    band.value: threshold for band, threshold in self.priority_thresholds.items()
                }
            },
            'components': {
                'base_severity_calculator': bool(self.base_severity_calc),
                'temporal_scoring': bool(self.temporal_scoring),
                'correlation_scoring': bool(self.correlation_scoring)
            }
        }