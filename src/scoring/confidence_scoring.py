"""
Confidence scoring system for threat intelligence.

This module implements sophisticated confidence scoring integrating source reliability
metrics, correlation strength analysis, validation results assessment, cross-validation
scoring, and confidence decay modeling.
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
    from .engine import ThreatScore
    from .risk_assessment import RiskLevel
except ImportError:
    from normalizers.schema import NormalizedIndicator, IndicatorType
    from scoring.engine import ThreatScore
    from scoring.risk_assessment import RiskLevel

logger = logging.getLogger(__name__)


class SourceType(Enum):
    """Types of intelligence sources."""
    COMMERCIAL_FEED = "commercial_feed"
    GOVERNMENT = "government"
    OPEN_SOURCE = "open_source"
    COMMUNITY = "community"
    INTERNAL = "internal"
    HONEYPOT = "honeypot"
    SANDBOX = "sandbox"
    AUTOMATED = "automated"
    MANUAL = "manual"
    UNKNOWN = "unknown"


class ConfidenceLevel(Enum):
    """Confidence level classifications."""
    CONFIRMED = "confirmed"        # 0.9 - 1.0
    HIGH = "high"                  # 0.7 - 0.89
    MEDIUM = "medium"              # 0.4 - 0.69
    LOW = "low"                    # 0.1 - 0.39
    UNCONFIRMED = "unconfirmed"    # 0.0 - 0.09


class ValidationMethod(Enum):
    """Validation methods for indicators."""
    MANUAL_VERIFICATION = "manual_verification"
    AUTOMATED_ANALYSIS = "automated_analysis"
    CROSS_REFERENCE = "cross_reference"
    BEHAVIORAL_ANALYSIS = "behavioral_analysis"
    NETWORK_VALIDATION = "network_validation"
    SANDBOX_EXECUTION = "sandbox_execution"
    EXPERT_REVIEW = "expert_review"
    COMMUNITY_VALIDATION = "community_validation"


@dataclass
class SourceReliability:
    """Reliability profile for an intelligence source."""
    
    source_name: str
    source_type: SourceType = SourceType.UNKNOWN
    
    # Historical performance
    accuracy_rate: float = 0.0           # 0-1 (false positive rate)
    coverage_completeness: float = 0.0   # How complete the data is
    timeliness_score: float = 0.0        # How quickly they report
    consistency_score: float = 0.0       # How consistent over time
    
    # Reputation metrics
    community_reputation: float = 0.5    # Community assessment
    false_positive_rate: float = 0.5     # Known FP rate
    true_positive_rate: float = 0.5      # Known TP rate
    
    # Volume and experience
    total_indicators_provided: int = 0
    years_of_operation: float = 0.0
    
    # Quality indicators
    provides_context: bool = False       # Rich metadata
    provides_attribution: bool = False   # Attack attribution
    provides_technical_details: bool = False  # Technical analysis
    
    # Reliability score (computed)
    reliability_score: float = 0.5
    reliability_level: ConfidenceLevel = ConfidenceLevel.MEDIUM
    
    # Temporal factors
    last_updated: datetime = field(default_factory=datetime.utcnow)
    reliability_decay: float = 1.0       # Decay factor over time
    
    def calculate_reliability_score(self) -> float:
        """Calculate overall reliability score."""
        
        components = []
        
        # Historical performance (40% weight)
        if self.accuracy_rate > 0:
            performance_score = (
                self.accuracy_rate * 0.4 +
                self.coverage_completeness * 0.2 +
                self.timeliness_score * 0.2 +
                self.consistency_score * 0.2
            )
            components.append((performance_score, 0.4))
        
        # Reputation (30% weight)
        reputation_score = (
            self.community_reputation * 0.5 +
            (1.0 - self.false_positive_rate) * 0.3 +
            self.true_positive_rate * 0.2
        )
        components.append((reputation_score, 0.3))
        
        # Experience and volume (20% weight)
        volume_score = min(self.total_indicators_provided / 10000.0, 1.0)  # Cap at 10k
        experience_score = min(self.years_of_operation / 10.0, 1.0)       # Cap at 10 years
        exp_vol_score = (volume_score * 0.6 + experience_score * 0.4)
        components.append((exp_vol_score, 0.2))
        
        # Quality indicators (10% weight)
        quality_factors = [
            self.provides_context,
            self.provides_attribution,
            self.provides_technical_details
        ]
        quality_score = sum(quality_factors) / len(quality_factors)
        components.append((quality_score, 0.1))
        
        # Calculate weighted average
        if components:
            weighted_sum = sum(score * weight for score, weight in components)
            total_weight = sum(weight for _, weight in components)
            base_score = weighted_sum / total_weight if total_weight > 0 else 0.5
        else:
            base_score = 0.5
        
        # Apply temporal decay
        age = datetime.utcnow() - self.last_updated
        if age > timedelta(days=30):
            # Decay reliability over time if not updated
            days_old = age.days
            decay_factor = math.exp(-days_old / 365.0)  # 1-year half-life
            base_score *= decay_factor
        
        self.reliability_score = max(0.0, min(1.0, base_score))
        self.reliability_level = self._determine_confidence_level(self.reliability_score)
        
        return self.reliability_score
    
    def _determine_confidence_level(self, score: float) -> ConfidenceLevel:
        """Determine confidence level from score."""
        
        if score >= 0.9:
            return ConfidenceLevel.CONFIRMED
        elif score >= 0.7:
            return ConfidenceLevel.HIGH
        elif score >= 0.4:
            return ConfidenceLevel.MEDIUM
        elif score >= 0.1:
            return ConfidenceLevel.LOW
        else:
            return ConfidenceLevel.UNCONFIRMED
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'source_info': {
                'source_name': self.source_name,
                'source_type': self.source_type.value
            },
            'performance_metrics': {
                'accuracy_rate': self.accuracy_rate,
                'coverage_completeness': self.coverage_completeness,
                'timeliness_score': self.timeliness_score,
                'consistency_score': self.consistency_score
            },
            'reputation_metrics': {
                'community_reputation': self.community_reputation,
                'false_positive_rate': self.false_positive_rate,
                'true_positive_rate': self.true_positive_rate
            },
            'experience': {
                'total_indicators_provided': self.total_indicators_provided,
                'years_of_operation': self.years_of_operation
            },
            'quality_indicators': {
                'provides_context': self.provides_context,
                'provides_attribution': self.provides_attribution,
                'provides_technical_details': self.provides_technical_details
            },
            'reliability_assessment': {
                'reliability_score': self.reliability_score,
                'reliability_level': self.reliability_level.value,
                'reliability_decay': self.reliability_decay
            },
            'temporal': {
                'last_updated': self.last_updated.isoformat()
            }
        }


@dataclass
class ValidationResult:
    """Result of indicator validation."""
    
    indicator_id: str
    validation_method: ValidationMethod
    validator: str
    
    # Validation outcome
    validation_score: float = 0.5        # 0-1 confidence in validation
    is_confirmed: bool = False           # Binary validation result
    validation_details: str = ""         # Human-readable details
    
    # Supporting evidence
    evidence_count: int = 0              # Number of supporting pieces
    contradicting_evidence: int = 0      # Conflicting evidence
    
    # Validation context
    validation_timestamp: datetime = field(default_factory=datetime.utcnow)
    validation_effort: str = "low"       # low, medium, high effort
    
    # Metadata
    false_positive_likelihood: float = 0.0  # Estimated FP probability
    confidence_adjustment: float = 0.0       # Adjustment to base confidence
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'validation_info': {
                'indicator_id': self.indicator_id,
                'validation_method': self.validation_method.value,
                'validator': self.validator
            },
            'outcome': {
                'validation_score': self.validation_score,
                'is_confirmed': self.is_confirmed,
                'validation_details': self.validation_details
            },
            'evidence': {
                'evidence_count': self.evidence_count,
                'contradicting_evidence': self.contradicting_evidence
            },
            'context': {
                'validation_timestamp': self.validation_timestamp.isoformat(),
                'validation_effort': self.validation_effort,
                'false_positive_likelihood': self.false_positive_likelihood,
                'confidence_adjustment': self.confidence_adjustment
            }
        }


@dataclass
class CorrelationStrength:
    """Strength assessment for indicator correlations."""
    
    primary_indicator_id: str
    correlated_indicator_id: str
    
    # Correlation metrics
    correlation_type: str = "unknown"    # temporal, behavioral, infrastructure, etc.
    correlation_score: float = 0.0       # 0-1 strength of correlation
    confidence_boost: float = 0.0        # How much this boosts confidence
    
    # Supporting factors
    shared_attributes: List[str] = field(default_factory=list)
    temporal_proximity: float = 0.0      # How close in time
    behavioral_similarity: float = 0.0   # Similar behavior patterns
    infrastructure_overlap: float = 0.0  # Shared infrastructure
    
    # Quality indicators
    correlation_confidence: float = 0.5  # Confidence in the correlation itself
    validation_count: int = 0            # How many sources confirm this
    
    def calculate_strength(self) -> float:
        """Calculate overall correlation strength."""
        
        # Weight different correlation factors
        factors = [
            (self.temporal_proximity, 0.3),
            (self.behavioral_similarity, 0.3),
            (self.infrastructure_overlap, 0.2),
            (min(len(self.shared_attributes) / 5.0, 1.0), 0.2)  # Cap at 5 attributes
        ]
        
        weighted_sum = sum(factor * weight for factor, weight in factors)
        total_weight = sum(weight for _, weight in factors)
        
        base_strength = weighted_sum / total_weight if total_weight > 0 else 0.0
        
        # Adjust by correlation confidence
        self.correlation_score = base_strength * self.correlation_confidence
        
        # Calculate confidence boost (diminishing returns)
        self.confidence_boost = math.sqrt(self.correlation_score) * 0.2  # Max boost of 20%
        
        return self.correlation_score
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'correlation_info': {
                'primary_indicator_id': self.primary_indicator_id,
                'correlated_indicator_id': self.correlated_indicator_id,
                'correlation_type': self.correlation_type
            },
            'strength_metrics': {
                'correlation_score': self.correlation_score,
                'confidence_boost': self.confidence_boost,
                'correlation_confidence': self.correlation_confidence
            },
            'factors': {
                'shared_attributes': self.shared_attributes,
                'temporal_proximity': self.temporal_proximity,
                'behavioral_similarity': self.behavioral_similarity,
                'infrastructure_overlap': self.infrastructure_overlap
            },
            'validation': {
                'validation_count': self.validation_count
            }
        }


@dataclass
class ConfidenceScore:
    """Comprehensive confidence scoring result."""
    
    indicator_id: str
    
    # Base confidence components
    source_confidence: float = 0.5       # Confidence from source reliability
    validation_confidence: float = 0.5   # Confidence from validation results
    correlation_confidence: float = 0.5  # Confidence from correlations
    consistency_confidence: float = 0.5  # Confidence from cross-source consistency
    
    # Computed confidence scores
    base_confidence_score: float = 0.5
    adjusted_confidence_score: float = 0.5
    confidence_level: ConfidenceLevel = ConfidenceLevel.MEDIUM
    
    # Confidence factors and adjustments
    confidence_boosts: List[Tuple[str, float]] = field(default_factory=list)
    confidence_penalties: List[Tuple[str, float]] = field(default_factory=list)
    
    # Supporting data
    source_reliabilities: List[SourceReliability] = field(default_factory=list)
    validation_results: List[ValidationResult] = field(default_factory=list)
    correlation_strengths: List[CorrelationStrength] = field(default_factory=list)
    
    # Decay modeling
    confidence_decay_factor: float = 1.0
    staleness_penalty: float = 0.0
    
    # Metadata
    confidence_factors: List[str] = field(default_factory=list)
    calculation_timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'indicator_id': self.indicator_id,
            'confidence_components': {
                'source_confidence': self.source_confidence,
                'validation_confidence': self.validation_confidence,
                'correlation_confidence': self.correlation_confidence,
                'consistency_confidence': self.consistency_confidence
            },
            'computed_scores': {
                'base_confidence_score': self.base_confidence_score,
                'adjusted_confidence_score': self.adjusted_confidence_score,
                'confidence_level': self.confidence_level.value
            },
            'adjustments': {
                'confidence_boosts': [(reason, boost) for reason, boost in self.confidence_boosts],
                'confidence_penalties': [(reason, penalty) for reason, penalty in self.confidence_penalties],
                'confidence_decay_factor': self.confidence_decay_factor,
                'staleness_penalty': self.staleness_penalty
            },
            'supporting_data': {
                'source_count': len(self.source_reliabilities),
                'validation_count': len(self.validation_results),
                'correlation_count': len(self.correlation_strengths)
            },
            'metadata': {
                'confidence_factors': self.confidence_factors,
                'calculation_timestamp': self.calculation_timestamp.isoformat()
            }
        }


class SourceReliabilityManager:
    """Manages source reliability profiles and assessments."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize source reliability manager."""
        self.config = config or {}
        
        # Source reliability database (in production, this would be persistent)
        self.source_profiles: Dict[str, SourceReliability] = {}
        
        # Default reliability by source type
        self.default_reliabilities = {
            SourceType.GOVERNMENT: 0.85,
            SourceType.COMMERCIAL_FEED: 0.75,
            SourceType.HONEYPOT: 0.80,
            SourceType.SANDBOX: 0.70,
            SourceType.INTERNAL: 0.65,
            SourceType.COMMUNITY: 0.55,
            SourceType.OPEN_SOURCE: 0.50,
            SourceType.AUTOMATED: 0.45,
            SourceType.MANUAL: 0.60,
            SourceType.UNKNOWN: 0.30
        }
        
        logger.debug("Source reliability manager initialized")
    
    def get_source_reliability(self, source_name: str) -> SourceReliability:
        """Get reliability profile for a source."""
        
        if source_name in self.source_profiles:
            profile = self.source_profiles[source_name]
            # Update reliability score
            profile.calculate_reliability_score()
            return profile
        else:
            # Create default profile
            return self._create_default_profile(source_name)
    
    def update_source_reliability(self, 
                                source_name: str,
                                reliability_data: Dict[str, Any]) -> SourceReliability:
        """Update source reliability profile."""
        
        if source_name in self.source_profiles:
            profile = self.source_profiles[source_name]
        else:
            profile = self._create_default_profile(source_name)
        
        # Update profile with new data
        if 'accuracy_rate' in reliability_data:
            profile.accuracy_rate = reliability_data['accuracy_rate']
        if 'false_positive_rate' in reliability_data:
            profile.false_positive_rate = reliability_data['false_positive_rate']
        if 'true_positive_rate' in reliability_data:
            profile.true_positive_rate = reliability_data['true_positive_rate']
        if 'total_indicators_provided' in reliability_data:
            profile.total_indicators_provided = reliability_data['total_indicators_provided']
        
        # Recalculate reliability score
        profile.calculate_reliability_score()
        profile.last_updated = datetime.utcnow()
        
        # Store updated profile
        self.source_profiles[source_name] = profile
        
        return profile
    
    def _create_default_profile(self, source_name: str) -> SourceReliability:
        """Create default reliability profile for unknown source."""
        
        # Attempt to classify source type from name
        source_type = self._classify_source_type(source_name)
        default_reliability = self.default_reliabilities.get(source_type, 0.5)
        
        profile = SourceReliability(
            source_name=source_name,
            source_type=source_type,
            community_reputation=default_reliability,
            false_positive_rate=1.0 - default_reliability,
            true_positive_rate=default_reliability
        )
        
        profile.calculate_reliability_score()
        return profile
    
    def _classify_source_type(self, source_name: str) -> SourceType:
        """Classify source type from source name."""
        
        name_lower = source_name.lower()
        
        # Government sources
        if any(gov in name_lower for gov in ['cisa', 'nist', 'fbi', 'cert', 'ncsc', 'government']):
            return SourceType.GOVERNMENT
        
        # Commercial feeds
        elif any(comm in name_lower for comm in ['virustotal', 'crowdstrike', 'fireeye', 'mandiant', 'recorded_future']):
            return SourceType.COMMERCIAL_FEED
        
        # Honeypots
        elif any(honey in name_lower for honey in ['honeypot', 'cowrie', 'kippo', 'dionaea']):
            return SourceType.HONEYPOT
        
        # Sandboxes
        elif any(sand in name_lower for sand in ['sandbox', 'cuckoo', 'joe', 'falcon', 'wildfire']):
            return SourceType.SANDBOX
        
        # Community sources
        elif any(comm in name_lower for comm in ['misp', 'otx', 'threatminer', 'community']):
            return SourceType.COMMUNITY
        
        # Open source
        elif any(oss in name_lower for comm in ['github', 'malware-traffic', 'abuse.ch', 'urlvoid']):
            return SourceType.OPEN_SOURCE
        
        else:
            return SourceType.UNKNOWN
    
    def get_reliability_statistics(self) -> Dict[str, Any]:
        """Get reliability statistics."""
        
        if not self.source_profiles:
            return {'total_sources': 0}
        
        scores = [profile.reliability_score for profile in self.source_profiles.values()]
        
        return {
            'total_sources': len(self.source_profiles),
            'reliability_statistics': {
                'mean_reliability': statistics.mean(scores),
                'median_reliability': statistics.median(scores),
                'min_reliability': min(scores),
                'max_reliability': max(scores),
                'std_reliability': statistics.stdev(scores) if len(scores) > 1 else 0.0
            },
            'source_type_distribution': dict(Counter(
                profile.source_type.value for profile in self.source_profiles.values()
            ))
        }


class ValidationEngine:
    """Processes and analyzes validation results for confidence scoring."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize validation engine."""
        self.config = config or {}
        
        # Validation method weights (how much to trust each method)
        self.validation_weights = {
            ValidationMethod.EXPERT_REVIEW: 0.9,
            ValidationMethod.MANUAL_VERIFICATION: 0.85,
            ValidationMethod.BEHAVIORAL_ANALYSIS: 0.8,
            ValidationMethod.NETWORK_VALIDATION: 0.75,
            ValidationMethod.SANDBOX_EXECUTION: 0.7,
            ValidationMethod.CROSS_REFERENCE: 0.65,
            ValidationMethod.AUTOMATED_ANALYSIS: 0.6,
            ValidationMethod.COMMUNITY_VALIDATION: 0.5
        }
        
        logger.debug("Validation engine initialized")
    
    def calculate_validation_confidence(self, 
                                     validation_results: List[ValidationResult]) -> float:
        """Calculate confidence from validation results."""
        
        if not validation_results:
            return 0.5  # Default medium confidence
        
        # Calculate weighted validation score
        weighted_scores = []
        
        for result in validation_results:
            method_weight = self.validation_weights.get(result.validation_method, 0.5)
            
            # Adjust score based on validation outcome
            if result.is_confirmed:
                adjusted_score = result.validation_score * 1.2  # Boost for confirmation
            else:
                adjusted_score = result.validation_score * 0.8  # Penalty for non-confirmation
            
            # Consider evidence balance
            if result.evidence_count > 0:
                evidence_ratio = result.evidence_count / (result.evidence_count + result.contradicting_evidence)
                adjusted_score *= evidence_ratio
            
            # Apply false positive adjustment
            fp_adjustment = 1.0 - result.false_positive_likelihood
            adjusted_score *= fp_adjustment
            
            weighted_score = adjusted_score * method_weight
            weighted_scores.append(weighted_score)
        
        # Use maximum weighted score (optimistic approach)
        max_validation_confidence = max(weighted_scores) if weighted_scores else 0.5
        
        # Cap at reasonable limits
        return max(0.0, min(1.0, max_validation_confidence))
    
    def analyze_validation_consensus(self, 
                                   validation_results: List[ValidationResult]) -> Tuple[float, List[str]]:
        """Analyze consensus across validation results."""
        
        if len(validation_results) < 2:
            return 0.5, ["insufficient_validation"]
        
        # Calculate agreement metrics
        confirmations = sum(1 for result in validation_results if result.is_confirmed)
        total_validations = len(validation_results)
        confirmation_rate = confirmations / total_validations
        
        # Calculate score variance
        scores = [result.validation_score for result in validation_results]
        score_variance = statistics.variance(scores) if len(scores) > 1 else 0.0
        
        # Determine consensus strength
        consensus_factors = []
        
        if confirmation_rate >= 0.8:
            consensus_strength = 0.9
            consensus_factors.append("high_validation_consensus")
        elif confirmation_rate >= 0.6:
            consensus_strength = 0.7
            consensus_factors.append("moderate_validation_consensus")
        elif confirmation_rate >= 0.4:
            consensus_strength = 0.5
            consensus_factors.append("mixed_validation_results")
        else:
            consensus_strength = 0.3
            consensus_factors.append("low_validation_consensus")
        
        # Adjust for score consistency
        if score_variance < 0.1:
            consensus_factors.append("consistent_validation_scores")
            consensus_strength += 0.1
        elif score_variance > 0.3:
            consensus_factors.append("inconsistent_validation_scores")
            consensus_strength -= 0.1
        
        return max(0.0, min(1.0, consensus_strength)), consensus_factors


class CorrelationAnalyzer:
    """Analyzes correlation strength for confidence scoring."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize correlation analyzer."""
        self.config = config or {}
        
        # Correlation type weights
        self.correlation_weights = {
            'infrastructure': 0.8,    # Infrastructure correlations are strong
            'behavioral': 0.7,        # Behavioral patterns are reliable
            'temporal': 0.6,          # Time-based correlations
            'attribution': 0.9,       # Attribution correlations very strong
            'campaign': 0.85,         # Campaign correlations strong
            'family': 0.75,           # Malware family correlations
            'generic': 0.5            # Generic correlations
        }
        
        logger.debug("Correlation analyzer initialized")
    
    def calculate_correlation_confidence(self, 
                                       correlations: List[CorrelationStrength]) -> float:
        """Calculate confidence boost from correlations."""
        
        if not correlations:
            return 0.5  # Neutral confidence for no correlations
        
        # Calculate weighted correlation strength
        correlation_boosts = []
        
        for correlation in correlations:
            correlation.calculate_strength()
            
            # Get weight for correlation type
            type_weight = self.correlation_weights.get(correlation.correlation_type, 0.5)
            
            # Calculate boost from this correlation
            boost = correlation.confidence_boost * type_weight
            correlation_boosts.append(boost)
        
        # Aggregate correlation boosts (diminishing returns)
        if correlation_boosts:
            # Sort by strength (highest first)
            correlation_boosts.sort(reverse=True)
            
            # Apply diminishing returns
            total_boost = 0.0
            for i, boost in enumerate(correlation_boosts):
                # Each additional correlation has less impact
                diminishing_factor = 1.0 / (i + 1)
                total_boost += boost * diminishing_factor
            
            # Convert boost to confidence (base + boost)
            correlation_confidence = 0.5 + min(total_boost, 0.4)  # Max 40% boost
        else:
            correlation_confidence = 0.5
        
        return max(0.0, min(1.0, correlation_confidence))


class ConfidenceScoringEngine:
    """Main confidence scoring engine integrating all confidence factors."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize confidence scoring engine."""
        self.config = config or {}
        
        # Initialize components
        self.source_manager = SourceReliabilityManager(self.config.get('source_config', {}))
        self.validation_engine = ValidationEngine(self.config.get('validation_config', {}))
        self.correlation_analyzer = CorrelationAnalyzer(self.config.get('correlation_config', {}))
        
        # Confidence component weights
        self.component_weights = {
            'source_reliability': 0.35,    # 35% weight for source reliability
            'validation_results': 0.30,    # 30% weight for validation
            'correlation_strength': 0.20,  # 20% weight for correlations
            'cross_source_consistency': 0.15  # 15% weight for consistency
        }
        
        # Confidence decay parameters
        self.confidence_half_life = timedelta(days=60)  # Confidence halves after 60 days
        self.staleness_threshold = timedelta(days=180)  # Major penalty after 180 days
        
        logger.info("Confidence scoring engine initialized")
    
    def calculate_confidence_score(self, 
                                 indicator: NormalizedIndicator,
                                 validation_results: Optional[List[ValidationResult]] = None,
                                 correlation_data: Optional[List[CorrelationStrength]] = None) -> ConfidenceScore:
        """Calculate comprehensive confidence score for an indicator."""
        
        confidence_score = ConfidenceScore(indicator_id=indicator.id)
        
        # Extract source information
        sources = indicator.properties.get('sources', [])
        source_reliabilities = []
        
        for source_info in sources:
            if isinstance(source_info, dict):
                source_name = source_info.get('name', 'unknown')
                reliability = self.source_manager.get_source_reliability(source_name)
                source_reliabilities.append(reliability)
        
        confidence_score.source_reliabilities = source_reliabilities
        
        # Calculate source confidence
        if source_reliabilities:
            # Use weighted average of source reliabilities
            source_scores = [rel.reliability_score for rel in source_reliabilities]
            confidence_score.source_confidence = statistics.mean(source_scores)
            
            # Boost for multiple reliable sources
            if len(source_reliabilities) >= 3:
                multi_source_boost = min(len(source_reliabilities) * 0.02, 0.1)
                confidence_score.confidence_boosts.append(("multiple_sources", multi_source_boost))
        else:
            confidence_score.source_confidence = 0.3  # Low confidence for unknown sources
            confidence_score.confidence_penalties.append(("no_known_sources", -0.2))
        
        # Process validation results
        if validation_results:
            confidence_score.validation_results = validation_results
            confidence_score.validation_confidence = self.validation_engine.calculate_validation_confidence(validation_results)
            
            # Analyze validation consensus
            consensus_score, consensus_factors = self.validation_engine.analyze_validation_consensus(validation_results)
            confidence_score.consistency_confidence = consensus_score
            confidence_score.confidence_factors.extend(consensus_factors)
        else:
            # No validation results
            confidence_score.validation_confidence = 0.4
            confidence_score.consistency_confidence = 0.5
            confidence_score.confidence_factors.append("no_validation_performed")
        
        # Process correlation data
        if correlation_data:
            confidence_score.correlation_strengths = correlation_data
            confidence_score.correlation_confidence = self.correlation_analyzer.calculate_correlation_confidence(correlation_data)
            
            if confidence_score.correlation_confidence > 0.7:
                confidence_score.confidence_factors.append("strong_correlations")
            elif confidence_score.correlation_confidence > 0.5:
                confidence_score.confidence_factors.append("moderate_correlations")
        else:
            confidence_score.correlation_confidence = 0.5
            confidence_score.confidence_factors.append("no_correlations_analyzed")
        
        # Calculate base confidence score
        component_scores = [
            (confidence_score.source_confidence, self.component_weights['source_reliability']),
            (confidence_score.validation_confidence, self.component_weights['validation_results']),
            (confidence_score.correlation_confidence, self.component_weights['correlation_strength']),
            (confidence_score.consistency_confidence, self.component_weights['cross_source_consistency'])
        ]
        
        weighted_sum = sum(score * weight for score, weight in component_scores)
        total_weight = sum(weight for _, weight in component_scores)
        
        confidence_score.base_confidence_score = weighted_sum / total_weight if total_weight > 0 else 0.5
        
        # Apply temporal decay
        age = self._calculate_indicator_age(indicator)
        if age:
            confidence_score.confidence_decay_factor = self._calculate_confidence_decay(age)
            
            if age >= self.staleness_threshold:
                staleness_days = (age - self.staleness_threshold).days
                confidence_score.staleness_penalty = -min(staleness_days * 0.001, 0.2)  # Max 20% penalty
        
        # Apply boosts and penalties
        total_boosts = sum(boost for _, boost in confidence_score.confidence_boosts)
        total_penalties = sum(penalty for _, penalty in confidence_score.confidence_penalties)
        
        # Calculate final adjusted confidence score
        confidence_score.adjusted_confidence_score = (
            confidence_score.base_confidence_score * confidence_score.confidence_decay_factor +
            total_boosts +
            total_penalties +
            confidence_score.staleness_penalty
        )
        
        # Ensure score is in valid range
        confidence_score.adjusted_confidence_score = max(0.0, min(1.0, confidence_score.adjusted_confidence_score))
        
        # Determine confidence level
        confidence_score.confidence_level = self._determine_confidence_level(confidence_score.adjusted_confidence_score)
        
        # Add final confidence factors
        if confidence_score.adjusted_confidence_score >= 0.8:
            confidence_score.confidence_factors.append("high_confidence_indicator")
        elif confidence_score.adjusted_confidence_score <= 0.3:
            confidence_score.confidence_factors.append("low_confidence_indicator")
        
        return confidence_score
    
    def _calculate_indicator_age(self, indicator: NormalizedIndicator) -> Optional[timedelta]:
        """Calculate age of indicator for decay purposes."""
        
        # Use first_seen or creation time
        time_ref = indicator.first_seen or indicator.properties.get('created_time')
        
        if time_ref:
            try:
                ref_dt = datetime.fromisoformat(time_ref.replace('Z', '+00:00'))
                return datetime.utcnow() - ref_dt
            except:
                pass
        
        return None
    
    def _calculate_confidence_decay(self, age: timedelta) -> float:
        """Calculate confidence decay factor based on age."""
        
        if age <= timedelta(0):
            return 1.0
        
        # Exponential decay with configurable half-life
        lambda_val = math.log(2) / self.confidence_half_life.total_seconds()
        age_seconds = age.total_seconds()
        
        decay_factor = math.exp(-lambda_val * age_seconds)
        return max(0.1, decay_factor)  # Minimum 10% confidence retention
    
    def _determine_confidence_level(self, confidence_score: float) -> ConfidenceLevel:
        """Determine confidence level from score."""
        
        if confidence_score >= 0.9:
            return ConfidenceLevel.CONFIRMED
        elif confidence_score >= 0.7:
            return ConfidenceLevel.HIGH
        elif confidence_score >= 0.4:
            return ConfidenceLevel.MEDIUM
        elif confidence_score >= 0.1:
            return ConfidenceLevel.LOW
        else:
            return ConfidenceLevel.UNCONFIRMED
    
    def batch_calculate_confidence_scores(self, 
                                        indicators: List[NormalizedIndicator],
                                        validation_data: Optional[Dict[str, List[ValidationResult]]] = None,
                                        correlation_data: Optional[Dict[str, List[CorrelationStrength]]] = None) -> List[ConfidenceScore]:
        """Batch calculate confidence scores for multiple indicators."""
        
        logger.info(f"Batch confidence scoring for {len(indicators)} indicators")
        
        scores = []
        
        for i, indicator in enumerate(indicators):
            try:
                # Get validation and correlation data for this indicator
                validations = validation_data.get(indicator.id, []) if validation_data else None
                correlations = correlation_data.get(indicator.id, []) if correlation_data else None
                
                confidence_score = self.calculate_confidence_score(indicator, validations, correlations)
                scores.append(confidence_score)
                
                # Log progress for large batches
                if (i + 1) % 50 == 0:
                    logger.debug(f"Processed {i + 1}/{len(indicators)} confidence scores")
                    
            except Exception as e:
                logger.error(f"Confidence scoring failed for {indicator.id}: {e}")
                # Create minimal error score
                error_score = ConfidenceScore(indicator_id=indicator.id)
                error_score.confidence_factors.append("scoring_error")
                scores.append(error_score)
        
        logger.info(f"Confidence scoring completed for {len(scores)} indicators")
        return scores
    
    def get_confidence_statistics(self) -> Dict[str, Any]:
        """Get confidence scoring system statistics."""
        
        return {
            'components': {
                'source_manager': bool(self.source_manager),
                'validation_engine': bool(self.validation_engine),
                'correlation_analyzer': bool(self.correlation_analyzer)
            },
            'configuration': {
                'component_weights': self.component_weights,
                'confidence_half_life_days': self.confidence_half_life.days,
                'staleness_threshold_days': self.staleness_threshold.days
            },
            'source_statistics': self.source_manager.get_reliability_statistics()
        }
    
    def update_source_feedback(self, 
                             source_name: str,
                             feedback_data: Dict[str, Any]) -> None:
        """Update source reliability based on feedback."""
        
        logger.info(f"Updating source feedback for {source_name}")
        self.source_manager.update_source_reliability(source_name, feedback_data)