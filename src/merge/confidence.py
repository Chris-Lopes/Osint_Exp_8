"""
Confidence scoring framework for merge decisions.

This module implements sophisticated confidence scoring algorithms that help
determine which indicators should be merged, how to prioritize sources,
and what level of confidence to assign to merge decisions.
"""

import logging
import math
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, Counter

try:
    from ..normalizers.schema import NormalizedIndicator, IndicatorType, ConfidenceLevel, TLPMarking
    from .deduplication import DuplicateMatch, DuplicateConfidence, DuplicateMatchType
except ImportError:
    from normalizers.schema import NormalizedIndicator, IndicatorType, ConfidenceLevel, TLPMarking
    from merge.deduplication import DuplicateMatch, DuplicateConfidence, DuplicateMatchType

logger = logging.getLogger(__name__)


class MergeDecision(Enum):
    """Merge decision types."""
    MERGE = "merge"                    # High confidence merge
    CONDITIONAL_MERGE = "conditional"  # Merge with conditions
    NO_MERGE = "no_merge"             # Do not merge
    MANUAL_REVIEW = "manual_review"   # Requires human review


class SourcePrecedence(Enum):
    """Source precedence levels for merge conflicts."""
    PRIMARY = "primary"       # Highest precedence (government, premium feeds)
    SECONDARY = "secondary"   # Medium precedence (established commercial)
    TERTIARY = "tertiary"     # Lower precedence (open source, community)
    UNKNOWN = "unknown"       # Unknown or unranked source


@dataclass
class ConfidenceFactors:
    """Factors contributing to merge confidence."""
    
    source_reliability: float = 0.0      # 0.0 - 1.0
    temporal_consistency: float = 0.0    # 0.0 - 1.0
    enrichment_alignment: float = 0.0    # 0.0 - 1.0
    cross_validation: float = 0.0        # 0.0 - 1.0
    data_completeness: float = 0.0       # 0.0 - 1.0
    tag_consistency: float = 0.0         # 0.0 - 1.0
    
    def overall_confidence(self, weights: Optional[Dict[str, float]] = None) -> float:
        """Calculate overall confidence score."""
        if weights is None:
            weights = {
                'source_reliability': 0.25,
                'temporal_consistency': 0.15,
                'enrichment_alignment': 0.20,
                'cross_validation': 0.20,
                'data_completeness': 0.10,
                'tag_consistency': 0.10
            }
        
        return sum(
            getattr(self, factor) * weight 
            for factor, weight in weights.items()
        )


@dataclass
class MergeConfidenceScore:
    """Complete confidence assessment for merge decision."""
    
    decision: MergeDecision
    confidence_score: float              # 0.0 - 1.0
    confidence_factors: ConfidenceFactors
    primary_indicator_id: Optional[str] = None  # Which indicator should be primary
    merge_rationale: Optional[str] = None
    warnings: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'decision': self.decision.value,
            'confidence_score': self.confidence_score,
            'confidence_factors': {
                'source_reliability': self.confidence_factors.source_reliability,
                'temporal_consistency': self.confidence_factors.temporal_consistency,
                'enrichment_alignment': self.confidence_factors.enrichment_alignment,
                'cross_validation': self.confidence_factors.cross_validation,
                'data_completeness': self.confidence_factors.data_completeness,
                'tag_consistency': self.confidence_factors.tag_consistency,
                'overall': self.confidence_factors.overall_confidence()
            },
            'primary_indicator_id': self.primary_indicator_id,
            'merge_rationale': self.merge_rationale,
            'warnings': self.warnings,
            'created_at': self.created_at.isoformat()
        }


class SourceReliabilityScorer:
    """Scores source reliability for merge decisions."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize source reliability scorer."""
        self.config = config or {}
        
        # Default source precedence mapping
        self.source_precedence = self.config.get('source_precedence', {
            # Government and official sources
            'cisa': SourcePrecedence.PRIMARY,
            'nist': SourcePrecedence.PRIMARY,
            'mitre': SourcePrecedence.PRIMARY,
            
            # Premium commercial feeds
            'virustotal': SourcePrecedence.SECONDARY,
            'ibm_xforce': SourcePrecedence.SECONDARY,
            'crowdstrike': SourcePrecedence.SECONDARY,
            
            # Open source and community
            'otx': SourcePrecedence.TERTIARY,
            'phishtank': SourcePrecedence.TERTIARY,
            'urlhaus': SourcePrecedence.TERTIARY,
            'malwarebazaar': SourcePrecedence.TERTIARY
        })
        
        # Source confidence scores
        self.source_confidence = self.config.get('source_confidence', {})
        
    def score_source_reliability(self, indicators: List[NormalizedIndicator]) -> float:
        """Score the overall source reliability for a group of indicators."""
        if not indicators:
            return 0.0
        
        source_scores = []
        
        for indicator in indicators:
            try:
                source_name = indicator.source_metadata.source_name.lower()
                
                # Get precedence-based score
                precedence = self.source_precedence.get(source_name, SourcePrecedence.UNKNOWN)
                precedence_score = self._precedence_to_score(precedence)
                
                # Get explicit confidence if available
                explicit_confidence = self.source_confidence.get(source_name, 0.5)
                
                # Combine precedence and explicit confidence
                source_score = (precedence_score + explicit_confidence) / 2
                
                # Apply source-specific adjustments
                source_score = self._apply_source_adjustments(source_score, indicator)
                
                source_scores.append(source_score)
                
            except Exception as e:
                logger.warning(f"Failed to score source reliability for {indicator.id}: {e}")
                source_scores.append(0.3)  # Default low score
        
        # Return weighted average (higher weight for higher scores)
        if source_scores:
            weights = [score ** 2 for score in source_scores]  # Quadratic weighting
            weighted_avg = sum(s * w for s, w in zip(source_scores, weights)) / sum(weights)
            return min(1.0, weighted_avg)
        
        return 0.0
    
    def _precedence_to_score(self, precedence: SourcePrecedence) -> float:
        """Convert precedence level to numeric score."""
        mapping = {
            SourcePrecedence.PRIMARY: 0.9,
            SourcePrecedence.SECONDARY: 0.7,
            SourcePrecedence.TERTIARY: 0.5,
            SourcePrecedence.UNKNOWN: 0.3
        }
        return mapping[precedence]
    
    def _apply_source_adjustments(self, base_score: float, 
                                indicator: NormalizedIndicator) -> float:
        """Apply source-specific adjustments to base score."""
        adjusted_score = base_score
        
        try:
            # Adjust based on source confidence field
            source_confidence = getattr(indicator.source_metadata, 'source_confidence', None)
            if source_confidence is not None:
                # Normalize source confidence (0-100 to 0-1)
                normalized_confidence = source_confidence / 100.0
                adjusted_score = (adjusted_score + normalized_confidence) / 2
            
            # Adjust based on indicator confidence
            if hasattr(indicator, 'confidence'):
                indicator_confidence = indicator.confidence / 100.0
                adjusted_score = (adjusted_score + indicator_confidence) / 2
            
            # Adjust based on TLP marking (higher for more restricted)
            if hasattr(indicator, 'tlp_marking'):
                tlp_adjustment = self._get_tlp_adjustment(indicator.tlp_marking)
                adjusted_score *= tlp_adjustment
            
        except Exception as e:
            logger.warning(f"Failed to apply source adjustments: {e}")
        
        return min(1.0, max(0.0, adjusted_score))
    
    def _get_tlp_adjustment(self, tlp_marking: TLPMarking) -> float:
        """Get TLP-based reliability adjustment."""
        adjustments = {
            TLPMarking.RED: 1.2,      # More restrictive = higher reliability
            TLPMarking.AMBER: 1.1,
            TLPMarking.GREEN: 1.0,
            TLPMarking.WHITE: 0.9     # Public = slightly lower reliability
        }
        return adjustments.get(tlp_marking, 1.0)


class TemporalConsistencyScorer:
    """Scores temporal consistency for merge decisions."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize temporal consistency scorer."""
        self.config = config or {}
        self.max_time_diff = timedelta(
            days=self.config.get('max_time_diff_days', 30)
        )
        self.optimal_time_diff = timedelta(
            hours=self.config.get('optimal_time_diff_hours', 24)
        )
    
    def score_temporal_consistency(self, indicators: List[NormalizedIndicator]) -> float:
        """Score temporal consistency of indicators."""
        if len(indicators) < 2:
            return 1.0
        
        timestamps = []
        
        for indicator in indicators:
            try:
                # Get creation timestamp
                if hasattr(indicator, 'created') and indicator.created:
                    timestamp = indicator.created
                    if isinstance(timestamp, str):
                        timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    timestamps.append(timestamp)
                    
            except Exception as e:
                logger.warning(f"Failed to parse timestamp for {indicator.id}: {e}")
        
        if len(timestamps) < 2:
            return 0.5  # Neutral score if we can't compare
        
        # Calculate temporal consistency
        return self._calculate_consistency_score(timestamps)
    
    def _calculate_consistency_score(self, timestamps: List[datetime]) -> float:
        """Calculate consistency score from timestamps."""
        # Find time span
        min_time = min(timestamps)
        max_time = max(timestamps)
        time_span = max_time - min_time
        
        # Score based on time span
        if time_span <= self.optimal_time_diff:
            # Very close in time = high consistency
            return 1.0
        elif time_span <= self.max_time_diff:
            # Within acceptable range = decreasing consistency
            ratio = time_span.total_seconds() / self.max_time_diff.total_seconds()
            return max(0.3, 1.0 - ratio)
        else:
            # Too far apart = low consistency
            return 0.2
        
        return 0.5


class EnrichmentAlignmentScorer:
    """Scores enrichment data alignment for merge decisions."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize enrichment alignment scorer."""
        self.config = config or {}
        
    def score_enrichment_alignment(self, indicators: List[NormalizedIndicator]) -> float:
        """Score alignment of enrichment data across indicators."""
        if len(indicators) < 2:
            return 1.0
        
        alignment_scores = []
        
        # Compare reputation data
        rep_score = self._score_reputation_alignment(indicators)
        if rep_score is not None:
            alignment_scores.append(rep_score)
        
        # Compare geolocation data
        geo_score = self._score_geolocation_alignment(indicators)
        if geo_score is not None:
            alignment_scores.append(geo_score)
        
        # Compare ASN data
        asn_score = self._score_asn_alignment(indicators)
        if asn_score is not None:
            alignment_scores.append(asn_score)
        
        # Return average of available scores
        if alignment_scores:
            return sum(alignment_scores) / len(alignment_scores)
        
        return 0.5  # Neutral if no enrichment data
    
    def _score_reputation_alignment(self, indicators: List[NormalizedIndicator]) -> Optional[float]:
        """Score reputation data alignment."""
        reputation_data = []
        
        for indicator in indicators:
            try:
                enrichment = indicator.context.get('enrichment', {})
                reputation = enrichment.get('reputation', {})
                
                if reputation:
                    reputation_data.append({
                        'score': reputation.get('reputation_score', 0),
                        'is_malicious': reputation.get('is_malicious', False),
                        'category': reputation.get('category', '')
                    })
            except Exception:
                continue
        
        if len(reputation_data) < 2:
            return None
        
        # Calculate alignment
        scores = [r['score'] for r in reputation_data]
        malicious_flags = [r['is_malicious'] for r in reputation_data]
        categories = [r['category'] for r in reputation_data if r['category']]
        
        alignment = 0.0
        
        # Score alignment (normalized to -100 to 100 range)
        if scores:
            score_variance = self._calculate_normalized_variance([
                (s + 100) / 200 for s in scores  # Normalize to 0-1
            ])
            alignment += 1.0 - score_variance
        
        # Malicious flag consistency
        if malicious_flags:
            consistent_flags = len(set(malicious_flags)) == 1
            alignment += 1.0 if consistent_flags else 0.0
        
        # Category consistency
        if categories:
            consistent_categories = len(set(categories)) == 1
            alignment += 1.0 if consistent_categories else 0.5
        
        return alignment / 3.0  # Average of three factors
    
    def _score_geolocation_alignment(self, indicators: List[NormalizedIndicator]) -> Optional[float]:
        """Score geolocation data alignment."""
        geo_data = []
        
        for indicator in indicators:
            try:
                enrichment = indicator.context.get('enrichment', {})
                geo = enrichment.get('geolocation', {})
                
                if geo:
                    geo_data.append({
                        'country': geo.get('country', ''),
                        'city': geo.get('city', ''),
                        'latitude': geo.get('latitude'),
                        'longitude': geo.get('longitude')
                    })
            except Exception:
                continue
        
        if len(geo_data) < 2:
            return None
        
        # Check country consistency
        countries = [g['country'] for g in geo_data if g['country']]
        if countries:
            consistent_countries = len(set(countries)) == 1
            return 1.0 if consistent_countries else 0.3
        
        return 0.5
    
    def _score_asn_alignment(self, indicators: List[NormalizedIndicator]) -> Optional[float]:
        """Score ASN data alignment."""
        asn_data = []
        
        for indicator in indicators:
            try:
                enrichment = indicator.context.get('enrichment', {})
                asn = enrichment.get('asn', {})
                
                if asn:
                    asn_data.append({
                        'asn_number': asn.get('asn_number'),
                        'org_name': asn.get('org_name', '')
                    })
            except Exception:
                continue
        
        if len(asn_data) < 2:
            return None
        
        # Check ASN number consistency
        asn_numbers = [a['asn_number'] for a in asn_data if a['asn_number']]
        if asn_numbers:
            consistent_asns = len(set(asn_numbers)) == 1
            return 1.0 if consistent_asns else 0.2
        
        return 0.5
    
    def _calculate_normalized_variance(self, values: List[float]) -> float:
        """Calculate normalized variance (0-1 range)."""
        if len(values) < 2:
            return 0.0
        
        mean_val = sum(values) / len(values)
        variance = sum((v - mean_val) ** 2 for v in values) / len(values)
        
        # Normalize variance to 0-1 range
        # Maximum possible variance is 0.25 (when values are at 0 and 1)
        return min(1.0, variance / 0.25)


class CrossValidationScorer:
    """Scores cross-validation evidence for merge decisions."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize cross-validation scorer."""
        self.config = config or {}
    
    def score_cross_validation(self, indicators: List[NormalizedIndicator]) -> float:
        """Score cross-validation evidence across indicators."""
        if len(indicators) < 2:
            return 0.5
        
        # Count unique sources
        sources = set()
        for indicator in indicators:
            try:
                source_name = indicator.source_metadata.source_name
                sources.add(source_name)
            except Exception:
                continue
        
        # More sources = better cross-validation
        num_sources = len(sources)
        
        if num_sources >= 3:
            return 1.0  # Excellent cross-validation
        elif num_sources == 2:
            return 0.8  # Good cross-validation
        else:
            return 0.3  # Limited cross-validation


class DataCompletenessScorer:
    """Scores data completeness for merge decisions."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize data completeness scorer."""
        self.config = config or {}
    
    def score_data_completeness(self, indicators: List[NormalizedIndicator]) -> float:
        """Score overall data completeness of indicators."""
        if not indicators:
            return 0.0
        
        completeness_scores = []
        
        for indicator in indicators:
            score = self._score_individual_completeness(indicator)
            completeness_scores.append(score)
        
        # Return average completeness
        return sum(completeness_scores) / len(completeness_scores)
    
    def _score_individual_completeness(self, indicator: NormalizedIndicator) -> float:
        """Score completeness of individual indicator."""
        total_fields = 0
        populated_fields = 0
        
        # Core fields
        fields_to_check = [
            'value', 'indicator_type', 'confidence', 'tags',
            'threat_types', 'created', 'source_metadata'
        ]
        
        for field in fields_to_check:
            total_fields += 1
            if hasattr(indicator, field):
                value = getattr(indicator, field)
                if value is not None and value != [] and value != {}:
                    populated_fields += 1
        
        # Enrichment completeness
        enrichment = indicator.context.get('enrichment', {})
        if enrichment:
            populated_fields += 0.5  # Bonus for having enrichment
            
            # Check enrichment subfields
            enrichment_fields = ['reputation', 'geolocation', 'asn', 'dns']
            for field in enrichment_fields:
                if field in enrichment and enrichment[field]:
                    populated_fields += 0.1
        
        return min(1.0, populated_fields / total_fields)


class TagConsistencyScorer:
    """Scores tag consistency for merge decisions."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize tag consistency scorer."""
        self.config = config or {}
    
    def score_tag_consistency(self, indicators: List[NormalizedIndicator]) -> float:
        """Score tag consistency across indicators."""
        if len(indicators) < 2:
            return 1.0
        
        all_tags = []
        for indicator in indicators:
            if hasattr(indicator, 'tags') and indicator.tags:
                all_tags.extend([tag.lower() for tag in indicator.tags])
        
        if not all_tags:
            return 0.5  # Neutral if no tags
        
        # Calculate tag overlap
        tag_counts = Counter(all_tags)
        total_tags = len(all_tags)
        num_indicators = len(indicators)
        
        # Tags that appear in multiple indicators
        shared_tags = sum(1 for count in tag_counts.values() if count > 1)
        
        # Consistency score based on shared tags ratio
        if total_tags > 0:
            consistency = shared_tags / len(tag_counts)
            return min(1.0, consistency * 2)  # Amplify the score
        
        return 0.5


class MergeConfidenceEngine:
    """Main engine for calculating merge confidence scores."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize merge confidence engine."""
        self.config = config or {}
        
        # Initialize scorers
        self.source_scorer = SourceReliabilityScorer(self.config.get('source_scoring', {}))
        self.temporal_scorer = TemporalConsistencyScorer(self.config.get('temporal_scoring', {}))
        self.enrichment_scorer = EnrichmentAlignmentScorer(self.config.get('enrichment_scoring', {}))
        self.cross_validation_scorer = CrossValidationScorer(self.config.get('cross_validation_scoring', {}))
        self.completeness_scorer = DataCompletenessScorer(self.config.get('completeness_scoring', {}))
        self.tag_scorer = TagConsistencyScorer(self.config.get('tag_scoring', {}))
        
        # Decision thresholds
        self.merge_threshold = self.config.get('merge_threshold', 0.8)
        self.conditional_threshold = self.config.get('conditional_threshold', 0.6)
        self.manual_review_threshold = self.config.get('manual_review_threshold', 0.4)
        
        logger.info("Merge confidence engine initialized")
    
    def calculate_merge_confidence(self, duplicate_match: DuplicateMatch,
                                 indicators: List[NormalizedIndicator]) -> MergeConfidenceScore:
        """Calculate comprehensive merge confidence score."""
        
        # Filter indicators for this match
        match_indicators = [
            ind for ind in indicators 
            if ind.id in {duplicate_match.indicator1_id, duplicate_match.indicator2_id}
        ]
        
        if len(match_indicators) != 2:
            logger.warning(f"Expected 2 indicators for match, got {len(match_indicators)}")
            return self._create_low_confidence_score("Insufficient indicators")
        
        # Calculate confidence factors
        factors = ConfidenceFactors()
        
        factors.source_reliability = self.source_scorer.score_source_reliability(match_indicators)
        factors.temporal_consistency = self.temporal_scorer.score_temporal_consistency(match_indicators)
        factors.enrichment_alignment = self.enrichment_scorer.score_enrichment_alignment(match_indicators)
        factors.cross_validation = self.cross_validation_scorer.score_cross_validation(match_indicators)
        factors.data_completeness = self.completeness_scorer.score_data_completeness(match_indicators)
        factors.tag_consistency = self.tag_scorer.score_tag_consistency(match_indicators)
        
        # Calculate overall confidence
        overall_confidence = factors.overall_confidence()
        
        # Adjust based on duplicate match confidence
        match_confidence_weight = self._get_match_confidence_weight(duplicate_match.confidence_level)
        adjusted_confidence = (overall_confidence + duplicate_match.confidence_score * match_confidence_weight) / 2
        
        # Determine decision
        decision = self._determine_merge_decision(adjusted_confidence, duplicate_match, match_indicators)
        
        # Select primary indicator
        primary_id = self._select_primary_indicator(match_indicators)
        
        # Generate rationale
        rationale = self._generate_merge_rationale(decision, factors, duplicate_match)
        
        # Generate warnings
        warnings = self._generate_warnings(factors, duplicate_match, match_indicators)
        
        return MergeConfidenceScore(
            decision=decision,
            confidence_score=adjusted_confidence,
            confidence_factors=factors,
            primary_indicator_id=primary_id,
            merge_rationale=rationale,
            warnings=warnings
        )
    
    def _get_match_confidence_weight(self, confidence_level: DuplicateConfidence) -> float:
        """Get weight for duplicate match confidence."""
        weights = {
            DuplicateConfidence.CERTAIN: 1.0,
            DuplicateConfidence.HIGH: 0.8,
            DuplicateConfidence.MODERATE: 0.6,
            DuplicateConfidence.LOW: 0.4,
            DuplicateConfidence.WEAK: 0.2
        }
        return weights.get(confidence_level, 0.5)
    
    def _determine_merge_decision(self, confidence_score: float, 
                                duplicate_match: DuplicateMatch,
                                indicators: List[NormalizedIndicator]) -> MergeDecision:
        """Determine merge decision based on confidence score."""
        
        # High confidence = merge
        if confidence_score >= self.merge_threshold:
            return MergeDecision.MERGE
        
        # Medium confidence = conditional merge
        elif confidence_score >= self.conditional_threshold:
            return MergeDecision.CONDITIONAL_MERGE
        
        # Low but not negligible = manual review
        elif confidence_score >= self.manual_review_threshold:
            return MergeDecision.MANUAL_REVIEW
        
        # Very low confidence = no merge
        else:
            return MergeDecision.NO_MERGE
    
    def _select_primary_indicator(self, indicators: List[NormalizedIndicator]) -> str:
        """Select primary indicator for merge."""
        if len(indicators) != 2:
            return indicators[0].id if indicators else ""
        
        # Score each indicator
        scores = []
        for indicator in indicators:
            score = 0.0
            
            # Source precedence
            try:
                source_name = indicator.source_metadata.source_name.lower()
                precedence = self.source_scorer.source_precedence.get(
                    source_name, SourcePrecedence.UNKNOWN
                )
                score += self.source_scorer._precedence_to_score(precedence) * 0.4
            except Exception:
                pass
            
            # Data completeness
            completeness = self.completeness_scorer._score_individual_completeness(indicator)
            score += completeness * 0.3
            
            # Confidence level
            if hasattr(indicator, 'confidence'):
                score += (indicator.confidence / 100.0) * 0.2
            
            # Recency (newer is better)
            try:
                created = indicator.created
                if isinstance(created, str):
                    created = datetime.fromisoformat(created.replace('Z', '+00:00'))
                
                age_days = (datetime.utcnow() - created).days
                recency_score = max(0, 1.0 - (age_days / 365))  # Decay over a year
                score += recency_score * 0.1
            except Exception:
                pass
            
            scores.append((indicator.id, score))
        
        # Return ID of highest scoring indicator
        scores.sort(key=lambda x: x[1], reverse=True)
        return scores[0][0]
    
    def _generate_merge_rationale(self, decision: MergeDecision, 
                                factors: ConfidenceFactors,
                                duplicate_match: DuplicateMatch) -> str:
        """Generate human-readable rationale for merge decision."""
        
        rationale_parts = []
        
        # Decision explanation
        if decision == MergeDecision.MERGE:
            rationale_parts.append("High confidence merge recommended")
        elif decision == MergeDecision.CONDITIONAL_MERGE:
            rationale_parts.append("Conditional merge with monitoring")
        elif decision == MergeDecision.MANUAL_REVIEW:
            rationale_parts.append("Manual review required")
        else:
            rationale_parts.append("Merge not recommended")
        
        # Key factors
        if factors.source_reliability > 0.8:
            rationale_parts.append("high source reliability")
        elif factors.source_reliability < 0.4:
            rationale_parts.append("low source reliability")
        
        if factors.cross_validation > 0.8:
            rationale_parts.append("strong cross-validation")
        
        if factors.enrichment_alignment > 0.8:
            rationale_parts.append("aligned enrichment data")
        elif factors.enrichment_alignment < 0.4:
            rationale_parts.append("conflicting enrichment data")
        
        # Match type
        match_type_desc = {
            DuplicateMatchType.EXACT_VALUE: "exact value match",
            DuplicateMatchType.SEMANTIC_EQUIVALENT: "semantic equivalence",
            DuplicateMatchType.CONTEXTUAL_SIMILAR: "contextual similarity",
            DuplicateMatchType.TEMPORAL_CLUSTER: "temporal clustering",
            DuplicateMatchType.ENRICHMENT_LINKED: "enrichment linkage"
        }
        
        rationale_parts.append(f"based on {match_type_desc[duplicate_match.match_type]}")
        
        return "; ".join(rationale_parts).capitalize()
    
    def _generate_warnings(self, factors: ConfidenceFactors, 
                         duplicate_match: DuplicateMatch,
                         indicators: List[NormalizedIndicator]) -> List[str]:
        """Generate warnings for merge decision."""
        warnings = []
        
        # Source reliability warnings
        if factors.source_reliability < 0.4:
            warnings.append("Low source reliability detected")
        
        # Temporal consistency warnings
        if factors.temporal_consistency < 0.3:
            warnings.append("Indicators are significantly separated in time")
        
        # Enrichment alignment warnings
        if factors.enrichment_alignment < 0.4:
            warnings.append("Conflicting enrichment data detected")
        
        # Cross-validation warnings
        if factors.cross_validation < 0.3:
            warnings.append("Limited cross-validation from multiple sources")
        
        # TLP marking conflicts
        tlp_markings = set()
        for indicator in indicators:
            if hasattr(indicator, 'tlp_marking'):
                tlp_markings.add(indicator.tlp_marking)
        
        if len(tlp_markings) > 1:
            warnings.append("Conflicting TLP markings detected")
        
        # Confidence level conflicts
        confidences = []
        for indicator in indicators:
            if hasattr(indicator, 'confidence_level'):
                confidences.append(indicator.confidence_level)
        
        if len(set(confidences)) > 1:
            warnings.append("Conflicting confidence levels detected")
        
        return warnings
    
    def _create_low_confidence_score(self, reason: str) -> MergeConfidenceScore:
        """Create a low confidence score with explanation."""
        return MergeConfidenceScore(
            decision=MergeDecision.NO_MERGE,
            confidence_score=0.1,
            confidence_factors=ConfidenceFactors(),
            merge_rationale=f"Low confidence: {reason}",
            warnings=[reason]
        )