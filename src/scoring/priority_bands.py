"""
Priority band classification system for threat intelligence scoring.

This module implements sophisticated priority band classification with P1-P4 bands,
escalation thresholds, dynamic adjustment capabilities, and operational response 
mapping for SOC workflows.
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
    from .engine import ThreatScore, PriorityBand, ThreatCategory
    from .risk_assessment import RiskLevel
except ImportError:
    from normalizers.schema import NormalizedIndicator, IndicatorType
    from scoring.engine import ThreatScore, PriorityBand, ThreatCategory
    from scoring.risk_assessment import RiskLevel

logger = logging.getLogger(__name__)


class EscalationTrigger(Enum):
    """Escalation trigger types."""
    HIGH_VOLUME = "high_volume"
    CRITICAL_CVE = "critical_cve"
    APT_ATTRIBUTION = "apt_attribution"
    ACTIVE_EXPLOITATION = "active_exploitation"
    INFRASTRUCTURE_CORRELATION = "infrastructure_correlation"
    CAMPAIGN_DETECTION = "campaign_detection"
    ZERO_DAY = "zero_day"
    RANSOMWARE_FAMILY = "ransomware_family"
    CRITICAL_ASSET = "critical_asset"
    MULTIPLE_SOURCES = "multiple_sources"


class ResponseAction(Enum):
    """SOC response actions."""
    IMMEDIATE_INVESTIGATION = "immediate_investigation"
    HUNT_DEPLOYMENT = "hunt_deployment"
    IOC_DEPLOYMENT = "ioc_deployment"
    ALERT_CREATION = "alert_creation"
    MONITORING_ENHANCEMENT = "monitoring_enhancement"
    INTELLIGENCE_COLLECTION = "intelligence_collection"
    STAKEHOLDER_NOTIFICATION = "stakeholder_notification"
    AUTOMATED_BLOCKING = "automated_blocking"
    MANUAL_REVIEW = "manual_review"
    DOCUMENTATION_UPDATE = "documentation_update"


@dataclass
class PriorityBandConfiguration:
    """Configuration for priority band classification."""
    
    # Score thresholds for bands
    p1_threshold: float = 0.85    # Critical (85-100%)
    p2_threshold: float = 0.65    # High (65-84%)
    p3_threshold: float = 0.35    # Medium (35-64%)
    p4_threshold: float = 0.0     # Low (0-34%)
    
    # Risk level multipliers
    risk_level_multipliers: Dict[RiskLevel, float] = field(default_factory=lambda: {
        RiskLevel.CRITICAL: 1.3,
        RiskLevel.HIGH: 1.1,
        RiskLevel.MEDIUM: 1.0,
        RiskLevel.LOW: 0.9,
        RiskLevel.MINIMAL: 0.8
    })
    
    # Escalation trigger weights
    escalation_weights: Dict[EscalationTrigger, float] = field(default_factory=lambda: {
        EscalationTrigger.ZERO_DAY: 0.3,
        EscalationTrigger.ACTIVE_EXPLOITATION: 0.25,
        EscalationTrigger.CRITICAL_CVE: 0.2,
        EscalationTrigger.APT_ATTRIBUTION: 0.2,
        EscalationTrigger.RANSOMWARE_FAMILY: 0.2,
        EscalationTrigger.CAMPAIGN_DETECTION: 0.15,
        EscalationTrigger.CRITICAL_ASSET: 0.15,
        EscalationTrigger.INFRASTRUCTURE_CORRELATION: 0.1,
        EscalationTrigger.HIGH_VOLUME: 0.1,
        EscalationTrigger.MULTIPLE_SOURCES: 0.05
    })
    
    # Time-based adjustments
    temporal_adjustments: Dict[str, float] = field(default_factory=lambda: {
        'recent_activity_boost': 0.1,      # Last 24 hours
        'trending_boost': 0.05,            # Increasing observations
        'stale_penalty': -0.1,             # No activity >30 days
        'aged_penalty': -0.05              # No activity >7 days
    })
    
    # Volume-based adjustments
    volume_thresholds: Dict[str, Tuple[int, float]] = field(default_factory=lambda: {
        'high_volume': (100, 0.1),         # 100+ indicators = +0.1
        'medium_volume': (20, 0.05),       # 20+ indicators = +0.05
        'low_volume': (5, 0.0)             # 5+ indicators = no change
    })


@dataclass
class PriorityAssignment:
    """Priority band assignment result."""
    
    indicator_id: str
    original_score: float
    adjusted_score: float
    priority_band: PriorityBand
    
    # Adjustment factors
    risk_multiplier: float = 1.0
    escalation_boost: float = 0.0
    temporal_adjustment: float = 0.0
    volume_adjustment: float = 0.0
    
    # Triggered escalations
    escalation_triggers: List[EscalationTrigger] = field(default_factory=list)
    
    # Response recommendations
    response_actions: List[ResponseAction] = field(default_factory=list)
    
    # Metadata
    assignment_reasoning: List[str] = field(default_factory=list)
    assignment_timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'indicator_id': self.indicator_id,
            'scoring': {
                'original_score': self.original_score,
                'adjusted_score': self.adjusted_score,
                'priority_band': self.priority_band.value
            },
            'adjustments': {
                'risk_multiplier': self.risk_multiplier,
                'escalation_boost': self.escalation_boost,
                'temporal_adjustment': self.temporal_adjustment,
                'volume_adjustment': self.volume_adjustment
            },
            'escalation': {
                'triggered_escalations': [trigger.value for trigger in self.escalation_triggers],
                'response_actions': [action.value for action in self.response_actions]
            },
            'metadata': {
                'assignment_reasoning': self.assignment_reasoning,
                'assignment_timestamp': self.assignment_timestamp.isoformat()
            }
        }


@dataclass
class BandStatistics:
    """Statistics for a priority band."""
    
    band: PriorityBand
    indicator_count: int = 0
    
    # Score statistics
    min_score: float = 0.0
    max_score: float = 0.0
    mean_score: float = 0.0
    median_score: float = 0.0
    
    # Escalation statistics
    escalation_count: int = 0
    common_triggers: List[Tuple[EscalationTrigger, int]] = field(default_factory=list)
    
    # Response statistics
    response_distribution: Dict[ResponseAction, int] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'band': self.band.value,
            'counts': {
                'indicator_count': self.indicator_count,
                'escalation_count': self.escalation_count
            },
            'score_statistics': {
                'min_score': self.min_score,
                'max_score': self.max_score,
                'mean_score': self.mean_score,
                'median_score': self.median_score
            },
            'escalations': {
                'common_triggers': [(trigger.value, count) for trigger, count in self.common_triggers]
            },
            'responses': {
                action.value: count for action, count in self.response_distribution.items()
            }
        }


class EscalationDetector:
    """Detects escalation triggers for priority adjustment."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize escalation detector."""
        self.config = config or {}
        
        # CVE patterns for critical escalation
        self.critical_cve_patterns = [
            'zero.day', 'zero day', '0day', 'remote code execution',
            'unauthenticated', 'critical', 'wormable'
        ]
        
        # APT group indicators
        self.apt_indicators = [
            'apt', 'lazarus', 'cozy bear', 'fancy bear', 'carbanak',
            'equation group', 'sandworm', 'turla', 'winnti'
        ]
        
        # Ransomware family patterns
        self.ransomware_patterns = [
            'ransomware', 'crypto', 'locker', 'ryuk', 'maze',
            'sodinokibi', 'conti', 'lockbit', 'revil'
        ]
        
        logger.debug("Escalation detector initialized")
    
    def detect_escalations(self, 
                         indicator: NormalizedIndicator,
                         threat_score: ThreatScore,
                         risk_assessment: Dict[str, Any]) -> List[EscalationTrigger]:
        """Detect escalation triggers for an indicator."""
        
        triggers = []
        
        try:
            # Check for zero-day indicators
            if self._is_zero_day(indicator, threat_score):
                triggers.append(EscalationTrigger.ZERO_DAY)
            
            # Check for active exploitation
            if self._has_active_exploitation(indicator, threat_score):
                triggers.append(EscalationTrigger.ACTIVE_EXPLOITATION)
            
            # Check for critical CVEs
            if self._has_critical_cve(indicator, threat_score):
                triggers.append(EscalationTrigger.CRITICAL_CVE)
            
            # Check for APT attribution
            if self._has_apt_attribution(indicator, threat_score):
                triggers.append(EscalationTrigger.APT_ATTRIBUTION)
            
            # Check for ransomware family
            if self._is_ransomware_family(indicator, threat_score):
                triggers.append(EscalationTrigger.RANSOMWARE_FAMILY)
            
            # Check for campaign detection
            if self._is_campaign_indicator(indicator, threat_score):
                triggers.append(EscalationTrigger.CAMPAIGN_DETECTION)
            
            # Check for critical asset targeting
            if self._targets_critical_assets(indicator, threat_score):
                triggers.append(EscalationTrigger.CRITICAL_ASSET)
            
            # Check for infrastructure correlation
            if self._has_infrastructure_correlation(indicator, threat_score):
                triggers.append(EscalationTrigger.INFRASTRUCTURE_CORRELATION)
            
            # Check for multiple sources
            if self._has_multiple_sources(indicator, threat_score):
                triggers.append(EscalationTrigger.MULTIPLE_SOURCES)
            
        except Exception as e:
            logger.error(f"Escalation detection failed: {e}")
        
        return triggers
    
    def _is_zero_day(self, indicator: NormalizedIndicator, threat_score: ThreatScore) -> bool:
        """Check if indicator is related to zero-day exploitation."""
        
        # Check tags and properties
        tags = indicator.properties.get('tags', [])
        description = indicator.properties.get('description', '').lower()
        
        zero_day_keywords = any(
            keyword in tag.lower() or keyword in description
            for keyword in ['zero-day', '0-day', 'zero day', '0day']
            for tag in tags
        )
        
        # Check CVE data for recent critical vulnerabilities
        cve_data = indicator.properties.get('cve_data', {})
        for cve_id, cve_info in cve_data.items():
            published = cve_info.get('published_date')
            if published:
                try:
                    pub_date = datetime.fromisoformat(published.replace('Z', '+00:00'))
                    if (datetime.utcnow() - pub_date) <= timedelta(days=7):
                        cvss_score = cve_info.get('cvss_v3_score', 0)
                        if cvss_score >= 9.0:
                            return True
                except:
                    pass
        
        return zero_day_keywords
    
    def _has_active_exploitation(self, indicator: NormalizedIndicator, threat_score: ThreatScore) -> bool:
        """Check if indicator shows active exploitation."""
        
        # Check for exploitation indicators
        properties = indicator.properties
        
        # Direct exploitation flags
        if properties.get('in_wild_exploitation') or properties.get('weaponized'):
            return True
        
        # Check recent activity
        last_seen = properties.get('last_seen')
        if last_seen:
            try:
                last_date = datetime.fromisoformat(last_seen.replace('Z', '+00:00'))
                if (datetime.utcnow() - last_date) <= timedelta(hours=24):
                    return True
            except:
                pass
        
        # Check for exploitation-related tags
        tags = properties.get('tags', [])
        exploitation_tags = ['exploit', 'weaponized', 'active', 'exploit-kit']
        
        return any(exploit_tag in tag.lower() for tag in tags for exploit_tag in exploitation_tags)
    
    def _has_critical_cve(self, indicator: NormalizedIndicator, threat_score: ThreatScore) -> bool:
        """Check if indicator has critical CVE."""
        
        cve_data = indicator.properties.get('cve_data', {})
        
        for cve_id, cve_info in cve_data.items():
            # Check CVSS score
            cvss_score = cve_info.get('cvss_v3_score', 0)
            if cvss_score >= 8.5:
                return True
            
            # Check description for critical patterns
            description = cve_info.get('description', '').lower()
            if any(pattern in description for pattern in self.critical_cve_patterns):
                return True
        
        return False
    
    def _has_apt_attribution(self, indicator: NormalizedIndicator, threat_score: ThreatScore) -> bool:
        """Check if indicator is attributed to APT groups."""
        
        # Check attribution in properties
        attribution = indicator.properties.get('attribution', [])
        if attribution:
            return True
        
        # Check tags for APT indicators
        tags = indicator.properties.get('tags', [])
        
        for tag in tags:
            tag_lower = tag.lower()
            if any(apt in tag_lower for apt in self.apt_indicators):
                return True
        
        # Check malware data for sophistication
        malware_data = indicator.properties.get('malware_data', {})
        for family, data in malware_data.items():
            sophistication = data.get('sophistication_level', '').lower()
            if sophistication in ['high', 'advanced']:
                return True
        
        return False
    
    def _is_ransomware_family(self, indicator: NormalizedIndicator, threat_score: ThreatScore) -> bool:
        """Check if indicator is related to ransomware."""
        
        # Check malware families
        malware_families = indicator.properties.get('malware_families', [])
        
        for family in malware_families:
            family_lower = family.lower()
            if any(ransomware in family_lower for ransomware in self.ransomware_patterns):
                return True
        
        # Check malware type
        malware_data = indicator.properties.get('malware_data', {})
        for family, data in malware_data.items():
            family_type = data.get('family_type', '').lower()
            if 'ransomware' in family_type:
                return True
        
        # Check tags
        tags = indicator.properties.get('tags', [])
        return any('ransomware' in tag.lower() for tag in tags)
    
    def _is_campaign_indicator(self, indicator: NormalizedIndicator, threat_score: ThreatScore) -> bool:
        """Check if indicator is part of a campaign."""
        
        # Check for campaign tags or properties
        campaign = indicator.properties.get('campaign')
        if campaign:
            return True
        
        tags = indicator.properties.get('tags', [])
        campaign_tags = ['campaign', 'operation', 'apt-campaign']
        
        return any(campaign_tag in tag.lower() for tag in tags for campaign_tag in campaign_tags)
    
    def _targets_critical_assets(self, indicator: NormalizedIndicator, threat_score: ThreatScore) -> bool:
        """Check if indicator targets critical assets."""
        
        # Check targeting information
        targeting = indicator.properties.get('targeting', {})
        
        # Critical sectors
        critical_sectors = {
            'financial', 'healthcare', 'energy', 'utilities',
            'government', 'defense', 'critical infrastructure'
        }
        
        targeted_sectors = set(sector.lower() for sector in targeting.get('sectors', []))
        if targeted_sectors & critical_sectors:
            return True
        
        # Check tags for critical asset targeting
        tags = indicator.properties.get('tags', [])
        return any(sector in tag.lower() for tag in tags for sector in critical_sectors)
    
    def _has_infrastructure_correlation(self, indicator: NormalizedIndicator, threat_score: ThreatScore) -> bool:
        """Check if indicator has infrastructure correlations."""
        
        # Check correlation data from threat score
        correlation_score = threat_score.breakdown.correlation_score
        
        # High correlation suggests infrastructure relationships
        return correlation_score >= 0.7
    
    def _has_multiple_sources(self, indicator: NormalizedIndicator, threat_score: ThreatScore) -> bool:
        """Check if indicator comes from multiple sources."""
        
        sources = indicator.properties.get('sources', [])
        return len(sources) >= 3  # 3+ sources indicates good coverage


class ResponseRecommendationEngine:
    """Generates response action recommendations based on priority assignments."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize response recommendation engine."""
        self.config = config or {}
        
        # Response mappings by priority band
        self.band_responses = {
            PriorityBand.P1: [
                ResponseAction.IMMEDIATE_INVESTIGATION,
                ResponseAction.HUNT_DEPLOYMENT,
                ResponseAction.IOC_DEPLOYMENT,
                ResponseAction.STAKEHOLDER_NOTIFICATION
            ],
            PriorityBand.P2: [
                ResponseAction.ALERT_CREATION,
                ResponseAction.IOC_DEPLOYMENT,
                ResponseAction.MONITORING_ENHANCEMENT
            ],
            PriorityBand.P3: [
                ResponseAction.IOC_DEPLOYMENT,
                ResponseAction.INTELLIGENCE_COLLECTION,
                ResponseAction.MANUAL_REVIEW
            ],
            PriorityBand.P4: [
                ResponseAction.DOCUMENTATION_UPDATE,
                ResponseAction.INTELLIGENCE_COLLECTION
            ]
        }
        
        # Escalation-specific responses
        self.escalation_responses = {
            EscalationTrigger.ZERO_DAY: [
                ResponseAction.IMMEDIATE_INVESTIGATION,
                ResponseAction.HUNT_DEPLOYMENT,
                ResponseAction.STAKEHOLDER_NOTIFICATION
            ],
            EscalationTrigger.ACTIVE_EXPLOITATION: [
                ResponseAction.IMMEDIATE_INVESTIGATION,
                ResponseAction.AUTOMATED_BLOCKING,
                ResponseAction.HUNT_DEPLOYMENT
            ],
            EscalationTrigger.CRITICAL_CVE: [
                ResponseAction.HUNT_DEPLOYMENT,
                ResponseAction.IOC_DEPLOYMENT,
                ResponseAction.MONITORING_ENHANCEMENT
            ],
            EscalationTrigger.APT_ATTRIBUTION: [
                ResponseAction.HUNT_DEPLOYMENT,
                ResponseAction.INTELLIGENCE_COLLECTION,
                ResponseAction.STAKEHOLDER_NOTIFICATION
            ],
            EscalationTrigger.RANSOMWARE_FAMILY: [
                ResponseAction.IMMEDIATE_INVESTIGATION,
                ResponseAction.AUTOMATED_BLOCKING,
                ResponseAction.STAKEHOLDER_NOTIFICATION
            ]
        }
        
        logger.debug("Response recommendation engine initialized")
    
    def recommend_responses(self, 
                          priority_assignment: PriorityAssignment,
                          indicator_context: Optional[Dict[str, Any]] = None) -> List[ResponseAction]:
        """Recommend response actions for a priority assignment."""
        
        responses = set()
        
        # Base responses for priority band
        band_responses = self.band_responses.get(priority_assignment.priority_band, [])
        responses.update(band_responses)
        
        # Additional responses for escalation triggers
        for trigger in priority_assignment.escalation_triggers:
            trigger_responses = self.escalation_responses.get(trigger, [])
            responses.update(trigger_responses)
        
        # Context-specific adjustments
        if indicator_context:
            context_responses = self._get_context_responses(indicator_context)
            responses.update(context_responses)
        
        return list(responses)
    
    def _get_context_responses(self, context: Dict[str, Any]) -> List[ResponseAction]:
        """Get context-specific response recommendations."""
        
        responses = []
        
        # High confidence indicators get automated deployment
        confidence = context.get('confidence_score', 0)
        if confidence >= 0.8:
            responses.append(ResponseAction.AUTOMATED_BLOCKING)
        
        # Multiple correlations suggest hunt activity
        correlation_count = context.get('correlation_count', 0)
        if correlation_count >= 5:
            responses.append(ResponseAction.HUNT_DEPLOYMENT)
        
        # Infrastructure patterns suggest monitoring
        if context.get('infrastructure_correlation'):
            responses.append(ResponseAction.MONITORING_ENHANCEMENT)
        
        return responses


class PriorityBandClassifier:
    """Main priority band classification system."""
    
    def __init__(self, config: Optional[PriorityBandConfiguration] = None):
        """Initialize priority band classifier."""
        self.config = config or PriorityBandConfiguration()
        
        # Initialize components
        self.escalation_detector = EscalationDetector()
        self.response_engine = ResponseRecommendationEngine()
        
        # Statistics tracking
        self.band_stats = {
            band: BandStatistics(band=band) 
            for band in PriorityBand
        }
        
        logger.info("Priority band classifier initialized")
    
    def classify_priority(self, 
                        indicator: NormalizedIndicator,
                        threat_score: ThreatScore,
                        risk_assessment: Optional[Dict[str, Any]] = None,
                        volume_context: Optional[Dict[str, int]] = None) -> PriorityAssignment:
        """Classify priority band for an indicator."""
        
        assignment = PriorityAssignment(
            indicator_id=indicator.id,
            original_score=threat_score.total_score
        )
        
        # Detect escalation triggers
        escalation_triggers = self.escalation_detector.detect_escalations(
            indicator, threat_score, risk_assessment or {}
        )
        assignment.escalation_triggers = escalation_triggers
        
        # Apply risk level multiplier
        risk_level = RiskLevel.MEDIUM  # Default
        if risk_assessment and 'overall_risk' in risk_assessment:
            risk_level_str = risk_assessment['overall_risk'].get('level', 'medium')
            try:
                risk_level = RiskLevel(risk_level_str)
            except ValueError:
                pass
        
        assignment.risk_multiplier = self.config.risk_level_multipliers.get(risk_level, 1.0)
        
        # Apply escalation boost
        escalation_boost = 0.0
        for trigger in escalation_triggers:
            trigger_weight = self.config.escalation_weights.get(trigger, 0.0)
            escalation_boost += trigger_weight
        
        assignment.escalation_boost = min(escalation_boost, 0.5)  # Cap at 50%
        
        # Apply temporal adjustments
        temporal_adjustment = self._calculate_temporal_adjustment(indicator)
        assignment.temporal_adjustment = temporal_adjustment
        
        # Apply volume adjustments
        volume_adjustment = self._calculate_volume_adjustment(volume_context or {})
        assignment.volume_adjustment = volume_adjustment
        
        # Calculate adjusted score
        base_adjusted = assignment.original_score * assignment.risk_multiplier
        final_score = base_adjusted + assignment.escalation_boost + assignment.temporal_adjustment + assignment.volume_adjustment
        assignment.adjusted_score = max(0.0, min(1.0, final_score))
        
        # Determine priority band
        assignment.priority_band = self._determine_priority_band(assignment.adjusted_score)
        
        # Generate response recommendations
        assignment.response_actions = self.response_engine.recommend_responses(
            assignment, 
            {
                'confidence_score': threat_score.breakdown.confidence_score,
                'correlation_count': len(threat_score.breakdown.correlation_factors),
                'infrastructure_correlation': any('infra' in factor for factor in threat_score.breakdown.correlation_factors)
            }
        )
        
        # Generate reasoning
        assignment.assignment_reasoning = self._generate_reasoning(assignment, risk_level, escalation_triggers)
        
        # Update statistics
        self._update_band_statistics(assignment)
        
        return assignment
    
    def _calculate_temporal_adjustment(self, indicator: NormalizedIndicator) -> float:
        """Calculate temporal-based priority adjustments."""
        
        adjustment = 0.0
        
        # Recent activity boost
        last_seen = indicator.properties.get('last_seen')
        if last_seen:
            try:
                last_date = datetime.fromisoformat(last_seen.replace('Z', '+00:00'))
                age = datetime.utcnow() - last_date
                
                if age <= timedelta(hours=24):
                    adjustment += self.config.temporal_adjustments['recent_activity_boost']
                elif age <= timedelta(days=7):
                    adjustment += self.config.temporal_adjustments['aged_penalty']
                elif age >= timedelta(days=30):
                    adjustment += self.config.temporal_adjustments['stale_penalty']
                    
            except:
                pass
        
        # Trending analysis (mock implementation)
        observation_count = indicator.properties.get('observation_count', 1)
        if observation_count > 10:  # High observation count suggests trending
            adjustment += self.config.temporal_adjustments['trending_boost']
        
        return adjustment
    
    def _calculate_volume_adjustment(self, volume_context: Dict[str, int]) -> float:
        """Calculate volume-based priority adjustments."""
        
        total_indicators = volume_context.get('total_indicators', 0)
        
        for threshold_name, (threshold, adjustment) in self.config.volume_thresholds.items():
            if total_indicators >= threshold:
                return adjustment
        
        return 0.0
    
    def _determine_priority_band(self, adjusted_score: float) -> PriorityBand:
        """Determine priority band from adjusted score."""
        
        if adjusted_score >= self.config.p1_threshold:
            return PriorityBand.P1
        elif adjusted_score >= self.config.p2_threshold:
            return PriorityBand.P2
        elif adjusted_score >= self.config.p3_threshold:
            return PriorityBand.P3
        else:
            return PriorityBand.P4
    
    def _generate_reasoning(self, 
                          assignment: PriorityAssignment,
                          risk_level: RiskLevel,
                          escalation_triggers: List[EscalationTrigger]) -> List[str]:
        """Generate human-readable reasoning for priority assignment."""
        
        reasoning = []
        
        # Score reasoning
        reasoning.append(f"Base score: {assignment.original_score:.3f}")
        
        if assignment.risk_multiplier != 1.0:
            reasoning.append(f"Risk level ({risk_level.value}) multiplier: {assignment.risk_multiplier:.2f}")
        
        if assignment.escalation_boost > 0:
            reasoning.append(f"Escalation boost: +{assignment.escalation_boost:.3f} from {len(escalation_triggers)} triggers")
        
        if assignment.temporal_adjustment != 0:
            reasoning.append(f"Temporal adjustment: {assignment.temporal_adjustment:+.3f}")
        
        if assignment.volume_adjustment != 0:
            reasoning.append(f"Volume adjustment: {assignment.volume_adjustment:+.3f}")
        
        reasoning.append(f"Final score: {assignment.adjusted_score:.3f} → {assignment.priority_band.value}")
        
        return reasoning
    
    def _update_band_statistics(self, assignment: PriorityAssignment) -> None:
        """Update statistics for priority bands."""
        
        band_stat = self.band_stats[assignment.priority_band]
        band_stat.indicator_count += 1
        band_stat.escalation_count += len(assignment.escalation_triggers)
        
        # Update score statistics
        scores = [assignment.adjusted_score]  # Would accumulate in real implementation
        if scores:
            band_stat.min_score = min(scores)
            band_stat.max_score = max(scores)
            band_stat.mean_score = sum(scores) / len(scores)
            band_stat.median_score = statistics.median(scores)
        
        # Update response statistics
        for response in assignment.response_actions:
            band_stat.response_distribution[response] = band_stat.response_distribution.get(response, 0) + 1
    
    def batch_classify_priorities(self, 
                                indicators_with_scores: List[Tuple[NormalizedIndicator, ThreatScore]],
                                risk_assessments: Optional[Dict[str, Dict[str, Any]]] = None) -> List[PriorityAssignment]:
        """Batch classify priority bands for multiple indicators."""
        
        logger.info(f"Batch priority classification for {len(indicators_with_scores)} indicators")
        
        assignments = []
        volume_context = {'total_indicators': len(indicators_with_scores)}
        
        for i, (indicator, threat_score) in enumerate(indicators_with_scores):
            try:
                risk_assessment = None
                if risk_assessments:
                    risk_assessment = risk_assessments.get(indicator.id)
                
                assignment = self.classify_priority(
                    indicator, threat_score, risk_assessment, volume_context
                )
                assignments.append(assignment)
                
                # Log progress for large batches
                if (i + 1) % 100 == 0:
                    logger.debug(f"Classified {i + 1}/{len(indicators_with_scores)} priorities")
                    
            except Exception as e:
                logger.error(f"Priority classification failed for {indicator.id}: {e}")
        
        logger.info(f"Priority classification completed for {len(assignments)} indicators")
        return assignments
    
    def get_band_statistics(self) -> Dict[str, Any]:
        """Get priority band statistics."""
        
        return {
            'band_statistics': {
                band.value: stat.to_dict() 
                for band, stat in self.band_stats.items()
            },
            'configuration': {
                'thresholds': {
                    'p1_threshold': self.config.p1_threshold,
                    'p2_threshold': self.config.p2_threshold,
                    'p3_threshold': self.config.p3_threshold,
                    'p4_threshold': self.config.p4_threshold
                }
            }
        }
    
    def update_configuration(self, new_config: PriorityBandConfiguration) -> None:
        """Update priority band configuration."""
        
        logger.info("Updating priority band configuration")
        self.config = new_config
        
        # Reset statistics after configuration change
        self.band_stats = {
            band: BandStatistics(band=band) 
            for band in PriorityBand
        }