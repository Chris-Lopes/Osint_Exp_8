"""
Lineage tracking system for threat intelligence indicator merging.

This module provides comprehensive lineage tracking capabilities that maintain
a complete audit trail of merge operations, source attribution, and data
provenance throughout the merge process.
"""

import logging
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import json

try:
    from ..normalizers.schema import NormalizedIndicator
    from .deduplication import DuplicateMatch, DuplicateMatchType
    from .confidence import MergeConfidenceScore, MergeDecision
except ImportError:
    from normalizers.schema import NormalizedIndicator
    from merge.deduplication import DuplicateMatch, DuplicateMatchType
    from merge.confidence import MergeConfidenceScore, MergeDecision

logger = logging.getLogger(__name__)


class LineageEventType(Enum):
    """Types of lineage events."""
    MERGE_OPERATION = "merge_operation"
    FIELD_MERGE = "field_merge"
    CONFLICT_RESOLUTION = "conflict_resolution"
    SOURCE_ATTRIBUTION = "source_attribution"
    QUALITY_ASSESSMENT = "quality_assessment"
    VALIDATION = "validation"


class ConflictResolutionStrategy(Enum):
    """Strategies for resolving merge conflicts."""
    HIGHEST_CONFIDENCE = "highest_confidence"
    MOST_RECENT = "most_recent"
    MOST_COMPLETE = "most_complete"
    MANUAL_DECISION = "manual_decision"
    WEIGHTED_MERGE = "weighted_merge"
    PRESERVE_ALL = "preserve_all"


@dataclass
class SourceAttribution:
    """Attribution information for merged data."""
    
    source_name: str
    source_confidence: float
    contribution_weight: float  # How much this source contributed to final value
    field_contributions: Dict[str, float] = field(default_factory=dict)  # Per-field contributions
    original_indicator_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'source_name': self.source_name,
            'source_confidence': self.source_confidence,
            'contribution_weight': self.contribution_weight,
            'field_contributions': self.field_contributions,
            'original_indicator_id': self.original_indicator_id
        }


@dataclass
class ConflictResolution:
    """Details of how a merge conflict was resolved."""
    
    field_name: str
    conflict_values: Dict[str, Any]  # original_indicator_id -> value
    resolved_value: Any
    resolution_strategy: ConflictResolutionStrategy
    resolution_rationale: str
    confidence_scores: Dict[str, float] = field(default_factory=dict)
    manual_override: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'field_name': self.field_name,
            'conflict_values': self.conflict_values,
            'resolved_value': self.resolved_value,
            'resolution_strategy': self.resolution_strategy.value,
            'resolution_rationale': self.resolution_rationale,
            'confidence_scores': self.confidence_scores,
            'manual_override': self.manual_override
        }


@dataclass
class LineageEvent:
    """Individual event in merge lineage."""
    
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event_type: LineageEventType = LineageEventType.MERGE_OPERATION
    timestamp: datetime = field(default_factory=datetime.utcnow)
    description: str = ""
    
    # Context data
    source_indicators: List[str] = field(default_factory=list)
    target_indicator: Optional[str] = None
    
    # Event-specific data
    merge_decision: Optional[MergeDecision] = None
    duplicate_match: Optional[Dict[str, Any]] = None
    conflict_resolutions: List[ConflictResolution] = field(default_factory=list)
    source_attributions: List[SourceAttribution] = field(default_factory=list)
    
    # Quality metrics
    confidence_score: Optional[float] = None
    quality_metrics: Dict[str, float] = field(default_factory=dict)
    
    # User context
    user_id: Optional[str] = None
    automated: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'event_id': self.event_id,
            'event_type': self.event_type.value,
            'timestamp': self.timestamp.isoformat(),
            'description': self.description,
            'source_indicators': self.source_indicators,
            'target_indicator': self.target_indicator,
            'merge_decision': self.merge_decision.value if self.merge_decision else None,
            'duplicate_match': self.duplicate_match,
            'conflict_resolutions': [cr.to_dict() for cr in self.conflict_resolutions],
            'source_attributions': [sa.to_dict() for sa in self.source_attributions],
            'confidence_score': self.confidence_score,
            'quality_metrics': self.quality_metrics,
            'user_id': self.user_id,
            'automated': self.automated
        }


@dataclass
class IndicatorLineage:
    """Complete lineage information for a merged indicator."""
    
    indicator_id: str
    original_indicators: List[str] = field(default_factory=list)
    merge_events: List[LineageEvent] = field(default_factory=list)
    source_attributions: List[SourceAttribution] = field(default_factory=list)
    
    # Merge metadata
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_modified: datetime = field(default_factory=datetime.utcnow)
    merge_count: int = 0
    confidence_history: List[Tuple[datetime, float]] = field(default_factory=list)
    
    def add_event(self, event: LineageEvent):
        """Add a lineage event."""
        self.merge_events.append(event)
        self.last_modified = datetime.utcnow()
        
        if event.confidence_score is not None:
            self.confidence_history.append((event.timestamp, event.confidence_score))
    
    def get_source_contribution(self, source_name: str) -> float:
        """Get total contribution weight for a source."""
        total_weight = 0.0
        for attribution in self.source_attributions:
            if attribution.source_name == source_name:
                total_weight += attribution.contribution_weight
        return total_weight
    
    def get_field_provenance(self, field_name: str) -> List[SourceAttribution]:
        """Get source attributions that contributed to a specific field."""
        field_attributions = []
        for attribution in self.source_attributions:
            if field_name in attribution.field_contributions:
                field_attributions.append(attribution)
        return field_attributions
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'indicator_id': self.indicator_id,
            'original_indicators': self.original_indicators,
            'merge_events': [event.to_dict() for event in self.merge_events],
            'source_attributions': [sa.to_dict() for sa in self.source_attributions],
            'created_at': self.created_at.isoformat(),
            'last_modified': self.last_modified.isoformat(),
            'merge_count': self.merge_count,
            'confidence_history': [
                (ts.isoformat(), conf) for ts, conf in self.confidence_history
            ]
        }


class LineageTracker:
    """Main lineage tracking system."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize lineage tracker."""
        self.config = config or {}
        self.lineages: Dict[str, IndicatorLineage] = {}
        
        # Storage configuration
        self.enable_persistence = self.config.get('enable_persistence', True)
        self.storage_path = self.config.get('storage_path', 'data/lineage')
        
        # Retention configuration
        self.max_events_per_lineage = self.config.get('max_events_per_lineage', 1000)
        self.retention_days = self.config.get('retention_days', 365)
        
        logger.info("Lineage tracker initialized")
    
    def create_lineage(self, indicator_id: str, 
                      original_indicators: List[str]) -> IndicatorLineage:
        """Create new lineage for merged indicator."""
        lineage = IndicatorLineage(
            indicator_id=indicator_id,
            original_indicators=original_indicators.copy()
        )
        
        # Create initial event
        initial_event = LineageEvent(
            event_type=LineageEventType.MERGE_OPERATION,
            description=f"Created merged indicator from {len(original_indicators)} sources",
            source_indicators=original_indicators,
            target_indicator=indicator_id
        )
        
        lineage.add_event(initial_event)
        self.lineages[indicator_id] = lineage
        
        logger.info(f"Created lineage for indicator {indicator_id}")
        return lineage
    
    def record_merge_operation(self, 
                             merged_indicator_id: str,
                             source_indicators: List[NormalizedIndicator],
                             duplicate_match: DuplicateMatch,
                             confidence_score: MergeConfidenceScore,
                             conflict_resolutions: List[ConflictResolution],
                             user_id: Optional[str] = None) -> LineageEvent:
        """Record a complete merge operation."""
        
        # Get or create lineage
        if merged_indicator_id not in self.lineages:
            original_ids = [ind.id for ind in source_indicators]
            lineage = self.create_lineage(merged_indicator_id, original_ids)
        else:
            lineage = self.lineages[merged_indicator_id]
        
        # Create merge event
        merge_event = LineageEvent(
            event_type=LineageEventType.MERGE_OPERATION,
            description=f"Merged {len(source_indicators)} indicators using {duplicate_match.match_type.value}",
            source_indicators=[ind.id for ind in source_indicators],
            target_indicator=merged_indicator_id,
            merge_decision=confidence_score.decision,
            duplicate_match=duplicate_match.to_dict(),
            conflict_resolutions=conflict_resolutions,
            confidence_score=confidence_score.confidence_score,
            user_id=user_id,
            automated=user_id is None
        )
        
        # Calculate source attributions
        attributions = self._calculate_source_attributions(source_indicators, confidence_score)
        merge_event.source_attributions = attributions
        
        # Update lineage
        lineage.add_event(merge_event)
        lineage.merge_count += 1
        lineage.source_attributions.extend(attributions)
        
        # Clean up old events if needed
        self._cleanup_lineage_events(lineage)
        
        logger.info(f"Recorded merge operation for indicator {merged_indicator_id}")
        return merge_event
    
    def record_conflict_resolution(self,
                                 indicator_id: str,
                                 field_name: str,
                                 conflict_values: Dict[str, Any],
                                 resolved_value: Any,
                                 strategy: ConflictResolutionStrategy,
                                 rationale: str,
                                 manual_override: bool = False) -> LineageEvent:
        """Record resolution of a merge conflict."""
        
        conflict_resolution = ConflictResolution(
            field_name=field_name,
            conflict_values=conflict_values,
            resolved_value=resolved_value,
            resolution_strategy=strategy,
            resolution_rationale=rationale,
            manual_override=manual_override
        )
        
        event = LineageEvent(
            event_type=LineageEventType.CONFLICT_RESOLUTION,
            description=f"Resolved conflict for field '{field_name}' using {strategy.value}",
            target_indicator=indicator_id,
            conflict_resolutions=[conflict_resolution]
        )
        
        # Add to lineage if exists
        if indicator_id in self.lineages:
            self.lineages[indicator_id].add_event(event)
        
        logger.info(f"Recorded conflict resolution for {indicator_id}.{field_name}")
        return event
    
    def record_field_merge(self,
                          indicator_id: str,
                          field_name: str,
                          source_values: Dict[str, Any],
                          merged_value: Any,
                          merge_strategy: str,
                          confidence_scores: Dict[str, float]) -> LineageEvent:
        """Record merging of a specific field."""
        
        event = LineageEvent(
            event_type=LineageEventType.FIELD_MERGE,
            description=f"Merged field '{field_name}' using {merge_strategy}",
            target_indicator=indicator_id,
            quality_metrics={
                'field_name': field_name,
                'merge_strategy': merge_strategy,
                'source_count': len(source_values)
            }
        )
        
        # Create conflict resolution record for this field
        conflict_resolution = ConflictResolution(
            field_name=field_name,
            conflict_values=source_values,
            resolved_value=merged_value,
            resolution_strategy=ConflictResolutionStrategy.WEIGHTED_MERGE,  # Default
            resolution_rationale=f"Field merged using {merge_strategy}",
            confidence_scores=confidence_scores
        )
        
        event.conflict_resolutions = [conflict_resolution]
        
        # Add to lineage
        if indicator_id in self.lineages:
            self.lineages[indicator_id].add_event(event)
        
        return event
    
    def get_lineage(self, indicator_id: str) -> Optional[IndicatorLineage]:
        """Get lineage for an indicator."""
        return self.lineages.get(indicator_id)
    
    def get_source_indicators(self, indicator_id: str) -> List[str]:
        """Get original source indicator IDs for a merged indicator."""
        lineage = self.get_lineage(indicator_id)
        return lineage.original_indicators if lineage else []
    
    def get_merge_history(self, indicator_id: str) -> List[LineageEvent]:
        """Get merge history for an indicator."""
        lineage = self.get_lineage(indicator_id)
        return lineage.merge_events if lineage else []
    
    def trace_field_provenance(self, indicator_id: str, 
                             field_name: str) -> List[SourceAttribution]:
        """Trace the provenance of a specific field value."""
        lineage = self.get_lineage(indicator_id)
        if not lineage:
            return []
        
        return lineage.get_field_provenance(field_name)
    
    def get_confidence_trend(self, indicator_id: str) -> List[Tuple[datetime, float]]:
        """Get confidence score trend over time."""
        lineage = self.get_lineage(indicator_id)
        return lineage.confidence_history if lineage else []
    
    def find_related_indicators(self, indicator_id: str) -> Set[str]:
        """Find all indicators related through merge operations."""
        related = set()
        
        # Find indicators that were merged into this one
        lineage = self.get_lineage(indicator_id)
        if lineage:
            related.update(lineage.original_indicators)
        
        # Find indicators that this one was merged into
        for other_id, other_lineage in self.lineages.items():
            if indicator_id in other_lineage.original_indicators:
                related.add(other_id)
                related.update(other_lineage.original_indicators)
        
        # Remove self
        related.discard(indicator_id)
        return related
    
    def generate_audit_report(self, indicator_id: str) -> Dict[str, Any]:
        """Generate comprehensive audit report for an indicator."""
        lineage = self.get_lineage(indicator_id)
        if not lineage:
            return {'error': 'No lineage found for indicator'}
        
        report = {
            'indicator_id': indicator_id,
            'summary': {
                'created_at': lineage.created_at.isoformat(),
                'last_modified': lineage.last_modified.isoformat(),
                'total_merges': lineage.merge_count,
                'source_indicators': len(lineage.original_indicators),
                'total_events': len(lineage.merge_events)
            },
            'source_breakdown': self._get_source_breakdown(lineage),
            'confidence_trend': [
                (ts.isoformat(), score) for ts, score in lineage.confidence_history
            ],
            'merge_timeline': [event.to_dict() for event in lineage.merge_events],
            'conflict_summary': self._get_conflict_summary(lineage),
            'data_provenance': self._get_data_provenance(lineage)
        }
        
        return report
    
    def _calculate_source_attributions(self, 
                                     indicators: List[NormalizedIndicator],
                                     confidence_score: MergeConfidenceScore) -> List[SourceAttribution]:
        """Calculate source attributions for merged indicators."""
        attributions = []
        
        total_confidence = sum(
            getattr(ind, 'confidence', 50) for ind in indicators
        )
        
        for indicator in indicators:
            try:
                source_name = indicator.source_metadata.source_name
                source_confidence = getattr(indicator.source_metadata, 'source_confidence', 50) / 100.0
                indicator_confidence = getattr(indicator, 'confidence', 50) / 100.0
                
                # Calculate contribution weight based on various factors
                weight = self._calculate_contribution_weight(
                    indicator, indicators, confidence_score
                )
                
                attribution = SourceAttribution(
                    source_name=source_name,
                    source_confidence=source_confidence,
                    contribution_weight=weight,
                    original_indicator_id=indicator.id
                )
                
                attributions.append(attribution)
                
            except Exception as e:
                logger.warning(f"Failed to create attribution for {indicator.id}: {e}")
        
        return attributions
    
    def _calculate_contribution_weight(self,
                                     indicator: NormalizedIndicator,
                                     all_indicators: List[NormalizedIndicator],
                                     confidence_score: MergeConfidenceScore) -> float:
        """Calculate how much an indicator contributes to the merged result."""
        
        weight_factors = []
        
        # Source reliability (from confidence scoring)
        source_reliability = confidence_score.confidence_factors.source_reliability
        weight_factors.append(source_reliability)
        
        # Data completeness
        completeness = self._calculate_indicator_completeness(indicator)
        weight_factors.append(completeness)
        
        # Recency
        try:
            created = indicator.created
            if isinstance(created, str):
                created = datetime.fromisoformat(created.replace('Z', '+00:00'))
            
            age_days = (datetime.utcnow() - created).days
            recency_score = max(0.1, 1.0 - (age_days / 365))  # Decay over a year
            weight_factors.append(recency_score)
        except Exception:
            weight_factors.append(0.5)
        
        # Indicator confidence
        if hasattr(indicator, 'confidence'):
            conf_score = indicator.confidence / 100.0
            weight_factors.append(conf_score)
        else:
            weight_factors.append(0.5)
        
        # Calculate weighted average
        return sum(weight_factors) / len(weight_factors)
    
    def _calculate_indicator_completeness(self, indicator: NormalizedIndicator) -> float:
        """Calculate completeness score for an indicator."""
        total_fields = 0
        populated_fields = 0
        
        # Check core fields
        core_fields = ['value', 'indicator_type', 'confidence', 'tags', 'created']
        for field in core_fields:
            total_fields += 1
            if hasattr(indicator, field):
                value = getattr(indicator, field)
                if value is not None and value != [] and value != {}:
                    populated_fields += 1
        
        # Check enrichment
        enrichment = indicator.context.get('enrichment', {})
        if enrichment:
            populated_fields += 0.5
        
        return populated_fields / total_fields if total_fields > 0 else 0.0
    
    def _cleanup_lineage_events(self, lineage: IndicatorLineage):
        """Clean up old lineage events to prevent unbounded growth."""
        if len(lineage.merge_events) > self.max_events_per_lineage:
            # Keep the most recent events
            lineage.merge_events = lineage.merge_events[-self.max_events_per_lineage:]
            
        # Remove events older than retention period
        cutoff_date = datetime.utcnow() - timedelta(days=self.retention_days)
        lineage.merge_events = [
            event for event in lineage.merge_events 
            if event.timestamp > cutoff_date
        ]
    
    def _get_source_breakdown(self, lineage: IndicatorLineage) -> Dict[str, Any]:
        """Get breakdown of sources contributing to merged indicator."""
        source_stats = {}
        
        for attribution in lineage.source_attributions:
            source_name = attribution.source_name
            if source_name not in source_stats:
                source_stats[source_name] = {
                    'total_weight': 0.0,
                    'confidence': attribution.source_confidence,
                    'contributions': 0
                }
            
            source_stats[source_name]['total_weight'] += attribution.contribution_weight
            source_stats[source_name]['contributions'] += 1
        
        return source_stats
    
    def _get_conflict_summary(self, lineage: IndicatorLineage) -> Dict[str, Any]:
        """Get summary of conflicts and resolutions."""
        conflicts = []
        
        for event in lineage.merge_events:
            if event.event_type == LineageEventType.CONFLICT_RESOLUTION:
                conflicts.extend([cr.to_dict() for cr in event.conflict_resolutions])
        
        # Group by resolution strategy
        strategy_counts = {}
        for conflict in conflicts:
            strategy = conflict['resolution_strategy']
            strategy_counts[strategy] = strategy_counts.get(strategy, 0) + 1
        
        return {
            'total_conflicts': len(conflicts),
            'resolution_strategies': strategy_counts,
            'conflicts': conflicts
        }
    
    def _get_data_provenance(self, lineage: IndicatorLineage) -> Dict[str, Any]:
        """Get data provenance information."""
        field_provenance = {}
        
        # Analyze field contributions across all events
        for event in lineage.merge_events:
            for resolution in event.conflict_resolutions:
                field_name = resolution.field_name
                if field_name not in field_provenance:
                    field_provenance[field_name] = {
                        'sources': [],
                        'final_strategy': resolution.resolution_strategy.value,
                        'confidence': resolution.confidence_scores
                    }
        
        return {
            'field_provenance': field_provenance,
            'source_indicators': lineage.original_indicators,
            'attribution_summary': {
                attribution.source_name: attribution.contribution_weight
                for attribution in lineage.source_attributions
            }
        }