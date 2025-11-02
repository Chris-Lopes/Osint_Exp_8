"""
Merge execution engine for threat intelligence indicators.

This module coordinates the complete merge process, combining deduplication,
confidence scoring, lineage tracking, and policy enforcement to perform
sophisticated indicator merging with full audit trails.
"""

import logging
import asyncio
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Set, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import copy

try:
    from ..normalizers.schema import NormalizedIndicator, IndicatorType
    from .deduplication import DeduplicationEngine, DuplicateMatch, DuplicateMatchType
    from .confidence import MergeConfidenceEngine, MergeConfidenceScore, MergeDecision
    from .lineage import LineageTracker, ConflictResolution, SourceAttribution
    from .policies import MergePolicyEngine, MergeRuleSet, FieldMergeRule, ConflictResolutionStrategy
except ImportError:
    from normalizers.schema import NormalizedIndicator, IndicatorType
    from merge.deduplication import DeduplicationEngine, DuplicateMatch, DuplicateMatchType
    from merge.confidence import MergeConfidenceEngine, MergeConfidenceScore, MergeDecision
    from merge.lineage import LineageTracker, ConflictResolution, SourceAttribution
    from merge.policies import MergePolicyEngine, MergeRuleSet, FieldMergeRule, ConflictResolutionStrategy

logger = logging.getLogger(__name__)


class MergeExecutionStatus(Enum):
    """Status of merge execution."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class MergeResult:
    """Result of a merge operation."""
    
    merge_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    status: MergeExecutionStatus = MergeExecutionStatus.PENDING
    
    # Input indicators
    source_indicators: List[NormalizedIndicator] = field(default_factory=list)
    duplicate_match: Optional[DuplicateMatch] = None
    
    # Merge decision info
    confidence_score: Optional[MergeConfidenceScore] = None
    merge_decision: Optional[MergeDecision] = None
    
    # Output
    merged_indicator: Optional[NormalizedIndicator] = None
    conflict_resolutions: List[ConflictResolution] = field(default_factory=list)
    
    # Execution metadata
    rule_set_used: Optional[str] = None
    execution_time: Optional[float] = None
    error_message: Optional[str] = None
    warnings: List[str] = field(default_factory=list)
    
    # Timestamps
    created_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'merge_id': self.merge_id,
            'status': self.status.value,
            'source_indicator_ids': [ind.id for ind in self.source_indicators],
            'duplicate_match': self.duplicate_match.to_dict() if self.duplicate_match else None,
            'confidence_score': self.confidence_score.to_dict() if self.confidence_score else None,
            'merge_decision': self.merge_decision.value if self.merge_decision else None,
            'merged_indicator_id': self.merged_indicator.id if self.merged_indicator else None,
            'conflict_resolutions': [cr.to_dict() for cr in self.conflict_resolutions],
            'rule_set_used': self.rule_set_used,
            'execution_time': self.execution_time,
            'error_message': self.error_message,
            'warnings': self.warnings,
            'created_at': self.created_at.isoformat(),
            'completed_at': self.completed_at.isoformat() if self.completed_at else None
        }


@dataclass
class MergeExecutionSummary:
    """Summary of batch merge execution."""
    
    total_indicators: int = 0
    duplicate_groups: int = 0
    merge_attempts: int = 0
    successful_merges: int = 0
    failed_merges: int = 0
    skipped_merges: int = 0
    
    # Timing
    execution_time: float = 0.0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    
    # Results breakdown
    results_by_decision: Dict[str, int] = field(default_factory=dict)
    results_by_status: Dict[str, int] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'total_indicators': self.total_indicators,
            'duplicate_groups': self.duplicate_groups,
            'merge_attempts': self.merge_attempts,
            'successful_merges': self.successful_merges,
            'failed_merges': self.failed_merges,
            'skipped_merges': self.skipped_merges,
            'execution_time': self.execution_time,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'results_by_decision': self.results_by_decision,
            'results_by_status': self.results_by_status
        }


class MergeExecutor:
    """Executes individual merge operations."""
    
    def __init__(self, 
                 confidence_engine: MergeConfidenceEngine,
                 policy_engine: MergePolicyEngine,
                 lineage_tracker: LineageTracker,
                 config: Optional[Dict[str, Any]] = None):
        """Initialize merge executor."""
        self.confidence_engine = confidence_engine
        self.policy_engine = policy_engine
        self.lineage_tracker = lineage_tracker
        self.config = config or {}
        
        # Execution settings
        self.default_rule_set = self.config.get('default_rule_set', 'moderate')
        self.enable_validation = self.config.get('enable_validation', True)
        
        logger.info("Merge executor initialized")
    
    def execute_merge(self, 
                     indicators: List[NormalizedIndicator],
                     duplicate_match: DuplicateMatch,
                     rule_set_name: Optional[str] = None) -> MergeResult:
        """Execute a single merge operation."""
        
        start_time = datetime.utcnow()
        merge_result = MergeResult(
            source_indicators=indicators,
            duplicate_match=duplicate_match
        )
        
        try:
            merge_result.status = MergeExecutionStatus.IN_PROGRESS
            
            # Use default rule set if not specified
            if rule_set_name is None:
                rule_set_name = self.default_rule_set
            
            merge_result.rule_set_used = rule_set_name
            
            # Step 1: Calculate merge confidence
            logger.debug(f"Calculating merge confidence for {len(indicators)} indicators")
            confidence_score = self.confidence_engine.calculate_merge_confidence(
                duplicate_match, indicators
            )
            merge_result.confidence_score = confidence_score
            merge_result.merge_decision = confidence_score.decision
            
            # Step 2: Check merge policy
            logger.debug(f"Evaluating merge policy: {rule_set_name}")
            policy_allows_merge = self.policy_engine.evaluate_merge_decision(
                rule_set_name, indicators, duplicate_match, confidence_score
            )
            
            if not policy_allows_merge:
                merge_result.status = MergeExecutionStatus.SKIPPED
                merge_result.warnings.append("Merge blocked by policy rules")
                return merge_result
            
            # Step 3: Check merge decision
            if confidence_score.decision in {MergeDecision.NO_MERGE, MergeDecision.MANUAL_REVIEW}:
                merge_result.status = MergeExecutionStatus.SKIPPED
                merge_result.warnings.append(f"Merge skipped: {confidence_score.decision.value}")
                return merge_result
            
            # Step 4: Perform actual merge
            logger.debug("Performing indicator merge")
            merged_indicator, conflict_resolutions = self._perform_merge(
                indicators, rule_set_name, confidence_score
            )
            
            merge_result.merged_indicator = merged_indicator
            merge_result.conflict_resolutions = conflict_resolutions
            
            # Step 5: Record lineage
            logger.debug("Recording merge lineage")
            self.lineage_tracker.record_merge_operation(
                merged_indicator.id,
                indicators,
                duplicate_match,
                confidence_score,
                conflict_resolutions
            )
            
            # Step 6: Validation (if enabled)
            if self.enable_validation:
                validation_warnings = self._validate_merge_result(merged_indicator, indicators)
                merge_result.warnings.extend(validation_warnings)
            
            merge_result.status = MergeExecutionStatus.COMPLETED
            logger.info(f"Merge completed successfully: {merge_result.merge_id}")
            
        except Exception as e:
            merge_result.status = MergeExecutionStatus.FAILED
            merge_result.error_message = str(e)
            logger.error(f"Merge execution failed: {e}", exc_info=True)
        
        finally:
            merge_result.completed_at = datetime.utcnow()
            merge_result.execution_time = (merge_result.completed_at - start_time).total_seconds()
        
        return merge_result
    
    def _perform_merge(self, 
                      indicators: List[NormalizedIndicator],
                      rule_set_name: str,
                      confidence_score: MergeConfidenceScore) -> Tuple[NormalizedIndicator, List[ConflictResolution]]:
        """Perform the actual merge operation."""
        
        if len(indicators) < 2:
            raise ValueError("Need at least 2 indicators to merge")
        
        # Get rule set
        rule_set = self.policy_engine.get_rule_set(rule_set_name)
        if not rule_set:
            raise ValueError(f"Unknown rule set: {rule_set_name}")
        
        # Start with primary indicator as base
        primary_id = confidence_score.primary_indicator_id
        if primary_id:
            base_indicator = next((ind for ind in indicators if ind.id == primary_id), indicators[0])
        else:
            base_indicator = indicators[0]
        
        # Create merged indicator (deep copy of base)
        merged_indicator = copy.deepcopy(base_indicator)
        merged_indicator.id = f"merged--{uuid.uuid4()}"
        
        # Track conflict resolutions
        conflict_resolutions = []
        
        # Merge each field
        field_names = self._get_mergeable_fields(indicators)
        
        for field_name in field_names:
            field_rule = rule_set.get_field_rule(field_name)
            
            # Check if field can be merged
            if not field_rule.can_merge_field(indicators, self.source_indicators[0], confidence_score):
                continue
            
            # Get values from all indicators
            field_values = self._extract_field_values(indicators, field_name)
            
            if len(set(str(v) for v in field_values.values())) <= 1:
                # No conflict - all values are the same
                continue
            
            # Resolve conflict
            try:
                merged_value = field_rule.merge_field(indicators)
                
                # Update merged indicator
                setattr(merged_indicator, field_name, merged_value)
                
                # Record conflict resolution
                conflict_resolution = ConflictResolution(
                    field_name=field_name,
                    conflict_values=field_values,
                    resolved_value=merged_value,
                    resolution_strategy=self._map_merge_strategy_to_resolution_strategy(field_rule.merge_strategy),
                    resolution_rationale=f"Applied {field_rule.merge_strategy.value} strategy",
                    confidence_scores={
                        ind.id: getattr(ind, 'confidence', 50) / 100.0
                        for ind in indicators
                    }
                )
                
                conflict_resolutions.append(conflict_resolution)
                
            except Exception as e:
                logger.warning(f"Failed to merge field {field_name}: {e}")
                # Keep original value from base indicator
        
        # Update metadata fields
        merged_indicator.modified = datetime.utcnow()
        
        # Update tags to include merge information
        if hasattr(merged_indicator, 'tags'):
            if not merged_indicator.tags:
                merged_indicator.tags = []
            merged_indicator.tags.append(f"merged_from_{len(indicators)}_sources")
        
        return merged_indicator, conflict_resolutions
    
    def _get_mergeable_fields(self, indicators: List[NormalizedIndicator]) -> List[str]:
        """Get list of fields that can be merged."""
        # Standard fields that can be merged
        mergeable_fields = [
            'tags', 'threat_types', 'malware_families', 'confidence',
            'severity', 'labels', 'description', 'context'
        ]
        
        # Only return fields that exist in at least one indicator
        existing_fields = []
        for field_name in mergeable_fields:
            if any(hasattr(ind, field_name) for ind in indicators):
                existing_fields.append(field_name)
        
        return existing_fields
    
    def _extract_field_values(self, indicators: List[NormalizedIndicator], 
                            field_name: str) -> Dict[str, Any]:
        """Extract field values from all indicators."""
        field_values = {}
        
        for indicator in indicators:
            if hasattr(indicator, field_name):
                value = getattr(indicator, field_name)
                field_values[indicator.id] = value
        
        return field_values
    
    def _map_merge_strategy_to_resolution_strategy(self, merge_strategy) -> ConflictResolutionStrategy:
        """Map merge strategy to conflict resolution strategy."""
        mapping = {
            'keep_highest_confidence': ConflictResolutionStrategy.HIGHEST_CONFIDENCE,
            'keep_most_recent': ConflictResolutionStrategy.MOST_RECENT,
            'keep_most_complete': ConflictResolutionStrategy.MOST_COMPLETE,
            'weighted_average': ConflictResolutionStrategy.WEIGHTED_MERGE,
            'concatenate_unique': ConflictResolutionStrategy.PRESERVE_ALL,
            'union_merge': ConflictResolutionStrategy.PRESERVE_ALL
        }
        
        strategy_name = merge_strategy.value if hasattr(merge_strategy, 'value') else str(merge_strategy)
        return mapping.get(strategy_name, ConflictResolutionStrategy.WEIGHTED_MERGE)
    
    def _validate_merge_result(self, merged_indicator: NormalizedIndicator,
                             source_indicators: List[NormalizedIndicator]) -> List[str]:
        """Validate the merge result."""
        warnings = []
        
        try:
            # Check that core fields are preserved
            if not hasattr(merged_indicator, 'value') or not merged_indicator.value:
                warnings.append("Merged indicator missing value field")
            
            if not hasattr(merged_indicator, 'indicator_type'):
                warnings.append("Merged indicator missing type field")
            
            # Check confidence bounds
            if hasattr(merged_indicator, 'confidence'):
                if merged_indicator.confidence < 0 or merged_indicator.confidence > 100:
                    warnings.append(f"Invalid confidence value: {merged_indicator.confidence}")
            
            # Check that merge preserved essential information
            source_tags = set()
            for ind in source_indicators:
                if hasattr(ind, 'tags') and ind.tags:
                    source_tags.update(ind.tags)
            
            merged_tags = set(merged_indicator.tags) if hasattr(merged_indicator, 'tags') and merged_indicator.tags else set()
            
            if source_tags and not merged_tags:
                warnings.append("All source tags were lost in merge")
            
        except Exception as e:
            warnings.append(f"Validation error: {e}")
        
        return warnings


class MergeOrchestrator:
    """Main orchestrator for merge operations."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize merge orchestrator."""
        self.config = config or {}
        
        # Initialize components
        self.deduplication_engine = DeduplicationEngine(
            self.config.get('deduplication', {})
        )
        self.confidence_engine = MergeConfidenceEngine(
            self.config.get('confidence', {})
        )
        self.policy_engine = MergePolicyEngine(
            self.config.get('policies', {})
        )
        self.lineage_tracker = LineageTracker(
            self.config.get('lineage', {})
        )
        
        # Initialize executor
        self.merge_executor = MergeExecutor(
            self.confidence_engine,
            self.policy_engine, 
            self.lineage_tracker,
            self.config.get('execution', {})
        )
        
        # Orchestration settings
        self.max_concurrent_merges = self.config.get('max_concurrent_merges', 10)
        self.enable_async_execution = self.config.get('enable_async_execution', True)
        
        logger.info("Merge orchestrator initialized")
    
    def merge_indicators(self, 
                        indicators: List[NormalizedIndicator],
                        rule_set_name: Optional[str] = None) -> Tuple[List[NormalizedIndicator], MergeExecutionSummary]:
        """Merge duplicate indicators in a batch."""
        
        start_time = datetime.utcnow()
        summary = MergeExecutionSummary(
            total_indicators=len(indicators),
            start_time=start_time
        )
        
        try:
            # Step 1: Find duplicates
            logger.info(f"Finding duplicates in {len(indicators)} indicators")
            duplicate_matches = self.deduplication_engine.find_duplicates(indicators)
            logger.info(f"Found {len(duplicate_matches)} potential duplicate matches")
            
            # Step 2: Group duplicates
            duplicate_groups = self.deduplication_engine.create_duplicate_groups(duplicate_matches)
            summary.duplicate_groups = len(duplicate_groups)
            
            # Step 3: Execute merges
            if self.enable_async_execution:
                merge_results = asyncio.run(self._execute_merges_async(
                    indicators, duplicate_matches, rule_set_name
                ))
            else:
                merge_results = self._execute_merges_sync(
                    indicators, duplicate_matches, rule_set_name
                )
            
            summary.merge_attempts = len(merge_results)
            
            # Step 4: Collect successful merges
            merged_indicators = []
            merged_ids = set()
            
            for result in merge_results:
                summary.results_by_status[result.status.value] = \
                    summary.results_by_status.get(result.status.value, 0) + 1
                
                if result.merge_decision:
                    summary.results_by_decision[result.merge_decision.value] = \
                        summary.results_by_decision.get(result.merge_decision.value, 0) + 1
                
                if result.status == MergeExecutionStatus.COMPLETED and result.merged_indicator:
                    merged_indicators.append(result.merged_indicator)
                    merged_ids.update(ind.id for ind in result.source_indicators)
                    summary.successful_merges += 1
                elif result.status == MergeExecutionStatus.FAILED:
                    summary.failed_merges += 1
                elif result.status == MergeExecutionStatus.SKIPPED:
                    summary.skipped_merges += 1
            
            # Step 5: Include non-merged indicators
            final_indicators = merged_indicators.copy()
            for indicator in indicators:
                if indicator.id not in merged_ids:
                    final_indicators.append(indicator)
            
            logger.info(f"Merge completed: {summary.successful_merges} successful, {summary.failed_merges} failed, {summary.skipped_merges} skipped")
            
            return final_indicators, summary
            
        except Exception as e:
            logger.error(f"Merge orchestration failed: {e}", exc_info=True)
            raise
        
        finally:
            summary.end_time = datetime.utcnow()
            summary.execution_time = (summary.end_time - start_time).total_seconds()
    
    async def _execute_merges_async(self, 
                                  indicators: List[NormalizedIndicator],
                                  duplicate_matches: List[DuplicateMatch],
                                  rule_set_name: Optional[str]) -> List[MergeResult]:
        """Execute merges asynchronously."""
        
        # Group indicators by match
        indicator_lookup = {ind.id: ind for ind in indicators}
        merge_tasks = []
        
        for match in duplicate_matches:
            match_indicators = [
                indicator_lookup[match.indicator1_id],
                indicator_lookup[match.indicator2_id]
            ]
            
            # Create async task
            task = self._execute_merge_async(match_indicators, match, rule_set_name)
            merge_tasks.append(task)
        
        # Execute with concurrency limit
        semaphore = asyncio.Semaphore(self.max_concurrent_merges)
        
        async def bounded_merge(task):
            async with semaphore:
                return await task
        
        bounded_tasks = [bounded_merge(task) for task in merge_tasks]
        merge_results = await asyncio.gather(*bounded_tasks, return_exceptions=True)
        
        # Handle exceptions
        final_results = []
        for i, result in enumerate(merge_results):
            if isinstance(result, Exception):
                # Create failed result
                failed_result = MergeResult(
                    source_indicators=[
                        indicator_lookup[duplicate_matches[i].indicator1_id],
                        indicator_lookup[duplicate_matches[i].indicator2_id]
                    ],
                    duplicate_match=duplicate_matches[i],
                    status=MergeExecutionStatus.FAILED,
                    error_message=str(result)
                )
                final_results.append(failed_result)
            else:
                final_results.append(result)
        
        return final_results
    
    async def _execute_merge_async(self,
                                 indicators: List[NormalizedIndicator],
                                 duplicate_match: DuplicateMatch,
                                 rule_set_name: Optional[str]) -> MergeResult:
        """Execute a single merge asynchronously."""
        # Run in thread pool to avoid blocking
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            self.merge_executor.execute_merge,
            indicators,
            duplicate_match,
            rule_set_name
        )
    
    def _execute_merges_sync(self,
                           indicators: List[NormalizedIndicator],
                           duplicate_matches: List[DuplicateMatch],
                           rule_set_name: Optional[str]) -> List[MergeResult]:
        """Execute merges synchronously."""
        
        indicator_lookup = {ind.id: ind for ind in indicators}
        merge_results = []
        
        for match in duplicate_matches:
            match_indicators = [
                indicator_lookup[match.indicator1_id],
                indicator_lookup[match.indicator2_id]
            ]
            
            result = self.merge_executor.execute_merge(
                match_indicators, match, rule_set_name
            )
            merge_results.append(result)
        
        return merge_results
    
    def get_merge_statistics(self) -> Dict[str, Any]:
        """Get merge statistics from lineage tracker."""
        stats = {
            'total_lineages': len(self.lineage_tracker.lineages),
            'merge_events_by_type': {},
            'source_attributions': {},
            'confidence_distribution': {}
        }
        
        for lineage in self.lineage_tracker.lineages.values():
            # Count events by type
            for event in lineage.merge_events:
                event_type = event.event_type.value
                stats['merge_events_by_type'][event_type] = \
                    stats['merge_events_by_type'].get(event_type, 0) + 1
            
            # Count source attributions
            for attribution in lineage.source_attributions:
                source = attribution.source_name
                stats['source_attributions'][source] = \
                    stats['source_attributions'].get(source, 0) + 1
        
        return stats