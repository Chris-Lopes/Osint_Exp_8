"""
Merge policies and rules engine for threat intelligence indicators.

This module defines configurable policies and rules that govern how indicators
should be merged, what conflicts should be resolved, and what merge strategies
to apply in different scenarios.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Any, Callable, Union
from dataclasses import dataclass, field
from enum import Enum
import re

try:
    from ..normalizers.schema import NormalizedIndicator, IndicatorType, TLPMarking, ConfidenceLevel
    from .deduplication import DuplicateMatch, DuplicateMatchType, DuplicateConfidence
    from .confidence import MergeConfidenceScore, MergeDecision
    from .lineage import ConflictResolutionStrategy
except ImportError:
    from normalizers.schema import NormalizedIndicator, IndicatorType, TLPMarking, ConfidenceLevel
    from merge.deduplication import DuplicateMatch, DuplicateMatchType, DuplicateConfidence
    from merge.confidence import MergeConfidenceScore, MergeDecision
    from merge.lineage import ConflictResolutionStrategy

logger = logging.getLogger(__name__)


class MergePolicy(Enum):
    """High-level merge policies."""
    CONSERVATIVE = "conservative"      # Only merge high-confidence matches
    MODERATE = "moderate"             # Balanced approach
    AGGRESSIVE = "aggressive"         # Merge more liberally
    CUSTOM = "custom"                # Use custom rules


class FieldMergeStrategy(Enum):
    """Strategies for merging specific fields."""
    KEEP_HIGHEST_CONFIDENCE = "keep_highest_confidence"
    KEEP_MOST_RECENT = "keep_most_recent"
    KEEP_MOST_COMPLETE = "keep_most_complete"
    CONCATENATE_UNIQUE = "concatenate_unique"
    WEIGHTED_AVERAGE = "weighted_average"
    UNION_MERGE = "union_merge"
    INTERSECTION_MERGE = "intersection_merge"
    CUSTOM_FUNCTION = "custom_function"


class MergeConditionType(Enum):
    """Types of merge conditions."""
    CONFIDENCE_THRESHOLD = "confidence_threshold"
    SOURCE_PRECEDENCE = "source_precedence"
    TIME_WINDOW = "time_window"
    TAG_OVERLAP = "tag_overlap"
    TLP_COMPATIBILITY = "tlp_compatibility"
    INDICATOR_TYPE = "indicator_type"
    CUSTOM_RULE = "custom_rule"


@dataclass
class MergeCondition:
    """A condition that must be met for merging."""
    
    condition_type: MergeConditionType
    parameters: Dict[str, Any] = field(default_factory=dict)
    required: bool = True
    description: str = ""
    
    def evaluate(self, indicators: List[NormalizedIndicator],
                duplicate_match: DuplicateMatch,
                confidence_score: MergeConfidenceScore) -> bool:
        """Evaluate if this condition is met."""
        try:
            if self.condition_type == MergeConditionType.CONFIDENCE_THRESHOLD:
                return self._evaluate_confidence_threshold(confidence_score)
            
            elif self.condition_type == MergeConditionType.SOURCE_PRECEDENCE:
                return self._evaluate_source_precedence(indicators)
            
            elif self.condition_type == MergeConditionType.TIME_WINDOW:
                return self._evaluate_time_window(indicators)
            
            elif self.condition_type == MergeConditionType.TAG_OVERLAP:
                return self._evaluate_tag_overlap(indicators)
            
            elif self.condition_type == MergeConditionType.TLP_COMPATIBILITY:
                return self._evaluate_tlp_compatibility(indicators)
            
            elif self.condition_type == MergeConditionType.INDICATOR_TYPE:
                return self._evaluate_indicator_type(indicators)
            
            elif self.condition_type == MergeConditionType.CUSTOM_RULE:
                return self._evaluate_custom_rule(indicators, duplicate_match, confidence_score)
            
            else:
                logger.warning(f"Unknown condition type: {self.condition_type}")
                return True  # Default to allow merge
                
        except Exception as e:
            logger.error(f"Failed to evaluate condition {self.condition_type}: {e}")
            return not self.required  # If required, fail; if optional, allow
    
    def _evaluate_confidence_threshold(self, confidence_score: MergeConfidenceScore) -> bool:
        """Evaluate confidence threshold condition."""
        threshold = self.parameters.get('minimum_confidence', 0.8)
        return confidence_score.confidence_score >= threshold
    
    def _evaluate_source_precedence(self, indicators: List[NormalizedIndicator]) -> bool:
        """Evaluate source precedence condition."""
        allowed_sources = self.parameters.get('allowed_sources', [])
        blocked_sources = self.parameters.get('blocked_sources', [])
        
        if not allowed_sources and not blocked_sources:
            return True
        
        indicator_sources = []
        for indicator in indicators:
            try:
                source_name = indicator.source_metadata.source_name.lower()
                indicator_sources.append(source_name)
            except Exception:
                continue
        
        # Check blocked sources
        if blocked_sources:
            for source in indicator_sources:
                if source in blocked_sources:
                    return False
        
        # Check allowed sources
        if allowed_sources:
            for source in indicator_sources:
                if source not in allowed_sources:
                    return False
        
        return True
    
    def _evaluate_time_window(self, indicators: List[NormalizedIndicator]) -> bool:
        """Evaluate time window condition."""
        max_age_days = self.parameters.get('max_age_days', 365)
        max_spread_days = self.parameters.get('max_spread_days', 30)
        
        timestamps = []
        cutoff_date = datetime.utcnow() - timedelta(days=max_age_days)
        
        for indicator in indicators:
            try:
                created = indicator.created
                if isinstance(created, str):
                    created = datetime.fromisoformat(created.replace('Z', '+00:00'))
                
                # Check age
                if created < cutoff_date:
                    return False
                
                timestamps.append(created)
                
            except Exception:
                continue
        
        # Check time spread
        if len(timestamps) > 1:
            time_span = max(timestamps) - min(timestamps)
            if time_span.days > max_spread_days:
                return False
        
        return True
    
    def _evaluate_tag_overlap(self, indicators: List[NormalizedIndicator]) -> bool:
        """Evaluate tag overlap condition."""
        min_overlap_ratio = self.parameters.get('min_overlap_ratio', 0.3)
        required_tags = self.parameters.get('required_tags', [])
        
        all_tags = []
        for indicator in indicators:
            if hasattr(indicator, 'tags') and indicator.tags:
                all_tags.extend([tag.lower() for tag in indicator.tags])
        
        if not all_tags:
            return len(required_tags) == 0
        
        # Check required tags
        if required_tags:
            tag_set = set(all_tags)
            for required_tag in required_tags:
                if required_tag.lower() not in tag_set:
                    return False
        
        # Check overlap ratio
        if len(indicators) > 1:
            tag_counts = {}
            for tag in all_tags:
                tag_counts[tag] = tag_counts.get(tag, 0) + 1
            
            overlapping_tags = sum(1 for count in tag_counts.values() if count > 1)
            total_unique_tags = len(tag_counts)
            
            if total_unique_tags > 0:
                overlap_ratio = overlapping_tags / total_unique_tags
                return overlap_ratio >= min_overlap_ratio
        
        return True
    
    def _evaluate_tlp_compatibility(self, indicators: List[NormalizedIndicator]) -> bool:
        """Evaluate TLP compatibility condition."""
        allow_different_tlp = self.parameters.get('allow_different_tlp', True)
        
        if allow_different_tlp:
            return True
        
        # Check if all indicators have same TLP
        tlp_markings = set()
        for indicator in indicators:
            if hasattr(indicator, 'tlp_marking'):
                tlp_markings.add(indicator.tlp_marking)
        
        return len(tlp_markings) <= 1
    
    def _evaluate_indicator_type(self, indicators: List[NormalizedIndicator]) -> bool:
        """Evaluate indicator type condition."""
        allowed_types = self.parameters.get('allowed_types', [])
        
        if not allowed_types:
            return True
        
        for indicator in indicators:
            if indicator.indicator_type not in allowed_types:
                return False
        
        return True
    
    def _evaluate_custom_rule(self, indicators: List[NormalizedIndicator],
                            duplicate_match: DuplicateMatch,
                            confidence_score: MergeConfidenceScore) -> bool:
        """Evaluate custom rule condition."""
        rule_function = self.parameters.get('rule_function')
        
        if callable(rule_function):
            try:
                return rule_function(indicators, duplicate_match, confidence_score)
            except Exception as e:
                logger.error(f"Custom rule function failed: {e}")
                return not self.required
        
        return True


@dataclass
class FieldMergeRule:
    """Rule for merging a specific field."""
    
    field_name: str
    merge_strategy: FieldMergeStrategy
    parameters: Dict[str, Any] = field(default_factory=dict)
    conditions: List[MergeCondition] = field(default_factory=list)
    custom_function: Optional[Callable] = None
    
    def can_merge_field(self, indicators: List[NormalizedIndicator],
                       duplicate_match: DuplicateMatch,
                       confidence_score: MergeConfidenceScore) -> bool:
        """Check if field can be merged based on conditions."""
        for condition in self.conditions:
            if not condition.evaluate(indicators, duplicate_match, confidence_score):
                return False
        return True
    
    def merge_field(self, indicators: List[NormalizedIndicator]) -> Any:
        """Merge field values from multiple indicators."""
        
        # Extract field values
        field_values = []
        for indicator in indicators:
            if hasattr(indicator, self.field_name):
                value = getattr(indicator, self.field_name)
                if value is not None:
                    field_values.append((indicator, value))
        
        if not field_values:
            return None
        
        if len(field_values) == 1:
            return field_values[0][1]
        
        # Apply merge strategy
        if self.merge_strategy == FieldMergeStrategy.KEEP_HIGHEST_CONFIDENCE:
            return self._merge_by_highest_confidence(field_values)
        
        elif self.merge_strategy == FieldMergeStrategy.KEEP_MOST_RECENT:
            return self._merge_by_most_recent(field_values)
        
        elif self.merge_strategy == FieldMergeStrategy.KEEP_MOST_COMPLETE:
            return self._merge_by_most_complete(field_values)
        
        elif self.merge_strategy == FieldMergeStrategy.CONCATENATE_UNIQUE:
            return self._merge_by_concatenation(field_values)
        
        elif self.merge_strategy == FieldMergeStrategy.UNION_MERGE:
            return self._merge_by_union(field_values)
        
        elif self.merge_strategy == FieldMergeStrategy.WEIGHTED_AVERAGE:
            return self._merge_by_weighted_average(field_values)
        
        elif self.merge_strategy == FieldMergeStrategy.CUSTOM_FUNCTION and self.custom_function:
            return self.custom_function(field_values, self.parameters)
        
        else:
            # Default: take first non-None value
            return field_values[0][1]
    
    def _merge_by_highest_confidence(self, field_values: List[Tuple]) -> Any:
        """Merge by selecting value from highest confidence indicator."""
        best_indicator, best_value = max(
            field_values, 
            key=lambda x: getattr(x[0], 'confidence', 0)
        )
        return best_value
    
    def _merge_by_most_recent(self, field_values: List[Tuple]) -> Any:
        """Merge by selecting value from most recent indicator."""
        def get_timestamp(indicator_value_pair):
            indicator = indicator_value_pair[0]
            try:
                created = indicator.created
                if isinstance(created, str):
                    created = datetime.fromisoformat(created.replace('Z', '+00:00'))
                return created
            except Exception:
                return datetime.min
        
        recent_indicator, recent_value = max(field_values, key=get_timestamp)
        return recent_value
    
    def _merge_by_most_complete(self, field_values: List[Tuple]) -> Any:
        """Merge by selecting most complete value."""
        def completeness_score(value):
            if isinstance(value, str):
                return len(value.strip())
            elif isinstance(value, list):
                return len(value)
            elif isinstance(value, dict):
                return len(value)
            else:
                return 1 if value else 0
        
        best_indicator, best_value = max(
            field_values,
            key=lambda x: completeness_score(x[1])
        )
        return best_value
    
    def _merge_by_concatenation(self, field_values: List[Tuple]) -> Any:
        """Merge by concatenating unique values."""
        if self.field_name == 'tags' or isinstance(field_values[0][1], list):
            # Handle list fields
            all_values = []
            for _, value in field_values:
                if isinstance(value, list):
                    all_values.extend(value)
                else:
                    all_values.append(value)
            
            # Remove duplicates while preserving order
            unique_values = []
            seen = set()
            for value in all_values:
                if value not in seen:
                    unique_values.append(value)
                    seen.add(value)
            
            return unique_values
        
        else:
            # Handle string fields
            unique_strings = []
            for _, value in field_values:
                if isinstance(value, str) and value.strip():
                    if value not in unique_strings:
                        unique_strings.append(value)
            
            return '; '.join(unique_strings) if unique_strings else None
    
    def _merge_by_union(self, field_values: List[Tuple]) -> Any:
        """Merge by taking union of all values."""
        if isinstance(field_values[0][1], (list, set)):
            all_values = set()
            for _, value in field_values:
                if isinstance(value, (list, set)):
                    all_values.update(value)
                else:
                    all_values.add(value)
            return list(all_values)
        
        return self._merge_by_concatenation(field_values)
    
    def _merge_by_weighted_average(self, field_values: List[Tuple]) -> Any:
        """Merge numeric values using weighted average."""
        try:
            numeric_values = []
            weights = []
            
            for indicator, value in field_values:
                if isinstance(value, (int, float)):
                    numeric_values.append(value)
                    # Use confidence as weight
                    weight = getattr(indicator, 'confidence', 50) / 100.0
                    weights.append(weight)
            
            if numeric_values and weights:
                weighted_sum = sum(v * w for v, w in zip(numeric_values, weights))
                total_weight = sum(weights)
                return weighted_sum / total_weight if total_weight > 0 else 0
                
        except Exception as e:
            logger.warning(f"Failed to calculate weighted average: {e}")
        
        # Fallback to first value
        return field_values[0][1]


@dataclass
class MergeRuleSet:
    """Complete set of merge rules for a specific scenario."""
    
    name: str
    description: str = ""
    merge_policy: MergePolicy = MergePolicy.MODERATE
    
    # Global conditions that must be met for any merge
    global_conditions: List[MergeCondition] = field(default_factory=list)
    
    # Field-specific merge rules
    field_rules: Dict[str, FieldMergeRule] = field(default_factory=dict)
    
    # Default strategies for fields not explicitly covered
    default_field_strategy: FieldMergeStrategy = FieldMergeStrategy.KEEP_HIGHEST_CONFIDENCE
    
    def can_merge(self, indicators: List[NormalizedIndicator],
                 duplicate_match: DuplicateMatch,
                 confidence_score: MergeConfidenceScore) -> bool:
        """Check if indicators can be merged under this rule set."""
        
        for condition in self.global_conditions:
            if not condition.evaluate(indicators, duplicate_match, confidence_score):
                logger.debug(f"Global condition failed: {condition.description}")
                return False
        
        return True
    
    def get_field_rule(self, field_name: str) -> FieldMergeRule:
        """Get merge rule for a specific field."""
        if field_name in self.field_rules:
            return self.field_rules[field_name]
        
        # Create default rule
        return FieldMergeRule(
            field_name=field_name,
            merge_strategy=self.default_field_strategy
        )


class MergePolicyEngine:
    """Engine for managing and applying merge policies."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize merge policy engine."""
        self.config = config or {}
        self.rule_sets: Dict[str, MergeRuleSet] = {}
        
        # Initialize default rule sets
        self._create_default_rule_sets()
        
        # Load custom rules from config
        self._load_custom_rules()
        
        logger.info("Merge policy engine initialized")
    
    def _create_default_rule_sets(self):
        """Create default merge rule sets."""
        
        # Conservative rule set
        conservative_conditions = [
            MergeCondition(
                condition_type=MergeConditionType.CONFIDENCE_THRESHOLD,
                parameters={'minimum_confidence': 0.9},
                description="Require very high confidence"
            ),
            MergeCondition(
                condition_type=MergeConditionType.TIME_WINDOW,
                parameters={'max_age_days': 30, 'max_spread_days': 7},
                description="Require recent and closely timed indicators"
            ),
            MergeCondition(
                condition_type=MergeConditionType.TLP_COMPATIBILITY,
                parameters={'allow_different_tlp': False},
                description="Require same TLP marking"
            )
        ]
        
        conservative_rules = MergeRuleSet(
            name="conservative",
            description="Conservative merge policy with strict conditions",
            merge_policy=MergePolicy.CONSERVATIVE,
            global_conditions=conservative_conditions
        )
        
        # Add conservative field rules
        conservative_rules.field_rules = {
            'tags': FieldMergeRule(
                field_name='tags',
                merge_strategy=FieldMergeStrategy.INTERSECTION_MERGE
            ),
            'confidence': FieldMergeRule(
                field_name='confidence',
                merge_strategy=FieldMergeStrategy.KEEP_HIGHEST_CONFIDENCE
            ),
            'threat_types': FieldMergeRule(
                field_name='threat_types',
                merge_strategy=FieldMergeStrategy.INTERSECTION_MERGE
            )
        }
        
        self.rule_sets['conservative'] = conservative_rules
        
        # Moderate rule set
        moderate_conditions = [
            MergeCondition(
                condition_type=MergeConditionType.CONFIDENCE_THRESHOLD,
                parameters={'minimum_confidence': 0.7},
                description="Require high confidence"
            ),
            MergeCondition(
                condition_type=MergeConditionType.TIME_WINDOW,
                parameters={'max_age_days': 90, 'max_spread_days': 30},
                description="Allow reasonable time spread"
            )
        ]
        
        moderate_rules = MergeRuleSet(
            name="moderate",
            description="Balanced merge policy",
            merge_policy=MergePolicy.MODERATE,
            global_conditions=moderate_conditions
        )
        
        # Add moderate field rules
        moderate_rules.field_rules = {
            'tags': FieldMergeRule(
                field_name='tags',
                merge_strategy=FieldMergeStrategy.UNION_MERGE
            ),
            'confidence': FieldMergeRule(
                field_name='confidence',
                merge_strategy=FieldMergeStrategy.WEIGHTED_AVERAGE
            ),
            'threat_types': FieldMergeRule(
                field_name='threat_types',
                merge_strategy=FieldMergeStrategy.UNION_MERGE
            ),
            'description': FieldMergeRule(
                field_name='description',
                merge_strategy=FieldMergeStrategy.KEEP_MOST_COMPLETE
            )
        }
        
        self.rule_sets['moderate'] = moderate_rules
        
        # Aggressive rule set
        aggressive_conditions = [
            MergeCondition(
                condition_type=MergeConditionType.CONFIDENCE_THRESHOLD,
                parameters={'minimum_confidence': 0.5},
                description="Allow moderate confidence"
            )
        ]
        
        aggressive_rules = MergeRuleSet(
            name="aggressive",
            description="Liberal merge policy for maximum consolidation",
            merge_policy=MergePolicy.AGGRESSIVE,
            global_conditions=aggressive_conditions
        )
        
        # Add aggressive field rules
        aggressive_rules.field_rules = {
            'tags': FieldMergeRule(
                field_name='tags',
                merge_strategy=FieldMergeStrategy.UNION_MERGE
            ),
            'confidence': FieldMergeRule(
                field_name='confidence',
                merge_strategy=FieldMergeStrategy.WEIGHTED_AVERAGE
            ),
            'threat_types': FieldMergeRule(
                field_name='threat_types',
                merge_strategy=FieldMergeStrategy.UNION_MERGE
            )
        }
        
        self.rule_sets['aggressive'] = aggressive_rules
    
    def _load_custom_rules(self):
        """Load custom rules from configuration."""
        custom_rules_config = self.config.get('custom_rules', {})
        
        for rule_name, rule_config in custom_rules_config.items():
            try:
                rule_set = self._parse_rule_config(rule_name, rule_config)
                self.rule_sets[rule_name] = rule_set
                logger.info(f"Loaded custom rule set: {rule_name}")
            except Exception as e:
                logger.error(f"Failed to load custom rule set {rule_name}: {e}")
    
    def _parse_rule_config(self, name: str, config: Dict[str, Any]) -> MergeRuleSet:
        """Parse rule set configuration."""
        # This would parse custom rule configurations
        # For now, return a basic rule set
        return MergeRuleSet(
            name=name,
            description=config.get('description', f'Custom rule set: {name}'),
            merge_policy=MergePolicy.CUSTOM
        )
    
    def get_rule_set(self, name: str) -> Optional[MergeRuleSet]:
        """Get rule set by name."""
        return self.rule_sets.get(name)
    
    def list_rule_sets(self) -> List[str]:
        """List available rule set names."""
        return list(self.rule_sets.keys())
    
    def evaluate_merge_decision(self, 
                              rule_set_name: str,
                              indicators: List[NormalizedIndicator],
                              duplicate_match: DuplicateMatch,
                              confidence_score: MergeConfidenceScore) -> bool:
        """Evaluate if merge should proceed under given rule set."""
        
        rule_set = self.get_rule_set(rule_set_name)
        if not rule_set:
            logger.warning(f"Unknown rule set: {rule_set_name}")
            return False
        
        return rule_set.can_merge(indicators, duplicate_match, confidence_score)
    
    def get_merge_strategy(self, 
                          rule_set_name: str,
                          field_name: str) -> FieldMergeRule:
        """Get merge strategy for a specific field."""
        
        rule_set = self.get_rule_set(rule_set_name)
        if not rule_set:
            # Return default rule
            return FieldMergeRule(
                field_name=field_name,
                merge_strategy=FieldMergeStrategy.KEEP_HIGHEST_CONFIDENCE
            )
        
        return rule_set.get_field_rule(field_name)
    
    def add_custom_rule_set(self, rule_set: MergeRuleSet):
        """Add a custom rule set."""
        self.rule_sets[rule_set.name] = rule_set
        logger.info(f"Added custom rule set: {rule_set.name}")
    
    def validate_rule_set(self, rule_set: MergeRuleSet) -> List[str]:
        """Validate a rule set for consistency and completeness."""
        issues = []
        
        # Check for required fields
        if not rule_set.name:
            issues.append("Rule set must have a name")
        
        # Validate global conditions
        for i, condition in enumerate(rule_set.global_conditions):
            if not condition.condition_type:
                issues.append(f"Global condition {i} missing condition_type")
        
        # Validate field rules
        for field_name, rule in rule_set.field_rules.items():
            if rule.field_name != field_name:
                issues.append(f"Field rule key '{field_name}' doesn't match rule field_name '{rule.field_name}'")
            
            if not rule.merge_strategy:
                issues.append(f"Field rule for '{field_name}' missing merge_strategy")
        
        return issues