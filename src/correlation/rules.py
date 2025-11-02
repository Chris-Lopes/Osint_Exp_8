"""
Correlation rules engine for threat intelligence knowledge graphs.

This module implements a comprehensive rules engine that defines relationship types,
scoring criteria, and confidence thresholds for different types of connections
between threat intelligence entities.
"""

import logging
import statistics
import math
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any, Optional, Set, Tuple, Union, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, Counter
import re
import json

try:
    from ..normalizers.schema import NormalizedIndicator, IndicatorType
    from .engine import GraphNode, GraphRelationship, NodeType, RelationshipType, CorrelationResult
except ImportError:
    from normalizers.schema import NormalizedIndicator, IndicatorType
    from correlation.engine import GraphNode, GraphRelationship, NodeType, RelationshipType, CorrelationResult

logger = logging.getLogger(__name__)


class RuleType(Enum):
    """Types of correlation rules."""
    INFRASTRUCTURE = "infrastructure"
    TEMPORAL = "temporal"  
    BEHAVIORAL = "behavioral"
    ATTRIBUTION = "attribution"
    TECHNICAL = "technical"
    CONTEXTUAL = "contextual"


class MatchOperator(Enum):
    """Operators for rule matching."""
    EQUALS = "equals"
    CONTAINS = "contains"
    STARTS_WITH = "starts_with"
    ENDS_WITH = "ends_with"
    REGEX = "regex"
    IN_LIST = "in_list"
    GREATER_THAN = "greater_than"
    LESS_THAN = "less_than"
    BETWEEN = "between"
    EXISTS = "exists"
    NOT_EXISTS = "not_exists"


@dataclass
class RuleCondition:
    """Individual condition within a correlation rule."""
    
    field_path: str  # e.g., "properties.asn" or "node_type"
    operator: MatchOperator
    value: Any
    weight: float = 1.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'field_path': self.field_path,
            'operator': self.operator.value,
            'value': self.value,
            'weight': self.weight
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'RuleCondition':
        """Create from dictionary."""
        return cls(
            field_path=data['field_path'],
            operator=MatchOperator(data['operator']),
            value=data['value'],
            weight=data.get('weight', 1.0)
        )


@dataclass
class CorrelationRule:
    """Definition of a correlation rule."""
    
    rule_id: str
    name: str
    description: str
    rule_type: RuleType
    relationship_type: RelationshipType
    
    # Rule conditions
    source_conditions: List[RuleCondition] = field(default_factory=list)
    target_conditions: List[RuleCondition] = field(default_factory=list)
    
    # Scoring parameters
    base_weight: float = 1.0
    confidence_threshold: float = 0.5
    max_confidence: float = 1.0
    
    # Temporal constraints
    max_time_difference: Optional[timedelta] = None
    temporal_decay_factor: float = 1.0
    
    # Rule metadata
    enabled: bool = True
    priority: int = 100
    tags: List[str] = field(default_factory=list)
    author: str = ""
    created_date: Optional[datetime] = None
    last_updated: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'rule_id': self.rule_id,
            'name': self.name,
            'description': self.description,
            'rule_type': self.rule_type.value,
            'relationship_type': self.relationship_type.value,
            'source_conditions': [cond.to_dict() for cond in self.source_conditions],
            'target_conditions': [cond.to_dict() for cond in self.target_conditions],
            'scoring': {
                'base_weight': self.base_weight,
                'confidence_threshold': self.confidence_threshold,
                'max_confidence': self.max_confidence
            },
            'temporal': {
                'max_time_difference': self.max_time_difference.total_seconds() if self.max_time_difference else None,
                'temporal_decay_factor': self.temporal_decay_factor
            },
            'metadata': {
                'enabled': self.enabled,
                'priority': self.priority,
                'tags': self.tags,
                'author': self.author,
                'created_date': self.created_date.isoformat() if self.created_date else None,
                'last_updated': self.last_updated.isoformat() if self.last_updated else None
            }
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CorrelationRule':
        """Create from dictionary."""
        rule = cls(
            rule_id=data['rule_id'],
            name=data['name'],
            description=data['description'],
            rule_type=RuleType(data['rule_type']),
            relationship_type=RelationshipType(data['relationship_type'])
        )
        
        # Conditions
        rule.source_conditions = [
            RuleCondition.from_dict(cond_data) 
            for cond_data in data.get('source_conditions', [])
        ]
        rule.target_conditions = [
            RuleCondition.from_dict(cond_data) 
            for cond_data in data.get('target_conditions', [])
        ]
        
        # Scoring
        scoring = data.get('scoring', {})
        rule.base_weight = scoring.get('base_weight', 1.0)
        rule.confidence_threshold = scoring.get('confidence_threshold', 0.5)
        rule.max_confidence = scoring.get('max_confidence', 1.0)
        
        # Temporal
        temporal = data.get('temporal', {})
        if temporal.get('max_time_difference'):
            rule.max_time_difference = timedelta(seconds=temporal['max_time_difference'])
        rule.temporal_decay_factor = temporal.get('temporal_decay_factor', 1.0)
        
        # Metadata
        metadata = data.get('metadata', {})
        rule.enabled = metadata.get('enabled', True)
        rule.priority = metadata.get('priority', 100)
        rule.tags = metadata.get('tags', [])
        rule.author = metadata.get('author', '')
        
        if metadata.get('created_date'):
            rule.created_date = datetime.fromisoformat(metadata['created_date'])
        if metadata.get('last_updated'):
            rule.last_updated = datetime.fromisoformat(metadata['last_updated'])
        
        return rule


@dataclass
class RuleMatchResult:
    """Result of rule matching."""
    
    rule_id: str
    matched: bool = False
    confidence: float = 0.0
    weight: float = 0.0
    
    # Match details
    source_matches: List[Tuple[str, bool, float]] = field(default_factory=list)  # condition, matched, score
    target_matches: List[Tuple[str, bool, float]] = field(default_factory=list)
    
    # Temporal analysis
    temporal_distance: Optional[float] = None
    temporal_decay: float = 1.0
    
    # Additional context
    match_context: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'rule_id': self.rule_id,
            'matched': self.matched,
            'confidence': self.confidence,
            'weight': self.weight,
            'source_matches': self.source_matches,
            'target_matches': self.target_matches,
            'temporal': {
                'temporal_distance': self.temporal_distance,
                'temporal_decay': self.temporal_decay
            },
            'match_context': self.match_context
        }


class RuleEngine:
    """Core rule matching engine."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize rule engine."""
        self.config = config or {}
        
        # Compiled regex cache
        self._regex_cache = {}
        
        logger.debug("Rule engine initialized")
    
    def evaluate_rule(self, 
                     rule: CorrelationRule,
                     source_node: GraphNode,
                     target_node: GraphNode) -> RuleMatchResult:
        """Evaluate a rule against two nodes."""
        
        result = RuleMatchResult(rule_id=rule.rule_id)
        
        # Skip disabled rules
        if not rule.enabled:
            return result
        
        # Evaluate source conditions
        source_score = self._evaluate_conditions(rule.source_conditions, source_node)
        result.source_matches = [(cond.field_path, score > 0, score) for cond, score in source_score]
        
        # Evaluate target conditions  
        target_score = self._evaluate_conditions(rule.target_conditions, target_node)
        result.target_matches = [(cond.field_path, score > 0, score) for cond, score in target_score]
        
        # Calculate overall match scores
        source_total_score = sum(score for _, score in source_score)
        target_total_score = sum(score for _, score in target_score)
        source_max_score = sum(cond.weight for cond in rule.source_conditions) or 1.0
        target_max_score = sum(cond.weight for cond in rule.target_conditions) or 1.0
        
        # Normalize scores
        source_normalized = source_total_score / source_max_score
        target_normalized = target_total_score / target_max_score
        
        # Calculate temporal decay if applicable
        temporal_decay = self._calculate_temporal_decay(rule, source_node, target_node)
        result.temporal_decay = temporal_decay
        
        # Calculate final confidence
        base_confidence = (source_normalized + target_normalized) / 2
        final_confidence = min(base_confidence * temporal_decay, rule.max_confidence)
        
        # Apply rule weight
        final_weight = rule.base_weight * final_confidence
        
        # Check if rule matches
        result.matched = final_confidence >= rule.confidence_threshold
        result.confidence = final_confidence
        result.weight = final_weight
        
        return result
    
    def _evaluate_conditions(self, 
                           conditions: List[RuleCondition], 
                           node: GraphNode) -> List[Tuple[RuleCondition, float]]:
        """Evaluate conditions against a node."""
        
        results = []
        
        for condition in conditions:
            score = self._evaluate_condition(condition, node)
            results.append((condition, score))
        
        return results
    
    def _evaluate_condition(self, condition: RuleCondition, node: GraphNode) -> float:
        """Evaluate a single condition."""
        
        # Get field value from node
        field_value = self._get_field_value(node, condition.field_path)
        
        if field_value is None and condition.operator not in [MatchOperator.NOT_EXISTS]:
            return 0.0
        
        # Evaluate based on operator
        match_score = 0.0
        
        try:
            if condition.operator == MatchOperator.EQUALS:
                match_score = 1.0 if field_value == condition.value else 0.0
                
            elif condition.operator == MatchOperator.CONTAINS:
                if isinstance(field_value, str) and isinstance(condition.value, str):
                    match_score = 1.0 if condition.value.lower() in field_value.lower() else 0.0
                elif isinstance(field_value, (list, set)):
                    match_score = 1.0 if condition.value in field_value else 0.0
                    
            elif condition.operator == MatchOperator.STARTS_WITH:
                if isinstance(field_value, str) and isinstance(condition.value, str):
                    match_score = 1.0 if field_value.lower().startswith(condition.value.lower()) else 0.0
                    
            elif condition.operator == MatchOperator.ENDS_WITH:
                if isinstance(field_value, str) and isinstance(condition.value, str):
                    match_score = 1.0 if field_value.lower().endswith(condition.value.lower()) else 0.0
                    
            elif condition.operator == MatchOperator.REGEX:
                if isinstance(field_value, str):
                    regex_pattern = self._get_compiled_regex(condition.value)
                    match_score = 1.0 if regex_pattern.search(field_value) else 0.0
                    
            elif condition.operator == MatchOperator.IN_LIST:
                match_score = 1.0 if field_value in condition.value else 0.0
                
            elif condition.operator == MatchOperator.GREATER_THAN:
                if isinstance(field_value, (int, float)) and isinstance(condition.value, (int, float)):
                    match_score = 1.0 if field_value > condition.value else 0.0
                    
            elif condition.operator == MatchOperator.LESS_THAN:
                if isinstance(field_value, (int, float)) and isinstance(condition.value, (int, float)):
                    match_score = 1.0 if field_value < condition.value else 0.0
                    
            elif condition.operator == MatchOperator.BETWEEN:
                if isinstance(field_value, (int, float)) and isinstance(condition.value, (list, tuple)) and len(condition.value) == 2:
                    min_val, max_val = condition.value
                    match_score = 1.0 if min_val <= field_value <= max_val else 0.0
                    
            elif condition.operator == MatchOperator.EXISTS:
                match_score = 1.0 if field_value is not None else 0.0
                
            elif condition.operator == MatchOperator.NOT_EXISTS:
                match_score = 1.0 if field_value is None else 0.0
                
        except Exception as e:
            logger.warning(f"Error evaluating condition {condition.field_path}: {e}")
            match_score = 0.0
        
        return match_score * condition.weight
    
    def _get_field_value(self, node: GraphNode, field_path: str) -> Any:
        """Get field value from node using dot notation path."""
        
        try:
            # Start with the node object
            current_value = node
            
            # Navigate the path
            for part in field_path.split('.'):
                if hasattr(current_value, part):
                    current_value = getattr(current_value, part)
                elif isinstance(current_value, dict) and part in current_value:
                    current_value = current_value[part]
                else:
                    return None
            
            return current_value
            
        except Exception as e:
            logger.debug(f"Error getting field value {field_path}: {e}")
            return None
    
    def _get_compiled_regex(self, pattern: str) -> re.Pattern:
        """Get compiled regex pattern (cached)."""
        
        if pattern not in self._regex_cache:
            try:
                self._regex_cache[pattern] = re.compile(pattern, re.IGNORECASE)
            except re.error as e:
                logger.warning(f"Invalid regex pattern '{pattern}': {e}")
                # Use a pattern that never matches
                self._regex_cache[pattern] = re.compile(r'(?!.*)')
        
        return self._regex_cache[pattern]
    
    def _calculate_temporal_decay(self, 
                                rule: CorrelationRule,
                                source_node: GraphNode,
                                target_node: GraphNode) -> float:
        """Calculate temporal decay factor."""
        
        # If no temporal constraints, no decay
        if not rule.max_time_difference or rule.temporal_decay_factor == 1.0:
            return 1.0
        
        # Get timestamps
        source_time = getattr(source_node, 'first_observed', None)
        target_time = getattr(target_node, 'first_observed', None)
        
        if not source_time or not target_time:
            return 1.0  # No decay if timestamps unavailable
        
        # Calculate time difference
        time_diff = abs(source_time - target_time)
        
        # Apply decay if beyond threshold
        if time_diff > rule.max_time_difference:
            # Exponential decay
            decay_ratio = time_diff.total_seconds() / rule.max_time_difference.total_seconds()
            decay_factor = math.exp(-decay_ratio * rule.temporal_decay_factor)
            return max(decay_factor, 0.1)  # Minimum 10% strength
        
        return 1.0


class RuleManager:
    """Manages correlation rules and rule sets."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize rule manager."""
        self.config = config or {}
        
        # Rule storage
        self._rules: Dict[str, CorrelationRule] = {}
        self._rules_by_type: Dict[RuleType, List[str]] = defaultdict(list)
        
        # Rule engine
        self.engine = RuleEngine(self.config.get('engine', {}))
        
        # Load default rules
        if self.config.get('load_default_rules', True):
            self._load_default_rules()
        
        logger.info(f"Rule manager initialized with {len(self._rules)} rules")
    
    def add_rule(self, rule: CorrelationRule) -> None:
        """Add a correlation rule."""
        
        # Set timestamps
        now = datetime.now(timezone.utc)
        if not rule.created_date:
            rule.created_date = now
        rule.last_updated = now
        
        # Store rule
        self._rules[rule.rule_id] = rule
        self._rules_by_type[rule.rule_type].append(rule.rule_id)
        
        logger.debug(f"Added rule: {rule.rule_id} ({rule.name})")
    
    def remove_rule(self, rule_id: str) -> bool:
        """Remove a correlation rule."""
        
        if rule_id in self._rules:
            rule = self._rules[rule_id]
            
            # Remove from type index
            if rule_id in self._rules_by_type[rule.rule_type]:
                self._rules_by_type[rule.rule_type].remove(rule_id)
            
            # Remove rule
            del self._rules[rule_id]
            
            logger.debug(f"Removed rule: {rule_id}")
            return True
        
        return False
    
    def get_rule(self, rule_id: str) -> Optional[CorrelationRule]:
        """Get a rule by ID."""
        return self._rules.get(rule_id)
    
    def get_rules_by_type(self, rule_type: RuleType) -> List[CorrelationRule]:
        """Get rules by type."""
        rule_ids = self._rules_by_type.get(rule_type, [])
        return [self._rules[rule_id] for rule_id in rule_ids if rule_id in self._rules]
    
    def get_all_rules(self, enabled_only: bool = True) -> List[CorrelationRule]:
        """Get all rules."""
        rules = list(self._rules.values())
        
        if enabled_only:
            rules = [rule for rule in rules if rule.enabled]
        
        # Sort by priority (higher priority first)
        rules.sort(key=lambda r: r.priority, reverse=True)
        
        return rules
    
    def evaluate_rules(self, 
                      source_node: GraphNode,
                      target_node: GraphNode,
                      rule_types: Optional[List[RuleType]] = None) -> List[RuleMatchResult]:
        """Evaluate rules against two nodes."""
        
        results = []
        
        # Get applicable rules
        if rule_types:
            applicable_rules = []
            for rule_type in rule_types:
                applicable_rules.extend(self.get_rules_by_type(rule_type))
        else:
            applicable_rules = self.get_all_rules(enabled_only=True)
        
        # Evaluate each rule
        for rule in applicable_rules:
            try:
                result = self.engine.evaluate_rule(rule, source_node, target_node)
                results.append(result)
            except Exception as e:
                logger.warning(f"Error evaluating rule {rule.rule_id}: {e}")
        
        return results
    
    def find_matching_rules(self, 
                           source_node: GraphNode,
                           target_node: GraphNode,
                           min_confidence: float = 0.5) -> List[RuleMatchResult]:
        """Find rules that match between two nodes."""
        
        all_results = self.evaluate_rules(source_node, target_node)
        
        # Filter by confidence and matching status
        matching_results = [
            result for result in all_results
            if result.matched and result.confidence >= min_confidence
        ]
        
        # Sort by confidence (highest first)
        matching_results.sort(key=lambda r: r.confidence, reverse=True)
        
        return matching_results
    
    def export_rules(self, file_path: str) -> None:
        """Export rules to JSON file."""
        
        rules_data = {
            'rules': [rule.to_dict() for rule in self._rules.values()],
            'metadata': {
                'exported_at': datetime.now(timezone.utc).isoformat(),
                'rule_count': len(self._rules),
                'version': '1.0'
            }
        }
        
        with open(file_path, 'w') as f:
            json.dump(rules_data, f, indent=2)
        
        logger.info(f"Exported {len(self._rules)} rules to {file_path}")
    
    def import_rules(self, file_path: str, merge: bool = True) -> int:
        """Import rules from JSON file."""
        
        with open(file_path, 'r') as f:
            rules_data = json.load(f)
        
        imported_count = 0
        
        for rule_dict in rules_data.get('rules', []):
            try:
                rule = CorrelationRule.from_dict(rule_dict)
                
                # Check for conflicts
                if not merge and rule.rule_id in self._rules:
                    logger.warning(f"Skipping duplicate rule: {rule.rule_id}")
                    continue
                
                self.add_rule(rule)
                imported_count += 1
                
            except Exception as e:
                logger.warning(f"Failed to import rule {rule_dict.get('rule_id', 'unknown')}: {e}")
        
        logger.info(f"Imported {imported_count} rules from {file_path}")
        return imported_count
    
    def _load_default_rules(self) -> None:
        """Load default correlation rules."""
        
        # Infrastructure sharing rule
        infrastructure_rule = CorrelationRule(
            rule_id="infra_asn_sharing",
            name="ASN Infrastructure Sharing",
            description="Correlates indicators sharing the same ASN",
            rule_type=RuleType.INFRASTRUCTURE,
            relationship_type=RelationshipType.INFRASTRUCTURE_SHARING,
            source_conditions=[
                RuleCondition("node_type", MatchOperator.EQUALS, NodeType.INDICATOR, 1.0),
                RuleCondition("properties.asn", MatchOperator.EXISTS, None, 2.0)
            ],
            target_conditions=[
                RuleCondition("node_type", MatchOperator.EQUALS, NodeType.INDICATOR, 1.0),
                RuleCondition("properties.asn", MatchOperator.EXISTS, None, 2.0)
            ],
            base_weight=0.8,
            confidence_threshold=0.6
        )
        
        # Add custom evaluation for ASN matching
        self.add_rule(infrastructure_rule)
        
        # Temporal correlation rule
        temporal_rule = CorrelationRule(
            rule_id="temporal_proximity",
            name="Temporal Proximity Correlation",
            description="Correlates indicators observed within the same time window",
            rule_type=RuleType.TEMPORAL,
            relationship_type=RelationshipType.TEMPORAL_CORRELATION,
            source_conditions=[
                RuleCondition("node_type", MatchOperator.EQUALS, NodeType.INDICATOR, 1.0),
                RuleCondition("first_observed", MatchOperator.EXISTS, None, 1.0)
            ],
            target_conditions=[
                RuleCondition("node_type", MatchOperator.EQUALS, NodeType.INDICATOR, 1.0),
                RuleCondition("first_observed", MatchOperator.EXISTS, None, 1.0)
            ],
            base_weight=0.6,
            confidence_threshold=0.5,
            max_time_difference=timedelta(hours=24),
            temporal_decay_factor=2.0
        )
        
        self.add_rule(temporal_rule)
        
        # Behavioral similarity rule
        behavioral_rule = CorrelationRule(
            rule_id="tag_similarity",
            name="Tag Similarity Correlation",
            description="Correlates indicators with similar behavioral tags",
            rule_type=RuleType.BEHAVIORAL,
            relationship_type=RelationshipType.BEHAVIORAL_SIMILARITY,
            source_conditions=[
                RuleCondition("node_type", MatchOperator.EQUALS, NodeType.INDICATOR, 1.0),
                RuleCondition("properties.tags", MatchOperator.EXISTS, None, 1.0)
            ],
            target_conditions=[
                RuleCondition("node_type", MatchOperator.EQUALS, NodeType.INDICATOR, 1.0),
                RuleCondition("properties.tags", MatchOperator.EXISTS, None, 1.0)
            ],
            base_weight=0.7,
            confidence_threshold=0.6
        )
        
        self.add_rule(behavioral_rule)
        
        # Technique usage correlation rule
        technique_rule = CorrelationRule(
            rule_id="technique_usage",
            name="Technique Usage Correlation",
            description="Correlates indicators using the same techniques",
            rule_type=RuleType.TECHNICAL,
            relationship_type=RelationshipType.TECHNIQUE_USAGE,
            source_conditions=[
                RuleCondition("node_type", MatchOperator.EQUALS, NodeType.INDICATOR, 1.0),
                RuleCondition("properties.mitre_techniques", MatchOperator.EXISTS, None, 2.0)
            ],
            target_conditions=[
                RuleCondition("node_type", MatchOperator.EQUALS, NodeType.INDICATOR, 1.0),
                RuleCondition("properties.mitre_techniques", MatchOperator.EXISTS, None, 2.0)
            ],
            base_weight=0.9,
            confidence_threshold=0.7
        )
        
        self.add_rule(technique_rule)
        
        # Attribution rule for same threat actor
        attribution_rule = CorrelationRule(
            rule_id="threat_actor_attribution", 
            name="Threat Actor Attribution",
            description="Correlates indicators attributed to the same threat actor",
            rule_type=RuleType.ATTRIBUTION,
            relationship_type=RelationshipType.ATTRIBUTION,
            source_conditions=[
                RuleCondition("properties.threat_actor", MatchOperator.EXISTS, None, 3.0)
            ],
            target_conditions=[
                RuleCondition("properties.threat_actor", MatchOperator.EXISTS, None, 3.0)
            ],
            base_weight=1.0,
            confidence_threshold=0.8
        )
        
        self.add_rule(attribution_rule)
        
        logger.debug(f"Loaded {len(self._rules)} default rules")


class CorrelationRulesEngine:
    """High-level correlation rules engine integrating all components."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize correlation rules engine."""
        self.config = config or {}
        
        # Initialize rule manager
        self.rule_manager = RuleManager(self.config.get('rules', {}))
        
        # Correlation settings
        self.min_confidence = self.config.get('min_confidence', 0.5)
        self.max_relationships_per_node = self.config.get('max_relationships_per_node', 100)
        
        logger.info("Correlation rules engine initialized")
    
    def correlate_nodes(self, 
                       nodes: Dict[str, GraphNode],
                       existing_relationships: Optional[Dict[str, GraphRelationship]] = None) -> Dict[str, GraphRelationship]:
        """Apply correlation rules to find relationships between nodes."""
        
        start_time = datetime.now(timezone.utc)
        
        # Track existing relationships to avoid duplicates
        existing_pairs = set()
        if existing_relationships:
            for rel in existing_relationships.values():
                existing_pairs.add((rel.source_node_id, rel.target_node_id))
                existing_pairs.add((rel.target_node_id, rel.source_node_id))
        
        new_relationships = {}
        node_relationship_counts = defaultdict(int)
        
        # Get node IDs as list for iteration
        node_ids = list(nodes.keys())
        total_pairs = len(node_ids) * (len(node_ids) - 1) // 2
        
        logger.info(f"Correlating {len(nodes)} nodes ({total_pairs} pairs) using {len(self.rule_manager.get_all_rules())} rules")
        
        processed_pairs = 0
        
        # Evaluate all node pairs
        for i, source_id in enumerate(node_ids):
            # Skip if source node has too many relationships
            if node_relationship_counts[source_id] >= self.max_relationships_per_node:
                continue
            
            source_node = nodes[source_id]
            
            for target_id in node_ids[i+1:]:
                # Skip if target node has too many relationships
                if node_relationship_counts[target_id] >= self.max_relationships_per_node:
                    continue
                
                # Skip if relationship already exists
                if (source_id, target_id) in existing_pairs:
                    continue
                
                target_node = nodes[target_id]
                processed_pairs += 1
                
                # Find matching rules
                matching_results = self.rule_manager.find_matching_rules(
                    source_node, target_node, self.min_confidence
                )
                
                if matching_results:
                    # Use the best matching rule
                    best_result = matching_results[0]
                    rule = self.rule_manager.get_rule(best_result.rule_id)
                    
                    if rule:
                        # Create relationship
                        relationship = self._create_relationship_from_rule(
                            source_node, target_node, rule, best_result
                        )
                        
                        new_relationships[relationship.relationship_id] = relationship
                        
                        # Update counts
                        node_relationship_counts[source_id] += 1
                        node_relationship_counts[target_id] += 1
                
                # Log progress periodically
                if processed_pairs % 10000 == 0:
                    logger.debug(f"Processed {processed_pairs}/{total_pairs} pairs, found {len(new_relationships)} relationships")
        
        execution_time = (datetime.now(timezone.utc) - start_time).total_seconds()
        
        logger.info(f"Correlation completed: processed {processed_pairs} pairs, "
                   f"found {len(new_relationships)} new relationships in {execution_time:.2f}s")
        
        return new_relationships
    
    def _create_relationship_from_rule(self, 
                                     source_node: GraphNode,
                                     target_node: GraphNode,
                                     rule: CorrelationRule,
                                     match_result: RuleMatchResult) -> GraphRelationship:
        """Create a relationship from rule match result."""
        
        relationship_id = f"rel_{source_node.node_id}_{target_node.node_id}_{rule.rule_id}"
        
        # Build evidence from match results
        evidence = {
            'rule_id': rule.rule_id,
            'rule_name': rule.name,
            'source_matches': match_result.source_matches,
            'target_matches': match_result.target_matches,
            'temporal_analysis': {
                'temporal_distance': match_result.temporal_distance,
                'temporal_decay': match_result.temporal_decay
            }
        }
        
        # Create relationship
        relationship = GraphRelationship(
            relationship_id=relationship_id,
            source_node_id=source_node.node_id,
            target_node_id=target_node.node_id,
            relationship_type=rule.relationship_type,
            weight=match_result.weight,
            confidence=match_result.confidence,
            evidence=evidence,
            first_observed=datetime.now(timezone.utc),
            last_observed=datetime.now(timezone.utc),
            properties={
                'rule_type': rule.rule_type.value,
                'rule_priority': rule.priority,
                'rule_tags': rule.tags
            }
        )
        
        return relationship
    
    def validate_rules(self) -> Dict[str, Any]:
        """Validate loaded rules for correctness."""
        
        validation_results = {
            'total_rules': len(self.rule_manager._rules),
            'enabled_rules': len(self.rule_manager.get_all_rules(enabled_only=True)),
            'disabled_rules': len(self.rule_manager.get_all_rules(enabled_only=False)) - len(self.rule_manager.get_all_rules(enabled_only=True)),
            'rules_by_type': {},
            'validation_errors': [],
            'warnings': []
        }
        
        # Count by type
        for rule_type in RuleType:
            type_rules = self.rule_manager.get_rules_by_type(rule_type)
            validation_results['rules_by_type'][rule_type.value] = len(type_rules)
        
        # Validate individual rules
        for rule in self.rule_manager.get_all_rules(enabled_only=False):
            try:
                self._validate_rule(rule, validation_results)
            except Exception as e:
                validation_results['validation_errors'].append(
                    f"Error validating rule {rule.rule_id}: {e}"
                )
        
        return validation_results
    
    def _validate_rule(self, rule: CorrelationRule, results: Dict[str, Any]) -> None:
        """Validate a single rule."""
        
        # Check for empty conditions
        if not rule.source_conditions and not rule.target_conditions:
            results['validation_errors'].append(
                f"Rule {rule.rule_id}: No conditions defined"
            )
        
        # Check confidence threshold
        if not 0.0 <= rule.confidence_threshold <= 1.0:
            results['validation_errors'].append(
                f"Rule {rule.rule_id}: Invalid confidence threshold {rule.confidence_threshold}"
            )
        
        # Check weight values
        if rule.base_weight < 0:
            results['validation_errors'].append(
                f"Rule {rule.rule_id}: Negative base weight {rule.base_weight}"
            )
        
        # Validate conditions
        for i, condition in enumerate(rule.source_conditions):
            try:
                self._validate_condition(condition, f"{rule.rule_id}.source_conditions[{i}]", results)
            except Exception as e:
                results['validation_errors'].append(
                    f"Rule {rule.rule_id}.source_conditions[{i}]: {e}"
                )
        
        for i, condition in enumerate(rule.target_conditions):
            try:
                self._validate_condition(condition, f"{rule.rule_id}.target_conditions[{i}]", results)
            except Exception as e:
                results['validation_errors'].append(
                    f"Rule {rule.rule_id}.target_conditions[{i}]: {e}"
                )
    
    def _validate_condition(self, condition: RuleCondition, context: str, results: Dict[str, Any]) -> None:
        """Validate a rule condition."""
        
        # Check field path
        if not condition.field_path:
            results['validation_errors'].append(f"{context}: Empty field path")
        
        # Check weight
        if condition.weight < 0:
            results['validation_errors'].append(f"{context}: Negative weight {condition.weight}")
        
        # Validate regex patterns
        if condition.operator == MatchOperator.REGEX:
            try:
                re.compile(str(condition.value))
            except re.error as e:
                results['validation_errors'].append(f"{context}: Invalid regex '{condition.value}': {e}")
        
        # Validate BETWEEN operator
        if condition.operator == MatchOperator.BETWEEN:
            if not isinstance(condition.value, (list, tuple)) or len(condition.value) != 2:
                results['validation_errors'].append(f"{context}: BETWEEN operator requires list/tuple of 2 values")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get correlation engine statistics."""
        
        return {
            'rules': {
                'total': len(self.rule_manager._rules),
                'enabled': len(self.rule_manager.get_all_rules(enabled_only=True)),
                'by_type': {
                    rule_type.value: len(self.rule_manager.get_rules_by_type(rule_type))
                    for rule_type in RuleType
                }
            },
            'configuration': {
                'min_confidence': self.min_confidence,
                'max_relationships_per_node': self.max_relationships_per_node
            }
        }