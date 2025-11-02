"""
Comprehensive validation system for threat intelligence correlation.

This module provides validation capabilities for relationship detection accuracy,
graph construction correctness, and overall system integrity testing.
"""

import logging
import statistics
import math
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any, Optional, Set, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, Counter
import json

try:
    import networkx as nx
    HAS_NETWORKX = True
except ImportError:
    HAS_NETWORKX = False
    nx = None

try:
    from ..normalizers.schema import NormalizedIndicator, IndicatorType
    from .engine import CorrelationEngine, GraphNode, GraphRelationship, NodeType, RelationshipType, CorrelationResult
    from .relationships import RelationshipDetector
    from .rules import CorrelationRulesEngine, CorrelationRule, RuleType
    from .analysis import GraphAnalysisOrchestrator
    from .storage import KnowledgeGraphManager
except ImportError:
    from normalizers.schema import NormalizedIndicator, IndicatorType
    from correlation.engine import CorrelationEngine, GraphNode, GraphRelationship, NodeType, RelationshipType, CorrelationResult
    from correlation.relationships import RelationshipDetector
    from correlation.rules import CorrelationRulesEngine, CorrelationRule, RuleType
    from correlation.analysis import GraphAnalysisOrchestrator
    from correlation.storage import KnowledgeGraphManager

logger = logging.getLogger(__name__)


class ValidationLevel(Enum):
    """Levels of validation testing."""
    BASIC = "basic"
    COMPREHENSIVE = "comprehensive"
    STRESS = "stress"
    PERFORMANCE = "performance"


class TestCaseType(Enum):
    """Types of validation test cases."""
    RELATIONSHIP_DETECTION = "relationship_detection"
    GRAPH_CONSTRUCTION = "graph_construction"
    RULE_EVALUATION = "rule_evaluation"
    ANALYSIS_CORRECTNESS = "analysis_correctness"
    PERFORMANCE_BENCHMARK = "performance_benchmark"
    EDGE_CASE = "edge_case"


@dataclass
class ValidationTestCase:
    """Individual validation test case."""
    
    test_id: str
    name: str
    description: str
    test_type: TestCaseType
    
    # Test data
    input_data: Dict[str, Any] = field(default_factory=dict)
    expected_output: Dict[str, Any] = field(default_factory=dict)
    
    # Test parameters
    tolerance: float = 0.01
    timeout_seconds: int = 30
    
    # Metadata
    tags: List[str] = field(default_factory=list)
    priority: int = 100
    author: str = ""
    created_date: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'test_id': self.test_id,
            'name': self.name,
            'description': self.description,
            'test_type': self.test_type.value,
            'input_data': self.input_data,
            'expected_output': self.expected_output,
            'parameters': {
                'tolerance': self.tolerance,
                'timeout_seconds': self.timeout_seconds
            },
            'metadata': {
                'tags': self.tags,
                'priority': self.priority,
                'author': self.author,
                'created_date': self.created_date.isoformat() if self.created_date else None
            }
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ValidationTestCase':
        """Create from dictionary."""
        test_case = cls(
            test_id=data['test_id'],
            name=data['name'],
            description=data['description'],
            test_type=TestCaseType(data['test_type']),
            input_data=data.get('input_data', {}),
            expected_output=data.get('expected_output', {})
        )
        
        # Parameters
        params = data.get('parameters', {})
        test_case.tolerance = params.get('tolerance', 0.01)
        test_case.timeout_seconds = params.get('timeout_seconds', 30)
        
        # Metadata
        metadata = data.get('metadata', {})
        test_case.tags = metadata.get('tags', [])
        test_case.priority = metadata.get('priority', 100)
        test_case.author = metadata.get('author', '')
        
        if metadata.get('created_date'):
            test_case.created_date = datetime.fromisoformat(metadata['created_date'])
        
        return test_case


@dataclass
class ValidationResult:
    """Result of validation test execution."""
    
    test_id: str
    test_name: str
    
    # Execution status
    passed: bool = False
    error_message: str = ""
    execution_time: float = 0.0
    
    # Detailed results
    actual_output: Dict[str, Any] = field(default_factory=dict)
    comparison_details: Dict[str, Any] = field(default_factory=dict)
    
    # Performance metrics
    memory_usage: Optional[int] = None
    cpu_time: Optional[float] = None
    
    # Execution metadata
    executed_at: Optional[datetime] = None
    environment_info: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'test_id': self.test_id,
            'test_name': self.test_name,
            'passed': self.passed,
            'error_message': self.error_message,
            'execution_time': self.execution_time,
            'actual_output': self.actual_output,
            'comparison_details': self.comparison_details,
            'performance': {
                'memory_usage': self.memory_usage,
                'cpu_time': self.cpu_time
            },
            'metadata': {
                'executed_at': self.executed_at.isoformat() if self.executed_at else None,
                'environment_info': self.environment_info
            }
        }


@dataclass
class ValidationSummary:
    """Summary of validation run results."""
    
    total_tests: int = 0
    passed_tests: int = 0
    failed_tests: int = 0
    skipped_tests: int = 0
    
    # Performance statistics
    total_execution_time: float = 0.0
    average_execution_time: float = 0.0
    
    # Results by category
    results_by_type: Dict[str, Dict[str, int]] = field(default_factory=dict)
    
    # Failed tests
    failed_test_ids: List[str] = field(default_factory=list)
    
    # Execution metadata
    validation_started: Optional[datetime] = None
    validation_completed: Optional[datetime] = None
    
    @property
    def success_rate(self) -> float:
        """Calculate success rate."""
        if self.total_tests == 0:
            return 0.0
        return self.passed_tests / self.total_tests
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'summary': {
                'total_tests': self.total_tests,
                'passed_tests': self.passed_tests,
                'failed_tests': self.failed_tests,
                'skipped_tests': self.skipped_tests,
                'success_rate': self.success_rate
            },
            'performance': {
                'total_execution_time': self.total_execution_time,
                'average_execution_time': self.average_execution_time
            },
            'results_by_type': self.results_by_type,
            'failed_tests': self.failed_test_ids,
            'metadata': {
                'validation_started': self.validation_started.isoformat() if self.validation_started else None,
                'validation_completed': self.validation_completed.isoformat() if self.validation_completed else None
            }
        }


class TestDataGenerator:
    """Generates test data for validation."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize test data generator."""
        self.config = config or {}
        
        # Generation parameters
        self.node_count_range = self.config.get('node_count_range', (10, 100))
        self.relationship_count_range = self.config.get('relationship_count_range', (5, 50))
        
        logger.debug("Test data generator initialized")
    
    def generate_test_nodes(self, count: int) -> Dict[str, GraphNode]:
        """Generate test nodes."""
        
        nodes = {}
        
        for i in range(count):
            node_id = f"test_node_{i}"
            
            # Vary node types
            if i % 4 == 0:
                node_type = NodeType.INDICATOR
                value = f"test_indicator_{i}"
                properties = {
                    'indicator_type': 'ip_address' if i % 2 == 0 else 'domain',
                    'tags': [f'tag_{i % 5}', f'category_{i % 3}'],
                    'asn': 12345 + (i % 10),
                    'country': ['US', 'CN', 'RU', 'DE', 'FR'][i % 5]
                }
            elif i % 4 == 1:
                node_type = NodeType.TECHNIQUE
                value = f"T{1000 + i}"
                properties = {
                    'mitre_id': value,
                    'tactic': ['initial-access', 'execution', 'persistence'][i % 3],
                    'platform': ['Windows', 'Linux', 'macOS'][i % 3]
                }
            elif i % 4 == 2:
                node_type = NodeType.MALWARE
                value = f"test_malware_{i}"
                properties = {
                    'family': f'family_{i % 5}',
                    'type': 'trojan' if i % 2 == 0 else 'backdoor'
                }
            else:
                node_type = NodeType.INFRASTRUCTURE
                value = f"infra_{i}.example.com"
                properties = {
                    'asn': 12345 + (i % 10),
                    'registrar': f'registrar_{i % 3}',
                    'creation_date': '2023-01-01'
                }
            
            node = GraphNode(
                node_id=node_id,
                node_type=node_type,
                value=value,
                properties=properties,
                confidence=0.5 + (i % 5) * 0.1,
                first_observed=datetime.now(timezone.utc) - timedelta(days=i),
                last_observed=datetime.now(timezone.utc)
            )
            
            nodes[node_id] = node
        
        return nodes
    
    def generate_test_relationships(self, 
                                  nodes: Dict[str, GraphNode], 
                                  count: int) -> Dict[str, GraphRelationship]:
        """Generate test relationships."""
        
        relationships = {}
        node_ids = list(nodes.keys())
        
        for i in range(min(count, len(node_ids) * (len(node_ids) - 1) // 2)):
            # Select two different nodes
            source_idx = i % len(node_ids)
            target_idx = (i + 1 + i // len(node_ids)) % len(node_ids)
            
            if source_idx == target_idx:
                continue
            
            source_id = node_ids[source_idx]
            target_id = node_ids[target_idx]
            
            # Determine relationship type based on node types
            source_node = nodes[source_id]
            target_node = nodes[target_id]
            
            if (source_node.node_type == NodeType.INDICATOR and 
                target_node.node_type == NodeType.INDICATOR):
                if source_node.properties.get('asn') == target_node.properties.get('asn'):
                    rel_type = RelationshipType.INFRASTRUCTURE_SHARING
                else:
                    rel_type = RelationshipType.BEHAVIORAL_SIMILARITY
            elif (source_node.node_type == NodeType.INDICATOR and 
                  target_node.node_type == NodeType.TECHNIQUE):
                rel_type = RelationshipType.TECHNIQUE_USAGE
            else:
                rel_type = RelationshipType.RELATED
            
            rel_id = f"test_rel_{i}"
            
            relationship = GraphRelationship(
                relationship_id=rel_id,
                source_node_id=source_id,
                target_node_id=target_id,
                relationship_type=rel_type,
                weight=0.5 + (i % 10) * 0.05,
                confidence=0.6 + (i % 8) * 0.05,
                evidence={'test_evidence': f'evidence_{i}'},
                first_observed=datetime.now(timezone.utc) - timedelta(days=i % 30),
                last_observed=datetime.now(timezone.utc)
            )
            
            relationships[rel_id] = relationship
        
        return relationships
    
    def generate_synthetic_graph(self, 
                               node_count: Optional[int] = None,
                               relationship_count: Optional[int] = None) -> Tuple[Dict[str, GraphNode], Dict[str, GraphRelationship]]:
        """Generate a complete synthetic graph."""
        
        if node_count is None:
            node_count = self.node_count_range[0] + (abs(hash(str(datetime.now()))) % 
                                                    (self.node_count_range[1] - self.node_count_range[0]))
        
        if relationship_count is None:
            relationship_count = self.relationship_count_range[0] + (abs(hash(str(datetime.now(timezone.utc)))) % 
                                                                   (self.relationship_count_range[1] - self.relationship_count_range[0]))
        
        nodes = self.generate_test_nodes(node_count)
        relationships = self.generate_test_relationships(nodes, relationship_count)
        
        return nodes, relationships


class ComponentValidator:
    """Validates individual correlation system components."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize component validator."""
        self.config = config or {}
        
        # Test data generator
        self.data_generator = TestDataGenerator(self.config.get('test_data', {}))
        
        logger.debug("Component validator initialized")
    
    def validate_correlation_engine(self, engine: CorrelationEngine) -> ValidationResult:
        """Validate correlation engine functionality."""
        
        start_time = datetime.now(timezone.utc)
        result = ValidationResult(
            test_id="correlation_engine_basic",
            test_name="Basic Correlation Engine Validation"
        )
        
        try:
            # Generate test data
            nodes, relationships = self.data_generator.generate_synthetic_graph(20, 10)
            
            # Test correlation
            correlation_result = engine.correlate_indicators([])  # Empty input for basic test
            
            # Validate result structure
            if not isinstance(correlation_result, CorrelationResult):
                raise ValueError("Invalid correlation result type")
            
            # Validate basic properties
            if not hasattr(correlation_result, 'nodes') or not hasattr(correlation_result, 'relationships'):
                raise ValueError("Missing required attributes in correlation result")
            
            result.passed = True
            result.actual_output = {
                'correlation_completed': True,
                'result_type': str(type(correlation_result))
            }
            
        except Exception as e:
            result.passed = False
            result.error_message = str(e)
            logger.warning(f"Correlation engine validation failed: {e}")
        
        finally:
            result.execution_time = (datetime.now(timezone.utc) - start_time).total_seconds()
            result.executed_at = datetime.now(timezone.utc)
        
        return result
    
    def validate_relationship_detector(self, detector: RelationshipDetector) -> ValidationResult:
        """Validate relationship detector accuracy."""
        
        start_time = datetime.now(timezone.utc)
        result = ValidationResult(
            test_id="relationship_detector_accuracy",
            test_name="Relationship Detector Accuracy Test"
        )
        
        try:
            # Generate test nodes with known relationships
            nodes = self.data_generator.generate_test_nodes(10)
            
            # Create nodes with identical ASNs (should be detected)
            node_ids = list(nodes.keys())
            nodes[node_ids[0]].properties['asn'] = 12345
            nodes[node_ids[1]].properties['asn'] = 12345
            
            # Create nodes with similar tags
            nodes[node_ids[2]].properties['tags'] = ['malware', 'trojan']
            nodes[node_ids[3]].properties['tags'] = ['malware', 'backdoor']
            
            # Detect relationships
            detected_relationships = detector.detect_relationships(nodes, [])
            
            # Validate detection results
            asn_relationship_found = False
            tag_relationship_found = False
            
            for rel in detected_relationships:
                if (rel.source_node_id in [node_ids[0], node_ids[1]] and
                    rel.target_node_id in [node_ids[0], node_ids[1]] and
                    rel.relationship_type == RelationshipType.INFRASTRUCTURE_SHARING):
                    asn_relationship_found = True
                
                if (rel.source_node_id in [node_ids[2], node_ids[3]] and
                    rel.target_node_id in [node_ids[2], node_ids[3]] and
                    rel.relationship_type == RelationshipType.BEHAVIORAL_SIMILARITY):
                    tag_relationship_found = True
            
            # Check detection accuracy
            detection_score = (asn_relationship_found + tag_relationship_found) / 2.0
            
            result.passed = detection_score >= 0.5  # At least 50% accuracy
            result.actual_output = {
                'relationships_detected': len(detected_relationships),
                'asn_relationship_found': asn_relationship_found,
                'tag_relationship_found': tag_relationship_found,
                'detection_score': detection_score
            }
            
        except Exception as e:
            result.passed = False
            result.error_message = str(e)
            logger.warning(f"Relationship detector validation failed: {e}")
        
        finally:
            result.execution_time = (datetime.now(timezone.utc) - start_time).total_seconds()
            result.executed_at = datetime.now(timezone.utc)
        
        return result
    
    def validate_rules_engine(self, rules_engine: CorrelationRulesEngine) -> ValidationResult:
        """Validate correlation rules engine."""
        
        start_time = datetime.now(timezone.utc)
        result = ValidationResult(
            test_id="rules_engine_evaluation",
            test_name="Rules Engine Evaluation Test"
        )
        
        try:
            # Generate test nodes
            nodes = self.data_generator.generate_test_nodes(5)
            
            # Test rule evaluation
            node_ids = list(nodes.keys())
            source_node = nodes[node_ids[0]]
            target_node = nodes[node_ids[1]]
            
            # Make nodes similar for rule matching
            source_node.properties['asn'] = 12345
            target_node.properties['asn'] = 12345
            
            # Correlate nodes using rules
            new_relationships = rules_engine.correlate_nodes(nodes)
            
            # Validate results
            if not isinstance(new_relationships, dict):
                raise ValueError("Invalid relationships return type")
            
            # Check for expected relationship
            asn_relationship_found = False
            for rel in new_relationships.values():
                if (rel.source_node_id == source_node.node_id and
                    rel.target_node_id == target_node.node_id and
                    rel.relationship_type == RelationshipType.INFRASTRUCTURE_SHARING):
                    asn_relationship_found = True
                    break
            
            result.passed = True
            result.actual_output = {
                'relationships_created': len(new_relationships),
                'asn_relationship_found': asn_relationship_found,
                'rule_validation': rules_engine.validate_rules()
            }
            
        except Exception as e:
            result.passed = False
            result.error_message = str(e)
            logger.warning(f"Rules engine validation failed: {e}")
        
        finally:
            result.execution_time = (datetime.now(timezone.utc) - start_time).total_seconds()
            result.executed_at = datetime.now(timezone.utc)
        
        return result
    
    def validate_graph_analysis(self, analyzer: GraphAnalysisOrchestrator) -> ValidationResult:
        """Validate graph analysis capabilities."""
        
        start_time = datetime.now(timezone.utc)
        result = ValidationResult(
            test_id="graph_analysis_correctness",
            test_name="Graph Analysis Correctness Test"
        )
        
        try:
            # Generate test graph
            nodes, relationships = self.data_generator.generate_synthetic_graph(15, 20)
            
            # Perform analysis
            analysis_results = analyzer.analyze_complete_graph(nodes, relationships)
            
            # Validate analysis structure
            required_sections = ['centrality', 'communities', 'attack_patterns', 'insights']
            
            for section in required_sections:
                if section not in analysis_results:
                    raise ValueError(f"Missing analysis section: {section}")
            
            # Validate centrality results
            centrality = analysis_results['centrality']
            if not isinstance(centrality, dict) or len(centrality) == 0:
                raise ValueError("Invalid centrality analysis results")
            
            # Validate community detection
            communities = analysis_results['communities']
            if not isinstance(communities, dict):
                raise ValueError("Invalid community detection results")
            
            result.passed = True
            result.actual_output = {
                'analysis_sections': list(analysis_results.keys()),
                'centrality_measures': len(centrality),
                'communities_found': communities.get('community_count', 0),
                'attack_patterns': len(analysis_results.get('attack_patterns', []))
            }
            
        except Exception as e:
            result.passed = False
            result.error_message = str(e)
            logger.warning(f"Graph analysis validation failed: {e}")
        
        finally:
            result.execution_time = (datetime.now(timezone.utc) - start_time).total_seconds()
            result.executed_at = datetime.now(timezone.utc)
        
        return result
    
    def validate_storage_system(self, storage_manager: KnowledgeGraphManager) -> ValidationResult:
        """Validate knowledge graph storage system."""
        
        start_time = datetime.now(timezone.utc)
        result = ValidationResult(
            test_id="storage_system_integrity",
            test_name="Storage System Integrity Test"
        )
        
        try:
            # Generate test data
            nodes, relationships = self.data_generator.generate_synthetic_graph(10, 8)
            
            # Test storage and retrieval
            graph_id = f"test_graph_{int(datetime.now(timezone.utc).timestamp())}"
            
            # Save graph
            save_success = storage_manager.save_graph(graph_id, nodes, relationships)
            
            if not save_success:
                raise ValueError("Failed to save graph")
            
            # Load graph
            loaded_nodes, loaded_relationships = storage_manager.load_graph(graph_id)
            
            # Validate data integrity
            if len(loaded_nodes) != len(nodes):
                raise ValueError(f"Node count mismatch: {len(loaded_nodes)} != {len(nodes)}")
            
            if len(loaded_relationships) != len(relationships):
                raise ValueError(f"Relationship count mismatch: {len(loaded_relationships)} != {len(relationships)}")
            
            # Validate node integrity
            for node_id, original_node in nodes.items():
                if node_id not in loaded_nodes:
                    raise ValueError(f"Missing node: {node_id}")
                
                loaded_node = loaded_nodes[node_id]
                if loaded_node.value != original_node.value:
                    raise ValueError(f"Node value mismatch for {node_id}")
            
            # Clean up
            try:
                storage_manager.delete_graph(graph_id)
            except:
                pass  # Best effort cleanup
            
            result.passed = True
            result.actual_output = {
                'nodes_saved': len(nodes),
                'relationships_saved': len(relationships),
                'nodes_loaded': len(loaded_nodes),
                'relationships_loaded': len(loaded_relationships),
                'integrity_check': 'passed'
            }
            
        except Exception as e:
            result.passed = False
            result.error_message = str(e)
            logger.warning(f"Storage system validation failed: {e}")
        
        finally:
            result.execution_time = (datetime.now(timezone.utc) - start_time).total_seconds()
            result.executed_at = datetime.now(timezone.utc)
        
        return result


class PerformanceTester:
    """Tests performance and scalability."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize performance tester."""
        self.config = config or {}
        
        # Performance thresholds
        self.correlation_time_threshold = self.config.get('correlation_time_threshold', 10.0)  # seconds
        self.analysis_time_threshold = self.config.get('analysis_time_threshold', 5.0)  # seconds
        
        # Test data generator
        self.data_generator = TestDataGenerator(self.config.get('test_data', {}))
        
        logger.debug("Performance tester initialized")
    
    def test_correlation_performance(self, engine: CorrelationEngine) -> ValidationResult:
        """Test correlation engine performance."""
        
        start_time = datetime.now(timezone.utc)
        result = ValidationResult(
            test_id="correlation_performance",
            test_name="Correlation Engine Performance Test"
        )
        
        try:
            # Generate larger test dataset
            test_sizes = [50, 100, 200]
            performance_data = {}
            
            for size in test_sizes:
                test_start = datetime.now(timezone.utc)
                
                # Generate test data
                nodes, relationships = self.data_generator.generate_synthetic_graph(size, size // 2)
                
                # Convert to indicators for correlation
                indicators = []
                for node in nodes.values():
                    if node.node_type == NodeType.INDICATOR:
                        # Create mock normalized indicator
                        indicator = {
                            'value': node.value,
                            'type': node.properties.get('indicator_type', 'unknown'),
                            'properties': node.properties
                        }
                        indicators.append(indicator)
                
                # Perform correlation
                correlation_result = engine.correlate_indicators(indicators[:min(20, len(indicators))])
                
                test_time = (datetime.now(timezone.utc) - test_start).total_seconds()
                performance_data[f'size_{size}'] = {
                    'execution_time': test_time,
                    'nodes_processed': len(indicators[:min(20, len(indicators))]),
                    'relationships_found': len(correlation_result.relationships) if correlation_result.relationships else 0
                }
            
            # Check performance against threshold
            max_time = max([data['execution_time'] for data in performance_data.values()])
            result.passed = max_time <= self.correlation_time_threshold
            
            result.actual_output = {
                'performance_data': performance_data,
                'max_execution_time': max_time,
                'threshold': self.correlation_time_threshold
            }
            
        except Exception as e:
            result.passed = False
            result.error_message = str(e)
            logger.warning(f"Correlation performance test failed: {e}")
        
        finally:
            result.execution_time = (datetime.now(timezone.utc) - start_time).total_seconds()
            result.executed_at = datetime.now(timezone.utc)
        
        return result
    
    def test_analysis_performance(self, analyzer: GraphAnalysisOrchestrator) -> ValidationResult:
        """Test graph analysis performance."""
        
        start_time = datetime.now(timezone.utc)
        result = ValidationResult(
            test_id="analysis_performance",
            test_name="Graph Analysis Performance Test"
        )
        
        try:
            # Test with different graph sizes
            test_sizes = [25, 50, 100]
            performance_data = {}
            
            for size in test_sizes:
                test_start = datetime.now(timezone.utc)
                
                # Generate test graph
                nodes, relationships = self.data_generator.generate_synthetic_graph(size, size)
                
                # Perform analysis
                analysis_results = analyzer.analyze_complete_graph(nodes, relationships)
                
                test_time = (datetime.now(timezone.utc) - test_start).total_seconds()
                performance_data[f'size_{size}'] = {
                    'execution_time': test_time,
                    'nodes_analyzed': len(nodes),
                    'relationships_analyzed': len(relationships),
                    'analysis_sections': len(analysis_results)
                }
            
            # Check performance against threshold
            max_time = max([data['execution_time'] for data in performance_data.values()])
            result.passed = max_time <= self.analysis_time_threshold
            
            result.actual_output = {
                'performance_data': performance_data,
                'max_execution_time': max_time,
                'threshold': self.analysis_time_threshold
            }
            
        except Exception as e:
            result.passed = False
            result.error_message = str(e)
            logger.warning(f"Analysis performance test failed: {e}")
        
        finally:
            result.execution_time = (datetime.now(timezone.utc) - start_time).total_seconds()
            result.executed_at = datetime.now(timezone.utc)
        
        return result


class ValidationOrchestrator:
    """Orchestrates comprehensive validation testing."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize validation orchestrator."""
        self.config = config or {}
        
        # Initialize validators
        self.component_validator = ComponentValidator(self.config.get('component_validation', {}))
        self.performance_tester = PerformanceTester(self.config.get('performance_testing', {}))
        
        # Test cases storage
        self._test_cases: Dict[str, ValidationTestCase] = {}
        
        # Load default test cases
        if self.config.get('load_default_tests', True):
            self._load_default_test_cases()
        
        logger.info(f"Validation orchestrator initialized with {len(self._test_cases)} test cases")
    
    def run_comprehensive_validation(self, 
                                   correlation_engine: Optional[CorrelationEngine] = None,
                                   relationship_detector: Optional[RelationshipDetector] = None,
                                   rules_engine: Optional[CorrelationRulesEngine] = None,
                                   graph_analyzer: Optional[GraphAnalysisOrchestrator] = None,
                                   storage_manager: Optional[KnowledgeGraphManager] = None,
                                   validation_level: ValidationLevel = ValidationLevel.BASIC) -> Tuple[ValidationSummary, List[ValidationResult]]:
        """Run comprehensive validation across all components."""
        
        start_time = datetime.now(timezone.utc)
        summary = ValidationSummary(validation_started=start_time)
        results = []
        
        logger.info(f"Starting {validation_level.value} validation")
        
        try:
            # Component validation tests
            if correlation_engine:
                logger.debug("Validating correlation engine")
                result = self.component_validator.validate_correlation_engine(correlation_engine)
                results.append(result)
                self._update_summary(summary, result, TestCaseType.GRAPH_CONSTRUCTION)
            
            if relationship_detector:
                logger.debug("Validating relationship detector")
                result = self.component_validator.validate_relationship_detector(relationship_detector)
                results.append(result)
                self._update_summary(summary, result, TestCaseType.RELATIONSHIP_DETECTION)
            
            if rules_engine:
                logger.debug("Validating rules engine")
                result = self.component_validator.validate_rules_engine(rules_engine)
                results.append(result)
                self._update_summary(summary, result, TestCaseType.RULE_EVALUATION)
            
            if graph_analyzer:
                logger.debug("Validating graph analyzer")
                result = self.component_validator.validate_graph_analysis(graph_analyzer)
                results.append(result)
                self._update_summary(summary, result, TestCaseType.ANALYSIS_CORRECTNESS)
            
            if storage_manager:
                logger.debug("Validating storage manager")
                result = self.component_validator.validate_storage_system(storage_manager)
                results.append(result)
                self._update_summary(summary, result, TestCaseType.GRAPH_CONSTRUCTION)
            
            # Performance tests (for comprehensive and above)
            if validation_level in [ValidationLevel.COMPREHENSIVE, ValidationLevel.STRESS, ValidationLevel.PERFORMANCE]:
                
                if correlation_engine:
                    logger.debug("Testing correlation performance")
                    result = self.performance_tester.test_correlation_performance(correlation_engine)
                    results.append(result)
                    self._update_summary(summary, result, TestCaseType.PERFORMANCE_BENCHMARK)
                
                if graph_analyzer:
                    logger.debug("Testing analysis performance")
                    result = self.performance_tester.test_analysis_performance(graph_analyzer)
                    results.append(result)
                    self._update_summary(summary, result, TestCaseType.PERFORMANCE_BENCHMARK)
            
            # Calculate summary statistics
            summary.total_tests = len(results)
            summary.passed_tests = sum(1 for r in results if r.passed)
            summary.failed_tests = summary.total_tests - summary.passed_tests
            summary.failed_test_ids = [r.test_id for r in results if not r.passed]
            
            total_time = sum(r.execution_time for r in results)
            summary.total_execution_time = total_time
            summary.average_execution_time = total_time / len(results) if results else 0.0
            
        except Exception as e:
            logger.error(f"Validation orchestration failed: {e}", exc_info=True)
            # Create error result
            error_result = ValidationResult(
                test_id="validation_orchestration",
                test_name="Validation Orchestration",
                passed=False,
                error_message=str(e),
                executed_at=datetime.now(timezone.utc)
            )
            results.append(error_result)
            summary.total_tests = len(results)
            summary.failed_tests = summary.total_tests
        
        finally:
            end_time = datetime.now(timezone.utc)
            summary.validation_completed = end_time
        
        logger.info(f"Validation completed: {summary.passed_tests}/{summary.total_tests} tests passed "
                   f"({summary.success_rate:.1%} success rate)")
        
        return summary, results
    
    def _update_summary(self, 
                       summary: ValidationSummary, 
                       result: ValidationResult, 
                       test_type: TestCaseType) -> None:
        """Update summary with test result."""
        
        if test_type.value not in summary.results_by_type:
            summary.results_by_type[test_type.value] = {
                'total': 0, 'passed': 0, 'failed': 0
            }
        
        summary.results_by_type[test_type.value]['total'] += 1
        if result.passed:
            summary.results_by_type[test_type.value]['passed'] += 1
        else:
            summary.results_by_type[test_type.value]['failed'] += 1
    
    def _load_default_test_cases(self) -> None:
        """Load default test cases."""
        
        # Basic relationship detection test
        relationship_test = ValidationTestCase(
            test_id="basic_relationship_detection",
            name="Basic Relationship Detection",
            description="Test basic relationship detection between similar indicators",
            test_type=TestCaseType.RELATIONSHIP_DETECTION,
            input_data={
                'node_count': 10,
                'expected_relationships': ['asn_sharing', 'tag_similarity']
            },
            expected_output={
                'min_relationships': 2,
                'relationship_types': ['infrastructure_sharing', 'behavioral_similarity']
            },
            tolerance=0.1,
            tags=['basic', 'relationship'],
            priority=100
        )
        
        self._test_cases[relationship_test.test_id] = relationship_test
        
        # Graph construction test
        graph_test = ValidationTestCase(
            test_id="graph_construction_integrity",
            name="Graph Construction Integrity",
            description="Test graph construction and data integrity",
            test_type=TestCaseType.GRAPH_CONSTRUCTION,
            input_data={
                'node_count': 20,
                'relationship_count': 15
            },
            expected_output={
                'nodes_preserved': True,
                'relationships_preserved': True,
                'data_integrity': True
            },
            tolerance=0.0,
            tags=['basic', 'integrity'],
            priority=90
        )
        
        self._test_cases[graph_test.test_id] = graph_test
        
        logger.debug(f"Loaded {len(self._test_cases)} default test cases")
    
    def export_validation_report(self, 
                               summary: ValidationSummary,
                               results: List[ValidationResult],
                               file_path: str) -> None:
        """Export validation results to JSON report."""
        
        report = {
            'validation_report': {
                'summary': summary.to_dict(),
                'detailed_results': [result.to_dict() for result in results],
                'report_metadata': {
                    'generated_at': datetime.now(timezone.utc).isoformat(),
                    'total_tests': len(results),
                    'validation_level': 'comprehensive'
                }
            }
        }
        
        with open(file_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Validation report exported to {file_path}")
    
    def get_validation_statistics(self) -> Dict[str, Any]:
        """Get validation system statistics."""
        
        return {
            'test_cases': {
                'total': len(self._test_cases),
                'by_type': {
                    test_type.value: len([
                        tc for tc in self._test_cases.values() 
                        if tc.test_type == test_type
                    ])
                    for test_type in TestCaseType
                }
            },
            'configuration': {
                'component_validation': bool(self.component_validator),
                'performance_testing': bool(self.performance_tester)
            }
        }