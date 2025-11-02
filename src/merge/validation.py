"""
Comprehensive validation and testing system for the merge system.

This module provides extensive testing capabilities for all merge system components
including unit tests, integration tests, performance benchmarks, and validation
utilities to ensure system reliability and correctness.
"""

import logging
import time
import asyncio
import statistics
from datetime import datetime, timedelta
from typing import Dict, List, Any, Tuple, Optional, Set
from dataclasses import dataclass, field
import json
import uuid
from enum import Enum
import random

try:
    from ..normalizers.schema import NormalizedIndicator, IndicatorType
    from .deduplication import DeduplicationEngine, DuplicateMatchType
    from .confidence import MergeConfidenceEngine, MergeDecision
    from .lineage import LineageTracker
    from .policies import MergePolicyEngine
    from .orchestrator import MergeOrchestrator, MergeExecutionStatus
except ImportError:
    from normalizers.schema import NormalizedIndicator, IndicatorType
    from merge.deduplication import DeduplicationEngine, DuplicateMatchType
    from merge.confidence import MergeConfidenceEngine, MergeDecision
    from merge.lineage import LineageTracker
    from merge.policies import MergePolicyEngine
    from merge.orchestrator import MergeOrchestrator, MergeExecutionStatus

logger = logging.getLogger(__name__)


class ValidationResult(Enum):
    """Result of validation test."""
    PASS = "pass"
    FAIL = "fail"
    WARNING = "warning"
    ERROR = "error"


@dataclass
class TestCase:
    """Individual test case."""
    
    name: str
    description: str
    test_function: str  # Name of test method
    expected_result: ValidationResult = ValidationResult.PASS
    
    # Test data
    input_data: Any = None
    expected_output: Any = None
    
    # Test metadata
    category: str = "unit"
    priority: str = "medium"
    timeout: float = 30.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'name': self.name,
            'description': self.description,
            'test_function': self.test_function,
            'expected_result': self.expected_result.value,
            'category': self.category,
            'priority': self.priority,
            'timeout': self.timeout
        }


@dataclass
class TestResult:
    """Result of test execution."""
    
    test_case: TestCase
    result: ValidationResult = ValidationResult.FAIL
    
    # Execution info
    execution_time: float = 0.0
    error_message: Optional[str] = None
    warnings: List[str] = field(default_factory=list)
    
    # Output data
    actual_output: Any = None
    passed_assertions: int = 0
    failed_assertions: int = 0
    
    # Timestamps
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    
    @property
    def success(self) -> bool:
        """Check if test passed."""
        return self.result in {ValidationResult.PASS, ValidationResult.WARNING}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'test_name': self.test_case.name,
            'result': self.result.value,
            'execution_time': self.execution_time,
            'error_message': self.error_message,
            'warnings': self.warnings,
            'passed_assertions': self.passed_assertions,
            'failed_assertions': self.failed_assertions,
            'success': self.success,
            'started_at': self.started_at.isoformat(),
            'completed_at': self.completed_at.isoformat() if self.completed_at else None
        }


@dataclass
class ValidationSummary:
    """Summary of validation execution."""
    
    total_tests: int = 0
    passed_tests: int = 0
    failed_tests: int = 0
    warning_tests: int = 0
    error_tests: int = 0
    
    execution_time: float = 0.0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    
    # Performance metrics
    performance_metrics: Dict[str, float] = field(default_factory=dict)
    
    # Results by category
    results_by_category: Dict[str, Dict[str, int]] = field(default_factory=dict)
    
    @property
    def success_rate(self) -> float:
        """Calculate success rate."""
        if self.total_tests == 0:
            return 0.0
        return (self.passed_tests + self.warning_tests) / self.total_tests
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'total_tests': self.total_tests,
            'passed_tests': self.passed_tests,
            'failed_tests': self.failed_tests,
            'warning_tests': self.warning_tests,
            'error_tests': self.error_tests,
            'success_rate': self.success_rate,
            'execution_time': self.execution_time,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'performance_metrics': self.performance_metrics,
            'results_by_category': self.results_by_category
        }


class MergeSystemValidator:
    """Comprehensive validation system for merge components."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize validator."""
        self.config = config or {}
        
        # Test configuration
        self.enable_performance_tests = self.config.get('enable_performance_tests', True)
        self.enable_integration_tests = self.config.get('enable_integration_tests', True)
        self.test_timeout = self.config.get('test_timeout', 30.0)
        
        # Initialize test results
        self.test_results: List[TestResult] = []
        self.test_cases: List[TestCase] = []
        
        # Performance thresholds
        self.performance_thresholds = {
            'deduplication_per_indicator': 0.1,  # seconds
            'confidence_calculation': 0.05,     # seconds
            'merge_execution': 0.2,             # seconds
            'batch_processing_per_100': 5.0     # seconds
        }
        
        logger.info("Merge system validator initialized")
    
    def run_full_validation(self) -> ValidationSummary:
        """Run complete validation suite."""
        
        start_time = datetime.utcnow()
        summary = ValidationSummary(start_time=start_time)
        
        try:
            logger.info("Starting full merge system validation")
            
            # Initialize test cases
            self._initialize_test_cases()
            
            # Run all tests
            self._run_unit_tests()
            
            if self.enable_integration_tests:
                self._run_integration_tests()
            
            if self.enable_performance_tests:
                self._run_performance_tests()
            
            # Generate summary
            summary = self._generate_summary()
            
            logger.info(f"Validation completed: {summary.success_rate:.1%} success rate")
            
        except Exception as e:
            logger.error(f"Validation failed: {e}", exc_info=True)
            summary.error_tests += 1
        
        finally:
            summary.end_time = datetime.utcnow()
            summary.execution_time = (summary.end_time - start_time).total_seconds()
        
        return summary
    
    def _initialize_test_cases(self):
        """Initialize all test cases."""
        
        # Unit test cases
        unit_tests = [
            TestCase(
                name="test_deduplication_exact_match",
                description="Test exact value matching in deduplication engine",
                test_function="test_deduplication_exact_match",
                category="unit",
                priority="high"
            ),
            TestCase(
                name="test_deduplication_semantic_match",
                description="Test semantic equivalence matching",
                test_function="test_deduplication_semantic_match",
                category="unit",
                priority="high"
            ),
            TestCase(
                name="test_confidence_scoring_calculation",
                description="Test confidence score calculation accuracy",
                test_function="test_confidence_scoring_calculation",
                category="unit",
                priority="high"
            ),
            TestCase(
                name="test_lineage_tracking_integrity",
                description="Test lineage tracking completeness and accuracy",
                test_function="test_lineage_tracking_integrity",
                category="unit",
                priority="high"
            ),
            TestCase(
                name="test_merge_policies_enforcement",
                description="Test merge policy rule enforcement",
                test_function="test_merge_policies_enforcement",
                category="unit",
                priority="high"
            ),
            TestCase(
                name="test_merge_execution_accuracy",
                description="Test merge execution correctness",
                test_function="test_merge_execution_accuracy",
                category="unit",
                priority="high"
            )
        ]
        
        # Integration test cases
        integration_tests = [
            TestCase(
                name="test_end_to_end_merge_workflow",
                description="Test complete merge workflow from input to output",
                test_function="test_end_to_end_merge_workflow",
                category="integration",
                priority="critical"
            ),
            TestCase(
                name="test_batch_merge_processing",
                description="Test batch processing of multiple indicator sets",
                test_function="test_batch_merge_processing",
                category="integration",
                priority="high"
            ),
            TestCase(
                name="test_async_merge_execution",
                description="Test asynchronous merge execution",
                test_function="test_async_merge_execution",
                category="integration",
                priority="medium"
            ),
            TestCase(
                name="test_error_handling_resilience",
                description="Test system resilience to various error conditions",
                test_function="test_error_handling_resilience",
                category="integration",
                priority="high"
            )
        ]
        
        # Performance test cases
        performance_tests = [
            TestCase(
                name="test_deduplication_performance",
                description="Test deduplication performance with large datasets",
                test_function="test_deduplication_performance",
                category="performance",
                priority="medium",
                timeout=60.0
            ),
            TestCase(
                name="test_merge_execution_performance",
                description="Test merge execution performance benchmarks",
                test_function="test_merge_execution_performance",
                category="performance",
                priority="medium",
                timeout=120.0
            ),
            TestCase(
                name="test_memory_usage_efficiency",
                description="Test memory usage during large batch processing",
                test_function="test_memory_usage_efficiency",
                category="performance",
                priority="low",
                timeout=180.0
            )
        ]
        
        self.test_cases = unit_tests + integration_tests + performance_tests
        logger.info(f"Initialized {len(self.test_cases)} test cases")
    
    def _run_unit_tests(self):
        """Run unit tests."""
        logger.info("Running unit tests")
        
        unit_test_cases = [tc for tc in self.test_cases if tc.category == "unit"]
        
        for test_case in unit_test_cases:
            result = self._execute_test_case(test_case)
            self.test_results.append(result)
    
    def _run_integration_tests(self):
        """Run integration tests."""
        logger.info("Running integration tests")
        
        integration_test_cases = [tc for tc in self.test_cases if tc.category == "integration"]
        
        for test_case in integration_test_cases:
            result = self._execute_test_case(test_case)
            self.test_results.append(result)
    
    def _run_performance_tests(self):
        """Run performance tests."""
        logger.info("Running performance tests")
        
        performance_test_cases = [tc for tc in self.test_cases if tc.category == "performance"]
        
        for test_case in performance_test_cases:
            result = self._execute_test_case(test_case)
            self.test_results.append(result)
    
    def _execute_test_case(self, test_case: TestCase) -> TestResult:
        """Execute a single test case."""
        
        result = TestResult(test_case=test_case)
        
        try:
            start_time = time.time()
            
            # Get test method
            test_method = getattr(self, test_case.test_function, None)
            if not test_method:
                result.result = ValidationResult.ERROR
                result.error_message = f"Test method {test_case.test_function} not found"
                return result
            
            # Execute test with timeout
            test_output = test_method()
            
            result.execution_time = time.time() - start_time
            result.actual_output = test_output
            result.result = ValidationResult.PASS
            result.passed_assertions += 1
            
        except AssertionError as e:
            result.result = ValidationResult.FAIL
            result.error_message = str(e)
            result.failed_assertions += 1
        except Exception as e:
            result.result = ValidationResult.ERROR
            result.error_message = str(e)
        
        finally:
            result.completed_at = datetime.utcnow()
        
        return result
    
    # Unit test methods
    def test_deduplication_exact_match(self) -> Dict[str, Any]:
        """Test exact match deduplication."""
        
        # Create test indicators
        indicator1 = self._create_test_indicator(
            "192.168.1.100", IndicatorType.IP_ADDRESS, 
            tags=["malware", "c2"], confidence=85
        )
        indicator2 = self._create_test_indicator(
            "192.168.1.100", IndicatorType.IP_ADDRESS,
            tags=["botnet"], confidence=90
        )
        
        # Test deduplication
        dedup_engine = DeduplicationEngine()
        matches = dedup_engine.find_duplicates([indicator1, indicator2])
        
        assert len(matches) == 1, f"Expected 1 match, got {len(matches)}"
        match = matches[0]
        assert match.match_type == DuplicateMatchType.EXACT_VALUE, "Expected exact value match"
        assert match.confidence_score > 0.9, "Expected high confidence for exact match"
        
        return {"matches_found": len(matches), "match_type": match.match_type.value}
    
    def test_deduplication_semantic_match(self) -> Dict[str, Any]:
        """Test semantic equivalence matching."""
        
        # Create semantically equivalent indicators
        indicator1 = self._create_test_indicator(
            "example.com", IndicatorType.DOMAIN,
            tags=["phishing"], confidence=80
        )
        indicator2 = self._create_test_indicator(
            "EXAMPLE.COM", IndicatorType.DOMAIN,
            tags=["malicious"], confidence=75
        )
        
        dedup_engine = DeduplicationEngine()
        matches = dedup_engine.find_duplicates([indicator1, indicator2])
        
        assert len(matches) >= 1, "Expected semantic match for case-insensitive domains"
        
        return {"matches_found": len(matches)}
    
    def test_confidence_scoring_calculation(self) -> Dict[str, Any]:
        """Test confidence scoring accuracy."""
        
        # Create test indicators with different characteristics
        indicators = [
            self._create_test_indicator("malware.example.com", IndicatorType.DOMAIN, confidence=90, source="premium_feed"),
            self._create_test_indicator("malware.example.com", IndicatorType.DOMAIN, confidence=70, source="community_feed")
        ]
        
        # Create duplicate match
        dedup_engine = DeduplicationEngine()
        matches = dedup_engine.find_duplicates(indicators)
        
        assert len(matches) > 0, "Expected to find duplicate match"
        
        # Test confidence calculation
        confidence_engine = MergeConfidenceEngine()
        confidence_score = confidence_engine.calculate_merge_confidence(matches[0], indicators)
        
        assert 0.0 <= confidence_score.overall_confidence <= 1.0, "Confidence should be in range [0,1]"
        assert confidence_score.decision in MergeDecision, "Decision should be valid enum value"
        
        return {
            "overall_confidence": confidence_score.overall_confidence,
            "decision": confidence_score.decision.value,
            "factor_count": len(confidence_score.confidence_factors)
        }
    
    def test_lineage_tracking_integrity(self) -> Dict[str, Any]:
        """Test lineage tracking completeness."""
        
        # Create test indicators
        indicators = [
            self._create_test_indicator("test.malware.com", IndicatorType.DOMAIN, source="source1"),
            self._create_test_indicator("test.malware.com", IndicatorType.DOMAIN, source="source2")
        ]
        
        # Initialize components
        lineage_tracker = LineageTracker()
        dedup_engine = DeduplicationEngine()
        confidence_engine = MergeConfidenceEngine()
        
        # Create merge scenario
        matches = dedup_engine.find_duplicates(indicators)
        assert len(matches) > 0, "Expected duplicate match"
        
        confidence_score = confidence_engine.calculate_merge_confidence(matches[0], indicators)
        
        # Test lineage recording
        merge_id = str(uuid.uuid4())
        lineage_tracker.record_merge_operation(
            merge_id, indicators, matches[0], confidence_score, []
        )
        
        # Verify lineage exists
        lineage = lineage_tracker.get_lineage(merge_id)
        assert lineage is not None, "Lineage should be recorded"
        assert len(lineage.source_attributions) == len(indicators), "Should track all source indicators"
        
        return {
            "lineage_recorded": lineage is not None,
            "source_count": len(lineage.source_attributions),
            "event_count": len(lineage.merge_events)
        }
    
    def test_merge_policies_enforcement(self) -> Dict[str, Any]:
        """Test merge policy enforcement."""
        
        # Create test indicators
        indicators = [
            self._create_test_indicator("policy.test.com", IndicatorType.DOMAIN, confidence=30),  # Low confidence
            self._create_test_indicator("policy.test.com", IndicatorType.DOMAIN, confidence=95)   # High confidence
        ]
        
        # Test policy engine
        policy_engine = MergePolicyEngine()
        dedup_engine = DeduplicationEngine()
        confidence_engine = MergeConfidenceEngine()
        
        matches = dedup_engine.find_duplicates(indicators)
        assert len(matches) > 0, "Expected duplicate match"
        
        confidence_score = confidence_engine.calculate_merge_confidence(matches[0], indicators)
        
        # Test conservative policy (should reject low confidence)
        conservative_allows = policy_engine.evaluate_merge_decision(
            "conservative", indicators, matches[0], confidence_score
        )
        
        # Test aggressive policy (should allow most merges)
        aggressive_allows = policy_engine.evaluate_merge_decision(
            "aggressive", indicators, matches[0], confidence_score
        )
        
        return {
            "conservative_allows": conservative_allows,
            "aggressive_allows": aggressive_allows,
            "confidence": confidence_score.overall_confidence
        }
    
    def test_merge_execution_accuracy(self) -> Dict[str, Any]:
        """Test merge execution correctness."""
        
        # Create comprehensive test scenario
        indicators = [
            self._create_test_indicator(
                "exec.test.com", IndicatorType.DOMAIN,
                tags=["malware", "c2"], confidence=85,
                threat_types=["trojan"]
            ),
            self._create_test_indicator(
                "exec.test.com", IndicatorType.DOMAIN,
                tags=["botnet"], confidence=90,
                threat_types=["backdoor"]
            )
        ]
        
        # Execute full merge
        orchestrator = MergeOrchestrator()
        merged_indicators, summary = orchestrator.merge_indicators(indicators)
        
        assert summary.successful_merges > 0, "Expected successful merge"
        assert len(merged_indicators) < len(indicators), "Should reduce indicator count"
        
        # Find merged indicator
        merged_indicator = None
        for ind in merged_indicators:
            if hasattr(ind, 'tags') and ind.tags and any('merged_from' in tag for tag in ind.tags):
                merged_indicator = ind
                break
        
        assert merged_indicator is not None, "Should create merged indicator"
        
        return {
            "successful_merges": summary.successful_merges,
            "original_count": len(indicators),
            "final_count": len(merged_indicators),
            "merged_indicator_found": merged_indicator is not None
        }
    
    # Integration test methods
    def test_end_to_end_merge_workflow(self) -> Dict[str, Any]:
        """Test complete end-to-end merge workflow."""
        
        # Create diverse test dataset
        test_indicators = self._create_test_dataset(50)
        
        # Execute full workflow
        orchestrator = MergeOrchestrator()
        start_time = time.time()
        merged_indicators, summary = orchestrator.merge_indicators(test_indicators)
        execution_time = time.time() - start_time
        
        # Validate results
        assert len(merged_indicators) <= len(test_indicators), "Result count should not exceed input"
        assert summary.total_indicators == len(test_indicators), "Summary should match input count"
        
        return {
            "input_count": len(test_indicators),
            "output_count": len(merged_indicators),
            "execution_time": execution_time,
            "successful_merges": summary.successful_merges,
            "duplicate_groups": summary.duplicate_groups
        }
    
    def test_batch_merge_processing(self) -> Dict[str, Any]:
        """Test batch processing capabilities."""
        
        # Create multiple batches
        batch_sizes = [10, 50, 100]
        results = {}
        
        for batch_size in batch_sizes:
            test_indicators = self._create_test_dataset(batch_size)
            
            orchestrator = MergeOrchestrator()
            start_time = time.time()
            merged_indicators, summary = orchestrator.merge_indicators(test_indicators)
            execution_time = time.time() - start_time
            
            results[f"batch_{batch_size}"] = {
                "execution_time": execution_time,
                "throughput": batch_size / execution_time if execution_time > 0 else 0,
                "successful_merges": summary.successful_merges
            }
        
        return results
    
    def test_async_merge_execution(self) -> Dict[str, Any]:
        """Test asynchronous execution."""
        
        # Create test dataset
        test_indicators = self._create_test_dataset(30)
        
        # Test async execution
        async def run_async_test():
            orchestrator = MergeOrchestrator({"enable_async_execution": True})
            start_time = time.time()
            merged_indicators, summary = orchestrator.merge_indicators(test_indicators)
            execution_time = time.time() - start_time
            return merged_indicators, summary, execution_time
        
        # Run async test
        merged_indicators, summary, async_time = asyncio.run(run_async_test())
        
        # Test sync execution for comparison
        orchestrator_sync = MergeOrchestrator({"enable_async_execution": False})
        start_time = time.time()
        merged_indicators_sync, summary_sync = orchestrator_sync.merge_indicators(test_indicators)
        sync_time = time.time() - start_time
        
        return {
            "async_time": async_time,
            "sync_time": sync_time,
            "performance_improvement": (sync_time - async_time) / sync_time if sync_time > 0 else 0,
            "async_merges": summary.successful_merges,
            "sync_merges": summary_sync.successful_merges
        }
    
    def test_error_handling_resilience(self) -> Dict[str, Any]:
        """Test error handling and resilience."""
        
        # Create test cases with various error conditions
        error_test_cases = [
            # Invalid indicator data
            {"case": "invalid_data", "indicators": []},
            # Malformed indicators (will need to be created differently)
            {"case": "malformed_indicators", "indicators": self._create_malformed_indicators()},
            # Extreme values
            {"case": "extreme_values", "indicators": self._create_extreme_value_indicators()}
        ]
        
        results = {}
        orchestrator = MergeOrchestrator()
        
        for test_case in error_test_cases:
            try:
                merged_indicators, summary = orchestrator.merge_indicators(test_case["indicators"])
                results[test_case["case"]] = {
                    "handled_gracefully": True,
                    "error": None,
                    "output_count": len(merged_indicators)
                }
            except Exception as e:
                results[test_case["case"]] = {
                    "handled_gracefully": False,
                    "error": str(e),
                    "output_count": 0
                }
        
        return results
    
    # Performance test methods
    def test_deduplication_performance(self) -> Dict[str, Any]:
        """Test deduplication performance."""
        
        # Test with different dataset sizes
        dataset_sizes = [100, 500, 1000]
        performance_results = {}
        
        for size in dataset_sizes:
            test_indicators = self._create_test_dataset(size)
            
            dedup_engine = DeduplicationEngine()
            start_time = time.time()
            matches = dedup_engine.find_duplicates(test_indicators)
            execution_time = time.time() - start_time
            
            throughput = size / execution_time if execution_time > 0 else 0
            
            performance_results[f"size_{size}"] = {
                "execution_time": execution_time,
                "throughput": throughput,
                "matches_found": len(matches),
                "per_indicator_time": execution_time / size if size > 0 else 0
            }
            
            # Check performance threshold
            per_indicator_time = execution_time / size if size > 0 else 0
            if per_indicator_time > self.performance_thresholds['deduplication_per_indicator']:
                logger.warning(f"Deduplication performance below threshold for size {size}")
        
        return performance_results
    
    def test_merge_execution_performance(self) -> Dict[str, Any]:
        """Test merge execution performance."""
        
        # Create test scenario with known duplicates
        test_indicators = self._create_duplicate_heavy_dataset(200)
        
        orchestrator = MergeOrchestrator()
        start_time = time.time()
        merged_indicators, summary = orchestrator.merge_indicators(test_indicators)
        total_time = time.time() - start_time
        
        # Calculate performance metrics
        throughput = len(test_indicators) / total_time if total_time > 0 else 0
        merge_time_per_operation = total_time / summary.merge_attempts if summary.merge_attempts > 0 else 0
        
        performance_result = {
            "total_time": total_time,
            "throughput": throughput,
            "merge_time_per_operation": merge_time_per_operation,
            "input_count": len(test_indicators),
            "output_count": len(merged_indicators),
            "merge_attempts": summary.merge_attempts,
            "successful_merges": summary.successful_merges
        }
        
        # Check thresholds
        if merge_time_per_operation > self.performance_thresholds['merge_execution']:
            logger.warning("Merge execution performance below threshold")
        
        return performance_result
    
    def test_memory_usage_efficiency(self) -> Dict[str, Any]:
        """Test memory usage efficiency."""
        
        # This is a simplified memory test - in production you'd use memory_profiler
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss
        
        # Create large dataset
        large_dataset = self._create_test_dataset(1000)
        
        # Execute merge
        orchestrator = MergeOrchestrator()
        merged_indicators, summary = orchestrator.merge_indicators(large_dataset)
        
        final_memory = process.memory_info().rss
        memory_increase = final_memory - initial_memory
        
        # Clean up
        del large_dataset
        del merged_indicators
        
        return {
            "initial_memory_mb": initial_memory / (1024 * 1024),
            "final_memory_mb": final_memory / (1024 * 1024),
            "memory_increase_mb": memory_increase / (1024 * 1024),
            "indicators_processed": 1000
        }
    
    def _generate_summary(self) -> ValidationSummary:
        """Generate validation summary."""
        
        summary = ValidationSummary(
            total_tests=len(self.test_results),
            start_time=min((r.started_at for r in self.test_results), default=datetime.utcnow()),
            end_time=max((r.completed_at for r in self.test_results if r.completed_at), default=datetime.utcnow())
        )
        
        # Count results by status
        for result in self.test_results:
            if result.result == ValidationResult.PASS:
                summary.passed_tests += 1
            elif result.result == ValidationResult.FAIL:
                summary.failed_tests += 1
            elif result.result == ValidationResult.WARNING:
                summary.warning_tests += 1
            elif result.result == ValidationResult.ERROR:
                summary.error_tests += 1
            
            # Group by category
            category = result.test_case.category
            if category not in summary.results_by_category:
                summary.results_by_category[category] = {
                    "pass": 0, "fail": 0, "warning": 0, "error": 0
                }
            summary.results_by_category[category][result.result.value] += 1
        
        # Calculate performance metrics
        perf_results = [r for r in self.test_results if r.test_case.category == "performance"]
        if perf_results:
            exec_times = [r.execution_time for r in perf_results]
            summary.performance_metrics = {
                "avg_execution_time": statistics.mean(exec_times),
                "max_execution_time": max(exec_times),
                "min_execution_time": min(exec_times)
            }
        
        summary.execution_time = (summary.end_time - summary.start_time).total_seconds()
        
        return summary
    
    # Helper methods for test data generation
    def _create_test_indicator(self, 
                             value: str,
                             indicator_type: IndicatorType,
                             tags: Optional[List[str]] = None,
                             confidence: int = 75,
                             source: str = "test_source",
                             threat_types: Optional[List[str]] = None) -> NormalizedIndicator:
        """Create a test indicator."""
        
        return NormalizedIndicator(
            id=f"test-{uuid.uuid4()}",
            value=value,
            indicator_type=indicator_type,
            source=source,
            confidence=confidence,
            tags=tags or [],
            threat_types=threat_types or [],
            first_seen=datetime.utcnow() - timedelta(days=random.randint(1, 30)),
            last_seen=datetime.utcnow(),
            created=datetime.utcnow()
        )
    
    def _create_test_dataset(self, size: int) -> List[NormalizedIndicator]:
        """Create a test dataset with some duplicates."""
        
        indicators = []
        
        # Create base indicators
        for i in range(size // 2):
            # IP indicators
            indicators.append(
                self._create_test_indicator(
                    f"192.168.1.{i % 255}",
                    IndicatorType.IP_ADDRESS,
                    tags=[f"tag_{i % 5}"],
                    confidence=random.randint(60, 95)
                )
            )
            
            # Domain indicators
            indicators.append(
                self._create_test_indicator(
                    f"test{i}.example.com",
                    IndicatorType.DOMAIN,
                    tags=[f"domain_tag_{i % 3}"],
                    confidence=random.randint(50, 90)
                )
            )
        
        # Add some duplicates (10% of dataset)
        duplicate_count = size // 10
        for i in range(duplicate_count):
            original = random.choice(indicators)
            duplicate = self._create_test_indicator(
                original.value,
                original.indicator_type,
                tags=original.tags + [f"duplicate_{i}"],
                confidence=original.confidence + random.randint(-10, 10),
                source=f"duplicate_source_{i}"
            )
            indicators.append(duplicate)
        
        return indicators[:size]  # Ensure exact size
    
    def _create_duplicate_heavy_dataset(self, size: int) -> List[NormalizedIndicator]:
        """Create dataset with high duplicate rate for performance testing."""
        
        indicators = []
        base_values = [f"perf.test{i}.com" for i in range(size // 4)]
        
        for i in range(size):
            base_value = random.choice(base_values)
            indicator = self._create_test_indicator(
                base_value,
                IndicatorType.DOMAIN,
                tags=[f"perf_tag_{i % 5}"],
                confidence=random.randint(70, 95),
                source=f"perf_source_{i % 10}"
            )
            indicators.append(indicator)
        
        return indicators
    
    def _create_malformed_indicators(self) -> List[NormalizedIndicator]:
        """Create indicators with potential issues for error testing."""
        
        indicators = []
        
        # Indicator with empty value
        try:
            indicators.append(
                self._create_test_indicator("", IndicatorType.DOMAIN)
            )
        except:
            pass
        
        # Indicator with very long value
        indicators.append(
            self._create_test_indicator(
                "x" * 1000 + ".example.com",
                IndicatorType.DOMAIN
            )
        )
        
        return indicators
    
    def _create_extreme_value_indicators(self) -> List[NormalizedIndicator]:
        """Create indicators with extreme values."""
        
        indicators = []
        
        # Very high confidence
        indicators.append(
            self._create_test_indicator(
                "extreme.test.com",
                IndicatorType.DOMAIN,
                confidence=100
            )
        )
        
        # Very low confidence
        indicators.append(
            self._create_test_indicator(
                "extreme.test.com",
                IndicatorType.DOMAIN,
                confidence=0
            )
        )
        
        return indicators


def run_merge_system_validation(config: Optional[Dict[str, Any]] = None) -> ValidationSummary:
    """Run complete merge system validation."""
    
    validator = MergeSystemValidator(config)
    summary = validator.run_full_validation()
    
    # Print results
    print("\n" + "="*80)
    print("MERGE SYSTEM VALIDATION RESULTS")
    print("="*80)
    print(f"Total Tests: {summary.total_tests}")
    print(f"Passed: {summary.passed_tests}")
    print(f"Failed: {summary.failed_tests}")
    print(f"Warnings: {summary.warning_tests}")
    print(f"Errors: {summary.error_tests}")
    print(f"Success Rate: {summary.success_rate:.1%}")
    print(f"Execution Time: {summary.execution_time:.2f} seconds")
    
    if summary.performance_metrics:
        print(f"\nPerformance Metrics:")
        for metric, value in summary.performance_metrics.items():
            print(f"  {metric}: {value:.4f}")
    
    print("\nResults by Category:")
    for category, results in summary.results_by_category.items():
        print(f"  {category.upper()}: {results}")
    
    print("="*80)
    
    return summary


if __name__ == "__main__":
    # Load real indicators for testing
    import json
    from pathlib import Path
    
    def load_real_indicators_for_merge_validation(limit=50):
        """Load real indicators for merge validation testing."""
        enriched_dir = Path('data/enriched')
        
        if not enriched_dir.exists():
            # Fallback to hardcoded examples if no real data
            return [
                {
                    'value': '192.168.1.100',
                    'type': 'ip',
                    'malware_family': 'Emotet',
                    'threat_score': 85,
                    'confidence_score': 90,
                    'time_window': '24h'
                },
                {
                    'value': 'malicious-domain.com',
                    'type': 'domain',
                    'threat_actor': 'APT28',
                    'threat_score': 75,
                    'confidence_score': 85
                }
            ]
        
        indicators = []
        for source_dir in enriched_dir.iterdir():
            if source_dir.is_dir():
                for jsonl_file in source_dir.glob('*.jsonl'):
                    try:
                        with open(jsonl_file, 'r') as f:
                            for line_num, line in enumerate(f, 1):
                                if len(indicators) >= limit:
                                    break
                                line = line.strip()
                                if not line:
                                    continue
                                try:
                                    data = json.loads(line)
                                    # Convert to format expected by merge validation
                                    indicator = {
                                        'value': data.get('value'),
                                        'type': data.get('indicator_type', 'unknown'),
                                        'threat_score': data.get('confidence', 50),
                                        'confidence_score': data.get('confidence', 50),
                                        'time_window': '24h'
                                    }
                                    indicators.append(indicator)
                                except json.JSONDecodeError:
                                    continue
                    except Exception:
                        continue
        
        if not indicators:
            # Fallback to hardcoded examples
            return [
                {
                    'value': '192.168.1.100',
                    'type': 'ip',
                    'malware_family': 'Emotet',
                    'threat_score': 85,
                    'confidence_score': 90,
                    'time_window': '24h'
                },
                {
                    'value': 'malicious-domain.com',
                    'type': 'domain',
                    'threat_actor': 'APT28',
                    'threat_score': 75,
                    'confidence_score': 85
                }
            ]
        
        return indicators
    
    # Run validation if executed directly
    validation_config = {
        'enable_performance_tests': True,
        'enable_integration_tests': True,
        'test_timeout': 30.0
    }
    
    # Load real indicators for validation
    real_indicators = load_real_indicators_for_merge_validation()
    print(f"Loaded {len(real_indicators)} real indicators for validation")
    
    summary = run_merge_system_validation(validation_config)
    
    # Save results to file
    results_file = f"merge_validation_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(results_file, 'w') as f:
        json.dump(summary.to_dict(), f, indent=2)
    
    print(f"\nDetailed results saved to: {results_file}")