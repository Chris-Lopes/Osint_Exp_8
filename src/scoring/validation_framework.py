"""
Scoring validation and calibration framework for threat intelligence.

This module implements comprehensive validation and calibration systems with historical
performance analysis, accuracy metrics tracking, scoring model optimization, feedback
loops, and continuous improvement mechanisms.
"""

import logging
import statistics
import math
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set, Tuple, Union, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, Counter, deque
import json
import pickle

try:
    from ..normalizers.schema import NormalizedIndicator, IndicatorType
    from .engine import ThreatScore, PriorityBand, ThreatCategory
    from .confidence_scoring import ConfidenceScore, ConfidenceLevel
    from .risk_assessment import RiskLevel
except ImportError:
    from normalizers.schema import NormalizedIndicator, IndicatorType
    from scoring.engine import ThreatScore, PriorityBand, ThreatCategory
    from scoring.confidence_scoring import ConfidenceScore, ConfidenceLevel
    from scoring.risk_assessment import RiskLevel

logger = logging.getLogger(__name__)


class ValidationMetric(Enum):
    """Validation metrics for scoring performance."""
    ACCURACY = "accuracy"                    # Overall correctness
    PRECISION = "precision"                  # True positive rate
    RECALL = "recall"                       # Sensitivity
    F1_SCORE = "f1_score"                   # Harmonic mean of precision/recall
    FALSE_POSITIVE_RATE = "false_positive_rate"  # FPR
    TRUE_NEGATIVE_RATE = "true_negative_rate"    # Specificity
    ROC_AUC = "roc_auc"                     # Area under ROC curve
    CALIBRATION_ERROR = "calibration_error"  # Calibration accuracy
    MEAN_ABSOLUTE_ERROR = "mean_absolute_error"  # Score prediction error
    CONFIDENCE_CORRELATION = "confidence_correlation"  # Confidence vs accuracy


class FeedbackType(Enum):
    """Types of feedback for model improvement."""
    TRUE_POSITIVE = "true_positive"         # Confirmed threat
    FALSE_POSITIVE = "false_positive"       # Benign flagged as threat
    TRUE_NEGATIVE = "true_negative"         # Correctly ignored benign
    FALSE_NEGATIVE = "false_negative"       # Missed threat
    PARTIAL_MATCH = "partial_match"         # Partially correct
    UPDATED_CONTEXT = "updated_context"     # New information available
    ANALYST_OVERRIDE = "analyst_override"   # Expert disagreement
    AUTOMATED_VALIDATION = "automated_validation"  # System validation


class OptimizationObjective(Enum):
    """Optimization objectives for model tuning."""
    MAXIMIZE_ACCURACY = "maximize_accuracy"
    MINIMIZE_FALSE_POSITIVES = "minimize_false_positives" 
    MAXIMIZE_THREAT_DETECTION = "maximize_threat_detection"
    OPTIMIZE_ANALYST_EFFICIENCY = "optimize_analyst_efficiency"
    BALANCE_PRECISION_RECALL = "balance_precision_recall"
    MINIMIZE_INVESTIGATION_LOAD = "minimize_investigation_load"


@dataclass
class ValidationFeedback:
    """Feedback record for scoring validation."""
    
    indicator_id: str
    original_score: float
    original_priority: PriorityBand
    
    # Feedback details
    feedback_type: FeedbackType
    ground_truth_threat: bool = False       # Is it actually a threat?
    ground_truth_priority: Optional[PriorityBand] = None
    analyst_confidence: float = 0.8         # Analyst confidence in feedback
    
    # Context
    feedback_source: str = "analyst"        # Who provided feedback
    investigation_outcome: str = ""         # What was discovered
    time_to_resolution: Optional[timedelta] = None  # Investigation time
    
    # Scoring corrections
    suggested_score: Optional[float] = None
    suggested_priority: Optional[PriorityBand] = None
    
    # Metadata
    feedback_timestamp: datetime = field(default_factory=datetime.utcnow)
    feedback_tags: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'indicator_info': {
                'indicator_id': self.indicator_id,
                'original_score': self.original_score,
                'original_priority': self.original_priority.value
            },
            'feedback': {
                'feedback_type': self.feedback_type.value,
                'ground_truth_threat': self.ground_truth_threat,
                'ground_truth_priority': self.ground_truth_priority.value if self.ground_truth_priority else None,
                'analyst_confidence': self.analyst_confidence
            },
            'context': {
                'feedback_source': self.feedback_source,
                'investigation_outcome': self.investigation_outcome,
                'time_to_resolution_hours': self.time_to_resolution.total_seconds() / 3600 if self.time_to_resolution else None
            },
            'corrections': {
                'suggested_score': self.suggested_score,
                'suggested_priority': self.suggested_priority.value if self.suggested_priority else None
            },
            'metadata': {
                'feedback_timestamp': self.feedback_timestamp.isoformat(),
                'feedback_tags': self.feedback_tags
            }
        }


@dataclass
class PerformanceMetrics:
    """Performance metrics for scoring system validation."""
    
    metric_name: ValidationMetric
    metric_value: float
    
    # Confidence intervals
    confidence_interval_lower: Optional[float] = None
    confidence_interval_upper: Optional[float] = None
    confidence_level: float = 0.95  # 95% confidence by default
    
    # Sample information
    sample_size: int = 0
    calculation_method: str = ""
    
    # Temporal context
    measurement_period: Optional[timedelta] = None
    measurement_timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'metric': {
                'name': self.metric_name.value,
                'value': self.metric_value
            },
            'confidence': {
                'interval_lower': self.confidence_interval_lower,
                'interval_upper': self.confidence_interval_upper,
                'confidence_level': self.confidence_level
            },
            'sample': {
                'sample_size': self.sample_size,
                'calculation_method': self.calculation_method
            },
            'temporal': {
                'measurement_period_days': self.measurement_period.days if self.measurement_period else None,
                'measurement_timestamp': self.measurement_timestamp.isoformat()
            }
        }


@dataclass
class CalibrationResult:
    """Results of scoring calibration analysis."""
    
    system_component: str  # Which scoring component
    
    # Calibration metrics
    calibration_error: float = 0.0          # Overall calibration error
    reliability_score: float = 0.0          # How well-calibrated
    sharpness_score: float = 0.0            # How confident/decisive
    
    # Calibration curve data
    predicted_probabilities: List[float] = field(default_factory=list)
    observed_frequencies: List[float] = field(default_factory=list)
    bin_counts: List[int] = field(default_factory=list)
    
    # Recommended adjustments
    bias_adjustment: float = 0.0            # Systematic bias correction
    scaling_factor: float = 1.0             # Score scaling adjustment
    recommended_thresholds: Dict[str, float] = field(default_factory=dict)
    
    # Metadata
    calibration_timestamp: datetime = field(default_factory=datetime.utcnow)
    sample_size: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'system_component': self.system_component,
            'calibration_metrics': {
                'calibration_error': self.calibration_error,
                'reliability_score': self.reliability_score,
                'sharpness_score': self.sharpness_score
            },
            'calibration_curve': {
                'predicted_probabilities': self.predicted_probabilities,
                'observed_frequencies': self.observed_frequencies,
                'bin_counts': self.bin_counts
            },
            'adjustments': {
                'bias_adjustment': self.bias_adjustment,
                'scaling_factor': self.scaling_factor,
                'recommended_thresholds': self.recommended_thresholds
            },
            'metadata': {
                'calibration_timestamp': self.calibration_timestamp.isoformat(),
                'sample_size': self.sample_size
            }
        }


@dataclass
class OptimizationResult:
    """Results of scoring optimization."""
    
    optimization_objective: OptimizationObjective
    
    # Original vs optimized performance
    baseline_metrics: Dict[ValidationMetric, float] = field(default_factory=dict)
    optimized_metrics: Dict[ValidationMetric, float] = field(default_factory=dict)
    improvement_percentages: Dict[ValidationMetric, float] = field(default_factory=dict)
    
    # Optimized parameters
    optimized_weights: Dict[str, float] = field(default_factory=dict)
    optimized_thresholds: Dict[str, float] = field(default_factory=dict)
    
    # Optimization process
    optimization_iterations: int = 0
    convergence_achieved: bool = False
    final_objective_value: float = 0.0
    
    # Validation
    cross_validation_score: Optional[float] = None
    holdout_validation_score: Optional[float] = None
    
    # Metadata
    optimization_timestamp: datetime = field(default_factory=datetime.utcnow)
    optimization_duration: Optional[timedelta] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'optimization_objective': self.optimization_objective.value,
            'performance': {
                'baseline_metrics': {metric.value: value for metric, value in self.baseline_metrics.items()},
                'optimized_metrics': {metric.value: value for metric, value in self.optimized_metrics.items()},
                'improvement_percentages': {metric.value: value for metric, value in self.improvement_percentages.items()}
            },
            'parameters': {
                'optimized_weights': self.optimized_weights,
                'optimized_thresholds': self.optimized_thresholds
            },
            'process': {
                'optimization_iterations': self.optimization_iterations,
                'convergence_achieved': self.convergence_achieved,
                'final_objective_value': self.final_objective_value
            },
            'validation': {
                'cross_validation_score': self.cross_validation_score,
                'holdout_validation_score': self.holdout_validation_score
            },
            'metadata': {
                'optimization_timestamp': self.optimization_timestamp.isoformat(),
                'optimization_duration_minutes': self.optimization_duration.total_seconds() / 60 if self.optimization_duration else None
            }
        }


class FeedbackCollector:
    """Collects and manages validation feedback from analysts and systems."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize feedback collector."""
        self.config = config or {}
        
        # Feedback storage (in production, this would be persistent)
        self.feedback_records: List[ValidationFeedback] = []
        self.feedback_by_indicator: Dict[str, List[ValidationFeedback]] = defaultdict(list)
        
        # Feedback quality thresholds
        self.min_analyst_confidence = 0.6    # Minimum confidence to accept feedback
        self.feedback_timeout = timedelta(days=30)  # How long to wait for feedback
        
        logger.debug("Feedback collector initialized")
    
    def add_feedback(self, feedback: ValidationFeedback) -> bool:
        """Add validation feedback."""
        
        # Validate feedback quality
        if feedback.analyst_confidence < self.min_analyst_confidence:
            logger.warning(f"Feedback for {feedback.indicator_id} rejected due to low analyst confidence")
            return False
        
        # Store feedback
        self.feedback_records.append(feedback)
        self.feedback_by_indicator[feedback.indicator_id].append(feedback)
        
        logger.debug(f"Added feedback for indicator {feedback.indicator_id}: {feedback.feedback_type.value}")
        return True
    
    def get_feedback_for_indicator(self, indicator_id: str) -> List[ValidationFeedback]:
        """Get all feedback for a specific indicator."""
        return self.feedback_by_indicator.get(indicator_id, [])
    
    def get_feedback_by_type(self, feedback_type: FeedbackType) -> List[ValidationFeedback]:
        """Get feedback by type."""
        return [fb for fb in self.feedback_records if fb.feedback_type == feedback_type]
    
    def get_recent_feedback(self, since: Optional[datetime] = None) -> List[ValidationFeedback]:
        """Get recent feedback."""
        
        if since is None:
            since = datetime.utcnow() - timedelta(days=7)  # Last week by default
        
        return [fb for fb in self.feedback_records if fb.feedback_timestamp >= since]
    
    def get_feedback_statistics(self) -> Dict[str, Any]:
        """Get feedback collection statistics."""
        
        if not self.feedback_records:
            return {'total_feedback': 0}
        
        type_counts = Counter(fb.feedback_type.value for fb in self.feedback_records)
        source_counts = Counter(fb.feedback_source for fb in self.feedback_records)
        
        # Calculate feedback rates
        total_feedback = len(self.feedback_records)
        true_positives = len(self.get_feedback_by_type(FeedbackType.TRUE_POSITIVE))
        false_positives = len(self.get_feedback_by_type(FeedbackType.FALSE_POSITIVE))
        
        return {
            'total_feedback': total_feedback,
            'feedback_by_type': dict(type_counts),
            'feedback_by_source': dict(source_counts),
            'false_positive_rate': false_positives / total_feedback if total_feedback > 0 else 0,
            'true_positive_rate': true_positives / total_feedback if total_feedback > 0 else 0,
            'indicators_with_feedback': len(self.feedback_by_indicator),
            'average_analyst_confidence': statistics.mean(fb.analyst_confidence for fb in self.feedback_records)
        }


class PerformanceAnalyzer:
    """Analyzes scoring system performance using validation feedback."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize performance analyzer."""
        self.config = config or {}
        
        # Analysis parameters
        self.min_sample_size = 20           # Minimum samples for reliable metrics
        self.confidence_level = 0.95        # Confidence level for intervals
        
        logger.debug("Performance analyzer initialized")
    
    def calculate_performance_metrics(self, 
                                    feedback_records: List[ValidationFeedback]) -> List[PerformanceMetrics]:
        """Calculate comprehensive performance metrics."""
        
        if len(feedback_records) < self.min_sample_size:
            logger.warning(f"Insufficient feedback ({len(feedback_records)}) for reliable metrics")
            return []
        
        metrics = []
        
        # Prepare ground truth data
        y_true, y_pred, scores = self._prepare_ground_truth_data(feedback_records)
        
        if not y_true:
            logger.warning("No valid ground truth data available")
            return []
        
        # Calculate binary classification metrics
        metrics.extend(self._calculate_classification_metrics(y_true, y_pred, len(feedback_records)))
        
        # Calculate regression metrics for scores
        if scores:
            metrics.extend(self._calculate_regression_metrics(feedback_records, len(feedback_records)))
        
        # Calculate calibration metrics
        if scores and len(set(y_true)) > 1:  # Need both classes
            calibration_metrics = self._calculate_calibration_metrics(scores, y_true, len(feedback_records))
            metrics.extend(calibration_metrics)
        
        return metrics
    
    def _prepare_ground_truth_data(self, 
                                 feedback_records: List[ValidationFeedback]) -> Tuple[List[bool], List[bool], List[float]]:
        """Prepare ground truth data from feedback."""
        
        y_true = []  # Ground truth (is threat)
        y_pred = []  # Predicted (above threshold)
        scores = []  # Actual scores
        
        # Use P2 as threshold for "predicted positive"
        threat_threshold = 0.65  # P2 threshold from priority bands
        
        for feedback in feedback_records:
            # Skip low-confidence feedback
            if feedback.analyst_confidence < 0.6:
                continue
            
            # Ground truth from analyst feedback
            ground_truth = feedback.ground_truth_threat
            
            # Prediction based on original score
            predicted = feedback.original_score >= threat_threshold
            
            y_true.append(ground_truth)
            y_pred.append(predicted)
            scores.append(feedback.original_score)
        
        return y_true, y_pred, scores
    
    def _calculate_classification_metrics(self, 
                                        y_true: List[bool], 
                                        y_pred: List[bool],
                                        sample_size: int) -> List[PerformanceMetrics]:
        """Calculate binary classification metrics."""
        
        metrics = []
        
        # Calculate confusion matrix elements
        tp = sum(1 for true, pred in zip(y_true, y_pred) if true and pred)
        fp = sum(1 for true, pred in zip(y_true, y_pred) if not true and pred)
        tn = sum(1 for true, pred in zip(y_true, y_pred) if not true and not pred)
        fn = sum(1 for true, pred in zip(y_true, y_pred) if true and not pred)
        
        total = tp + fp + tn + fn
        
        if total == 0:
            return metrics
        
        # Accuracy
        accuracy = (tp + tn) / total if total > 0 else 0
        metrics.append(PerformanceMetrics(
            metric_name=ValidationMetric.ACCURACY,
            metric_value=accuracy,
            sample_size=sample_size,
            calculation_method="confusion_matrix"
        ))
        
        # Precision
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        metrics.append(PerformanceMetrics(
            metric_name=ValidationMetric.PRECISION,
            metric_value=precision,
            sample_size=sample_size,
            calculation_method="tp_over_tp_plus_fp"
        ))
        
        # Recall (Sensitivity)
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        metrics.append(PerformanceMetrics(
            metric_name=ValidationMetric.RECALL,
            metric_value=recall,
            sample_size=sample_size,
            calculation_method="tp_over_tp_plus_fn"
        ))
        
        # F1 Score
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        metrics.append(PerformanceMetrics(
            metric_name=ValidationMetric.F1_SCORE,
            metric_value=f1_score,
            sample_size=sample_size,
            calculation_method="harmonic_mean_precision_recall"
        ))
        
        # False Positive Rate
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        metrics.append(PerformanceMetrics(
            metric_name=ValidationMetric.FALSE_POSITIVE_RATE,
            metric_value=fpr,
            sample_size=sample_size,
            calculation_method="fp_over_fp_plus_tn"
        ))
        
        # True Negative Rate (Specificity)
        tnr = tn / (tn + fp) if (tn + fp) > 0 else 0
        metrics.append(PerformanceMetrics(
            metric_name=ValidationMetric.TRUE_NEGATIVE_RATE,
            metric_value=tnr,
            sample_size=sample_size,
            calculation_method="tn_over_tn_plus_fp"
        ))
        
        return metrics
    
    def _calculate_regression_metrics(self, 
                                    feedback_records: List[ValidationFeedback],
                                    sample_size: int) -> List[PerformanceMetrics]:
        """Calculate regression metrics for score accuracy."""
        
        metrics = []
        
        # Get suggested scores vs original scores
        original_scores = []
        suggested_scores = []
        
        for feedback in feedback_records:
            if feedback.suggested_score is not None:
                original_scores.append(feedback.original_score)
                suggested_scores.append(feedback.suggested_score)
        
        if len(original_scores) < 10:  # Need minimum samples
            return metrics
        
        # Mean Absolute Error
        mae = statistics.mean(abs(orig - sugg) for orig, sugg in zip(original_scores, suggested_scores))
        metrics.append(PerformanceMetrics(
            metric_name=ValidationMetric.MEAN_ABSOLUTE_ERROR,
            metric_value=mae,
            sample_size=len(original_scores),
            calculation_method="mean_absolute_difference"
        ))
        
        return metrics
    
    def _calculate_calibration_metrics(self, 
                                     scores: List[float], 
                                     y_true: List[bool],
                                     sample_size: int) -> List[PerformanceMetrics]:
        """Calculate calibration metrics."""
        
        metrics = []
        
        # Simple calibration error calculation
        # Bin scores and check if predicted probability matches observed frequency
        num_bins = min(10, len(scores) // 5)  # At least 5 samples per bin
        
        if num_bins < 3:
            return metrics
        
        # Create bins
        sorted_indices = sorted(range(len(scores)), key=lambda i: scores[i])
        bin_size = len(scores) // num_bins
        
        calibration_errors = []
        
        for i in range(num_bins):
            start_idx = i * bin_size
            end_idx = (i + 1) * bin_size if i < num_bins - 1 else len(scores)
            
            bin_indices = sorted_indices[start_idx:end_idx]
            bin_scores = [scores[j] for j in bin_indices]
            bin_labels = [y_true[j] for j in bin_indices]
            
            if len(bin_scores) > 0:
                avg_predicted_prob = statistics.mean(bin_scores)
                observed_frequency = sum(bin_labels) / len(bin_labels)
                calibration_error = abs(avg_predicted_prob - observed_frequency)
                calibration_errors.append(calibration_error)
        
        if calibration_errors:
            avg_calibration_error = statistics.mean(calibration_errors)
            metrics.append(PerformanceMetrics(
                metric_name=ValidationMetric.CALIBRATION_ERROR,
                metric_value=avg_calibration_error,
                sample_size=sample_size,
                calculation_method="binned_calibration_error"
            ))
        
        return metrics
    
    def analyze_priority_band_performance(self, 
                                        feedback_records: List[ValidationFeedback]) -> Dict[str, Dict[str, float]]:
        """Analyze performance by priority band."""
        
        band_performance = {}
        
        for band in PriorityBand:
            band_feedback = [fb for fb in feedback_records if fb.original_priority == band]
            
            if len(band_feedback) < 5:  # Need minimum samples
                continue
            
            # Calculate band-specific metrics
            true_threats = sum(1 for fb in band_feedback if fb.ground_truth_threat)
            false_positives = sum(1 for fb in band_feedback if not fb.ground_truth_threat)
            total = len(band_feedback)
            
            band_performance[band.value] = {
                'total_indicators': total,
                'true_threat_rate': true_threats / total if total > 0 else 0,
                'false_positive_rate': false_positives / total if total > 0 else 0,
                'average_investigation_time': statistics.mean([
                    fb.time_to_resolution.total_seconds() / 3600 
                    for fb in band_feedback 
                    if fb.time_to_resolution
                ]) if any(fb.time_to_resolution for fb in band_feedback) else 0
            }
        
        return band_performance


class CalibrationEngine:
    """Calibrates scoring systems based on feedback and performance analysis."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize calibration engine."""
        self.config = config or {}
        
        # Calibration parameters
        self.min_calibration_samples = 50   # Minimum samples for calibration
        self.calibration_bins = 10          # Number of bins for calibration curve
        
        logger.debug("Calibration engine initialized")
    
    def calibrate_scoring_system(self, 
                                feedback_records: List[ValidationFeedback],
                                component_name: str = "overall") -> CalibrationResult:
        """Calibrate a scoring system component."""
        
        result = CalibrationResult(
            system_component=component_name,
            sample_size=len(feedback_records)
        )
        
        if len(feedback_records) < self.min_calibration_samples:
            logger.warning(f"Insufficient samples for calibration: {len(feedback_records)}")
            return result
        
        # Prepare calibration data
        scores = []
        labels = []
        
        for feedback in feedback_records:
            if feedback.analyst_confidence >= 0.7:  # High-confidence feedback only
                scores.append(feedback.original_score)
                labels.append(feedback.ground_truth_threat)
        
        if len(scores) < self.min_calibration_samples:
            return result
        
        # Calculate calibration curve
        result.predicted_probabilities, result.observed_frequencies, result.bin_counts = \
            self._calculate_calibration_curve(scores, labels)
        
        # Calculate calibration metrics
        result.calibration_error = self._calculate_calibration_error(
            result.predicted_probabilities, result.observed_frequencies, result.bin_counts
        )
        
        result.reliability_score = 1.0 - result.calibration_error  # Higher is better
        result.sharpness_score = self._calculate_sharpness(scores)
        
        # Calculate recommended adjustments
        result.bias_adjustment, result.scaling_factor = self._calculate_adjustments(
            result.predicted_probabilities, result.observed_frequencies
        )
        
        # Calculate recommended thresholds
        result.recommended_thresholds = self._calculate_optimal_thresholds(scores, labels)
        
        return result
    
    def _calculate_calibration_curve(self, 
                                   scores: List[float], 
                                   labels: List[bool]) -> Tuple[List[float], List[float], List[int]]:
        """Calculate calibration curve data."""
        
        # Sort by score
        sorted_pairs = sorted(zip(scores, labels))
        
        # Create bins
        bin_size = len(sorted_pairs) // self.calibration_bins
        
        predicted_probs = []
        observed_freqs = []
        bin_counts = []
        
        for i in range(self.calibration_bins):
            start_idx = i * bin_size
            end_idx = (i + 1) * bin_size if i < self.calibration_bins - 1 else len(sorted_pairs)
            
            bin_data = sorted_pairs[start_idx:end_idx]
            
            if bin_data:
                bin_scores = [pair[0] for pair in bin_data]
                bin_labels = [pair[1] for pair in bin_data]
                
                avg_predicted = statistics.mean(bin_scores)
                observed_freq = sum(bin_labels) / len(bin_labels)
                
                predicted_probs.append(avg_predicted)
                observed_freqs.append(observed_freq)
                bin_counts.append(len(bin_data))
        
        return predicted_probs, observed_freqs, bin_counts
    
    def _calculate_calibration_error(self, 
                                   predicted_probs: List[float], 
                                   observed_freqs: List[float], 
                                   bin_counts: List[int]) -> float:
        """Calculate Expected Calibration Error (ECE)."""
        
        if not predicted_probs or sum(bin_counts) == 0:
            return 1.0  # Maximum error
        
        total_samples = sum(bin_counts)
        weighted_errors = []
        
        for pred, obs, count in zip(predicted_probs, observed_freqs, bin_counts):
            bin_error = abs(pred - obs)
            bin_weight = count / total_samples
            weighted_errors.append(bin_error * bin_weight)
        
        return sum(weighted_errors)
    
    def _calculate_sharpness(self, scores: List[float]) -> float:
        """Calculate sharpness (how decisive the scores are)."""
        
        if not scores:
            return 0.0
        
        # Sharpness is measured as variance of predicted probabilities
        # Higher variance = more decisive/sharp predictions
        variance = statistics.variance(scores) if len(scores) > 1 else 0.0
        
        # Normalize to 0-1 range (assuming max variance is 0.25 for probabilities)
        normalized_sharpness = min(variance / 0.25, 1.0)
        
        return normalized_sharpness
    
    def _calculate_adjustments(self, 
                             predicted_probs: List[float], 
                             observed_freqs: List[float]) -> Tuple[float, float]:
        """Calculate bias adjustment and scaling factor."""
        
        if not predicted_probs or not observed_freqs:
            return 0.0, 1.0
        
        # Calculate systematic bias (average difference)
        differences = [obs - pred for pred, obs in zip(predicted_probs, observed_freqs)]
        bias_adjustment = statistics.mean(differences)
        
        # Calculate scaling factor using linear regression slope
        # Simple approach: ratio of observed to predicted
        if statistics.mean(predicted_probs) > 0:
            scaling_factor = statistics.mean(observed_freqs) / statistics.mean(predicted_probs)
            scaling_factor = max(0.1, min(10.0, scaling_factor))  # Reasonable bounds
        else:
            scaling_factor = 1.0
        
        return bias_adjustment, scaling_factor
    
    def _calculate_optimal_thresholds(self, 
                                    scores: List[float], 
                                    labels: List[bool]) -> Dict[str, float]:
        """Calculate optimal thresholds for different objectives."""
        
        thresholds = {}
        
        if len(scores) < 20:
            return thresholds
        
        # Test different threshold values
        test_thresholds = [i * 0.05 for i in range(1, 20)]  # 0.05 to 0.95
        
        best_f1_threshold = 0.5
        best_f1_score = 0.0
        
        best_precision_threshold = 0.5
        best_precision_score = 0.0
        
        for threshold in test_thresholds:
            # Calculate predictions at this threshold
            predictions = [score >= threshold for score in scores]
            
            # Calculate metrics
            tp = sum(1 for true, pred in zip(labels, predictions) if true and pred)
            fp = sum(1 for true, pred in zip(labels, predictions) if not true and pred)
            fn = sum(1 for true, pred in zip(labels, predictions) if true and not pred)
            
            # Precision and Recall
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            
            # F1 Score
            f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
            
            # Track best thresholds
            if f1 > best_f1_score:
                best_f1_score = f1
                best_f1_threshold = threshold
            
            if precision > best_precision_score:
                best_precision_score = precision
                best_precision_threshold = threshold
        
        thresholds['optimal_f1'] = best_f1_threshold
        thresholds['optimal_precision'] = best_precision_threshold
        
        return thresholds


class OptimizationEngine:
    """Optimizes scoring system parameters based on feedback and objectives."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize optimization engine.""" 
        self.config = config or {}
        
        # Optimization parameters
        self.max_iterations = 100
        self.convergence_tolerance = 0.001
        self.learning_rate = 0.01
        
        logger.debug("Optimization engine initialized")
    
    def optimize_scoring_weights(self, 
                                feedback_records: List[ValidationFeedback],
                                current_weights: Dict[str, float],
                                objective: OptimizationObjective) -> OptimizationResult:
        """Optimize scoring component weights."""
        
        result = OptimizationResult(optimization_objective=objective)
        start_time = datetime.utcnow()
        
        if len(feedback_records) < 30:  # Need sufficient data
            logger.warning("Insufficient feedback for optimization")
            return result
        
        # Calculate baseline metrics
        result.baseline_metrics = self._evaluate_current_performance(feedback_records, current_weights)
        
        # Perform optimization
        optimized_weights, final_score, iterations = self._optimize_weights(
            feedback_records, current_weights, objective
        )
        
        result.optimized_weights = optimized_weights
        result.final_objective_value = final_score
        result.optimization_iterations = iterations
        result.convergence_achieved = iterations < self.max_iterations
        
        # Calculate optimized metrics
        result.optimized_metrics = self._evaluate_current_performance(feedback_records, optimized_weights)
        
        # Calculate improvements
        for metric in result.baseline_metrics:
            if metric in result.optimized_metrics:
                baseline = result.baseline_metrics[metric]
                optimized = result.optimized_metrics[metric]
                
                if baseline > 0:
                    improvement = ((optimized - baseline) / baseline) * 100
                    result.improvement_percentages[metric] = improvement
        
        # Validation
        result.cross_validation_score = self._cross_validate_weights(
            feedback_records, optimized_weights, objective
        )
        
        result.optimization_duration = datetime.utcnow() - start_time
        
        return result
    
    def _evaluate_current_performance(self, 
                                    feedback_records: List[ValidationFeedback],
                                    weights: Dict[str, float]) -> Dict[ValidationMetric, float]:
        """Evaluate performance with current weights."""
        
        # Simulate scoring with given weights
        # In real implementation, this would re-score indicators with new weights
        
        metrics = {}
        
        # Simple evaluation - count correct predictions
        correct_predictions = 0
        total_predictions = 0
        
        for feedback in feedback_records:
            if feedback.analyst_confidence >= 0.7:
                # Simulate adjusted score (simplified)
                adjusted_score = feedback.original_score  # In reality, would apply weights
                
                # Check if prediction would be correct
                predicted_threat = adjusted_score >= 0.6  # P2 threshold
                actual_threat = feedback.ground_truth_threat
                
                if predicted_threat == actual_threat:
                    correct_predictions += 1
                total_predictions += 1
        
        if total_predictions > 0:
            accuracy = correct_predictions / total_predictions
            metrics[ValidationMetric.ACCURACY] = accuracy
        
        return metrics
    
    def _optimize_weights(self, 
                        feedback_records: List[ValidationFeedback],
                        initial_weights: Dict[str, float],
                        objective: OptimizationObjective) -> Tuple[Dict[str, float], float, int]:
        """Perform weight optimization using simple gradient descent."""
        
        current_weights = initial_weights.copy()
        best_score = float('-inf')
        iterations = 0
        
        for iteration in range(self.max_iterations):
            # Evaluate current performance
            current_score = self._calculate_objective_score(
                feedback_records, current_weights, objective
            )
            
            if current_score > best_score:
                best_score = current_score
                best_weights = current_weights.copy()
            
            # Simple random search optimization (in practice, use more sophisticated methods)
            # Randomly adjust weights and see if performance improves
            test_weights = current_weights.copy()
            
            # Randomly select a weight to adjust
            weight_keys = list(test_weights.keys())
            if weight_keys:
                random_key = weight_keys[iteration % len(weight_keys)]
                adjustment = (hash(str(iteration)) % 21 - 10) / 1000  # -0.01 to +0.01
                test_weights[random_key] = max(0.0, min(1.0, test_weights[random_key] + adjustment))
                
                # Renormalize weights
                total_weight = sum(test_weights.values())
                if total_weight > 0:
                    test_weights = {k: v / total_weight for k, v in test_weights.items()}
            
            # Evaluate test weights
            test_score = self._calculate_objective_score(
                feedback_records, test_weights, objective
            )
            
            # Accept if better
            if test_score > current_score:
                current_weights = test_weights
            
            iterations += 1
            
            # Check convergence
            if iteration > 10 and abs(current_score - best_score) < self.convergence_tolerance:
                break
        
        return best_weights if 'best_weights' in locals() else current_weights, best_score, iterations
    
    def _calculate_objective_score(self, 
                                 feedback_records: List[ValidationFeedback],
                                 weights: Dict[str, float],
                                 objective: OptimizationObjective) -> float:
        """Calculate objective function value."""
        
        # Simulate performance with given weights
        metrics = self._evaluate_current_performance(feedback_records, weights)
        
        if not metrics:
            return 0.0
        
        # Return objective-specific score
        if objective == OptimizationObjective.MAXIMIZE_ACCURACY:
            return metrics.get(ValidationMetric.ACCURACY, 0.0)
        elif objective == OptimizationObjective.MINIMIZE_FALSE_POSITIVES:
            fpr = metrics.get(ValidationMetric.FALSE_POSITIVE_RATE, 1.0)
            return 1.0 - fpr  # Maximize (1 - FPR)
        else:
            # Default to accuracy
            return metrics.get(ValidationMetric.ACCURACY, 0.0)
    
    def _cross_validate_weights(self, 
                              feedback_records: List[ValidationFeedback],
                              weights: Dict[str, float],
                              objective: OptimizationObjective) -> float:
        """Perform cross-validation of optimized weights."""
        
        if len(feedback_records) < 20:
            return 0.0
        
        # Simple 5-fold cross-validation
        fold_size = len(feedback_records) // 5
        cv_scores = []
        
        for fold in range(5):
            # Split data
            start_idx = fold * fold_size
            end_idx = (fold + 1) * fold_size if fold < 4 else len(feedback_records)
            
            test_data = feedback_records[start_idx:end_idx]
            train_data = feedback_records[:start_idx] + feedback_records[end_idx:]
            
            if len(test_data) > 0 and len(train_data) > 0:
                # Evaluate on test data
                fold_score = self._calculate_objective_score(test_data, weights, objective)
                cv_scores.append(fold_score)
        
        return statistics.mean(cv_scores) if cv_scores else 0.0


class ScoringValidationFramework:
    """Main framework orchestrating all validation and improvement components."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize validation framework."""
        self.config = config or {}
        
        # Initialize components
        self.feedback_collector = FeedbackCollector(self.config.get('feedback_config', {}))
        self.performance_analyzer = PerformanceAnalyzer(self.config.get('performance_config', {}))
        self.calibration_engine = CalibrationEngine(self.config.get('calibration_config', {}))
        self.optimization_engine = OptimizationEngine(self.config.get('optimization_config', {}))
        
        # Validation state
        self.last_validation_run: Optional[datetime] = None
        self.validation_history: List[Dict[str, Any]] = []
        
        logger.info("Scoring validation framework initialized")
    
    def run_comprehensive_validation(self, 
                                   scoring_system_weights: Dict[str, float],
                                   optimization_objective: OptimizationObjective = OptimizationObjective.MAXIMIZE_ACCURACY) -> Dict[str, Any]:
        """Run comprehensive validation analysis."""
        
        validation_results = {
            'validation_timestamp': datetime.utcnow().isoformat(),
            'feedback_statistics': {},
            'performance_metrics': [],
            'calibration_results': {},
            'optimization_results': {},
            'recommendations': []
        }
        
        # Get recent feedback
        recent_feedback = self.feedback_collector.get_recent_feedback(
            since=datetime.utcnow() - timedelta(days=30)
        )
        
        logger.info(f"Running validation with {len(recent_feedback)} feedback records")
        
        # Analyze feedback statistics
        validation_results['feedback_statistics'] = self.feedback_collector.get_feedback_statistics()
        
        if len(recent_feedback) < 10:
            validation_results['recommendations'].append("Insufficient feedback for comprehensive validation")
            return validation_results
        
        # Calculate performance metrics
        try:
            performance_metrics = self.performance_analyzer.calculate_performance_metrics(recent_feedback)
            validation_results['performance_metrics'] = [metric.to_dict() for metric in performance_metrics]
            
            # Analyze priority band performance
            band_performance = self.performance_analyzer.analyze_priority_band_performance(recent_feedback)
            validation_results['priority_band_performance'] = band_performance
            
        except Exception as e:
            logger.error(f"Performance analysis failed: {e}")
            validation_results['recommendations'].append("Performance analysis failed - check feedback data quality")
        
        # Run calibration analysis
        try:
            calibration_result = self.calibration_engine.calibrate_scoring_system(recent_feedback)
            validation_results['calibration_results'] = calibration_result.to_dict()
            
            # Add calibration recommendations
            if calibration_result.calibration_error > 0.1:
                validation_results['recommendations'].append("High calibration error detected - consider score recalibration")
            
            if abs(calibration_result.bias_adjustment) > 0.05:
                validation_results['recommendations'].append(f"Systematic bias detected: {calibration_result.bias_adjustment:.3f}")
                
        except Exception as e:
            logger.error(f"Calibration analysis failed: {e}")
            validation_results['recommendations'].append("Calibration analysis failed")
        
        # Run optimization
        try:
            optimization_result = self.optimization_engine.optimize_scoring_weights(
                recent_feedback, scoring_system_weights, optimization_objective
            )
            validation_results['optimization_results'] = optimization_result.to_dict()
            
            # Add optimization recommendations
            if optimization_result.convergence_achieved:
                max_improvement = max(optimization_result.improvement_percentages.values()) if optimization_result.improvement_percentages else 0
                if max_improvement > 5:  # 5% improvement threshold
                    validation_results['recommendations'].append(f"Significant improvement possible: {max_improvement:.1f}%")
            
        except Exception as e:
            logger.error(f"Optimization failed: {e}")
            validation_results['recommendations'].append("Optimization failed")
        
        # Store validation history
        self.validation_history.append(validation_results)
        self.last_validation_run = datetime.utcnow()
        
        # Keep only last 10 validation runs
        if len(self.validation_history) > 10:
            self.validation_history = self.validation_history[-10:]
        
        return validation_results
    
    def add_analyst_feedback(self, 
                           indicator_id: str,
                           original_score: float,
                           original_priority: PriorityBand,
                           is_threat: bool,
                           analyst_confidence: float = 0.8,
                           feedback_details: Optional[Dict[str, Any]] = None) -> bool:
        """Add analyst feedback for an indicator."""
        
        feedback = ValidationFeedback(
            indicator_id=indicator_id,
            original_score=original_score,
            original_priority=original_priority,
            feedback_type=FeedbackType.TRUE_POSITIVE if is_threat else FeedbackType.FALSE_POSITIVE,
            ground_truth_threat=is_threat,
            analyst_confidence=analyst_confidence
        )
        
        if feedback_details:
            feedback.feedback_source = feedback_details.get('source', 'analyst')
            feedback.investigation_outcome = feedback_details.get('outcome', '')
            feedback.suggested_score = feedback_details.get('suggested_score')
            
            if feedback_details.get('suggested_priority'):
                try:
                    feedback.suggested_priority = PriorityBand(feedback_details['suggested_priority'])
                except ValueError:
                    pass
        
        return self.feedback_collector.add_feedback(feedback)
    
    def get_validation_summary(self) -> Dict[str, Any]:
        """Get summary of validation framework status."""
        
        return {
            'framework_status': {
                'last_validation_run': self.last_validation_run.isoformat() if self.last_validation_run else None,
                'total_validation_runs': len(self.validation_history),
                'components_active': {
                    'feedback_collector': bool(self.feedback_collector),
                    'performance_analyzer': bool(self.performance_analyzer),
                    'calibration_engine': bool(self.calibration_engine),
                    'optimization_engine': bool(self.optimization_engine)
                }
            },
            'feedback_summary': self.feedback_collector.get_feedback_statistics(),
            'recent_recommendations': self.validation_history[-1]['recommendations'] if self.validation_history else []
        }
    
    def export_validation_data(self) -> Dict[str, Any]:
        """Export validation data for external analysis."""
        
        return {
            'feedback_records': [fb.to_dict() for fb in self.feedback_collector.feedback_records],
            'validation_history': self.validation_history,
            'export_timestamp': datetime.utcnow().isoformat()
        }