"""
Advanced temporal scoring system for threat intelligence.

This module implements sophisticated temporal scoring with time-based decay algorithms,
freshness factors, trend analysis, activity pattern recognition, and temporal 
correlation analysis.
"""

import logging
import statistics
import math
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, Counter, deque
import json

try:
    from ..normalizers.schema import NormalizedIndicator, IndicatorType
    from .engine import ThreatScore
except ImportError:
    from normalizers.schema import NormalizedIndicator, IndicatorType
    from scoring.engine import ThreatScore

logger = logging.getLogger(__name__)


class TemporalPattern(Enum):
    """Temporal activity patterns."""
    BURST = "burst"                    # Sudden spike in activity
    SUSTAINED = "sustained"            # Consistent activity over time
    PERIODIC = "periodic"              # Regular intervals
    DECLINING = "declining"            # Decreasing activity
    EMERGING = "emerging"              # New and growing activity
    DORMANT = "dormant"               # Previously active, now quiet
    SPORADIC = "sporadic"             # Irregular activity
    SEASONAL = "seasonal"             # Time-of-day/week patterns


class DecayFunction(Enum):
    """Time-based decay function types."""
    LINEAR = "linear"                  # Constant rate decline
    EXPONENTIAL = "exponential"        # Accelerating decline  
    LOGARITHMIC = "logarithmic"        # Decelerating decline
    STEP = "step"                     # Threshold-based drops
    CUSTOM = "custom"                 # Custom decay curves


class TemporalWeight(Enum):
    """Temporal weighting factors."""
    RECENCY = "recency"               # How recent the activity
    FREQUENCY = "frequency"           # How often it occurs  
    PERSISTENCE = "persistence"       # How long it lasts
    VOLATILITY = "volatility"         # How variable it is
    ACCELERATION = "acceleration"     # Rate of change
    SEASONALITY = "seasonality"       # Time-based patterns


@dataclass 
class TemporalObservation:
    """Single temporal observation of indicator activity."""
    
    timestamp: datetime
    source: str
    confidence: float = 1.0
    
    # Activity metrics
    observation_count: int = 1
    severity_level: Optional[float] = None
    context_tags: List[str] = field(default_factory=list)
    
    # Metadata
    collection_method: str = "unknown"
    geo_location: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'timestamp': self.timestamp.isoformat(),
            'source': self.source,
            'confidence': self.confidence,
            'metrics': {
                'observation_count': self.observation_count,
                'severity_level': self.severity_level
            },
            'context': {
                'tags': self.context_tags,
                'collection_method': self.collection_method,
                'geo_location': self.geo_location
            }
        }


@dataclass
class TemporalTrendAnalysis:
    """Analysis of temporal trends in indicator activity."""
    
    indicator_id: str
    analysis_period: timedelta
    
    # Pattern identification
    detected_pattern: TemporalPattern = TemporalPattern.SPORADIC
    pattern_confidence: float = 0.0
    pattern_strength: float = 0.0
    
    # Trend metrics
    activity_trend: float = 0.0        # -1 (declining) to +1 (growing)
    velocity: float = 0.0              # Rate of change
    acceleration: float = 0.0          # Rate of velocity change
    
    # Frequency analysis
    observation_frequency: float = 0.0  # Observations per day
    peak_activity_times: List[int] = field(default_factory=list)  # Hours of day
    
    # Volatility metrics  
    activity_variance: float = 0.0
    burst_events: int = 0
    quiet_periods: int = 0
    
    # Seasonality
    weekly_pattern: List[float] = field(default_factory=list)  # 7 days
    daily_pattern: List[float] = field(default_factory=list)   # 24 hours
    
    # Predictions
    predicted_next_activity: Optional[datetime] = None
    activity_forecast: Dict[str, float] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'indicator_id': self.indicator_id,
            'analysis_period_days': self.analysis_period.days,
            'patterns': {
                'detected_pattern': self.detected_pattern.value,
                'pattern_confidence': self.pattern_confidence,
                'pattern_strength': self.pattern_strength
            },
            'trends': {
                'activity_trend': self.activity_trend,
                'velocity': self.velocity,
                'acceleration': self.acceleration
            },
            'frequency': {
                'observation_frequency': self.observation_frequency,
                'peak_activity_times': self.peak_activity_times
            },
            'volatility': {
                'activity_variance': self.activity_variance,
                'burst_events': self.burst_events,
                'quiet_periods': self.quiet_periods
            },
            'seasonality': {
                'weekly_pattern': self.weekly_pattern,
                'daily_pattern': self.daily_pattern
            },
            'predictions': {
                'predicted_next_activity': self.predicted_next_activity.isoformat() if self.predicted_next_activity else None,
                'activity_forecast': self.activity_forecast
            }
        }


@dataclass
class TemporalScore:
    """Comprehensive temporal scoring result."""
    
    indicator_id: str
    base_temporal_score: float = 0.0
    
    # Component scores
    recency_score: float = 0.0
    frequency_score: float = 0.0  
    persistence_score: float = 0.0
    volatility_score: float = 0.0
    trend_score: float = 0.0
    pattern_score: float = 0.0
    
    # Decay adjustments
    decay_factor: float = 1.0
    freshness_bonus: float = 0.0
    staleness_penalty: float = 0.0
    
    # Final computed scores
    adjusted_temporal_score: float = 0.0
    temporal_multiplier: float = 1.0
    
    # Supporting data
    temporal_factors: List[str] = field(default_factory=list)
    trend_analysis: Optional[TemporalTrendAnalysis] = None
    
    # Timestamps
    calculation_time: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'indicator_id': self.indicator_id,
            'base_score': self.base_temporal_score,
            'components': {
                'recency_score': self.recency_score,
                'frequency_score': self.frequency_score,
                'persistence_score': self.persistence_score,
                'volatility_score': self.volatility_score,
                'trend_score': self.trend_score,
                'pattern_score': self.pattern_score
            },
            'adjustments': {
                'decay_factor': self.decay_factor,
                'freshness_bonus': self.freshness_bonus,
                'staleness_penalty': self.staleness_penalty
            },
            'final_scores': {
                'adjusted_temporal_score': self.adjusted_temporal_score,
                'temporal_multiplier': self.temporal_multiplier
            },
            'metadata': {
                'temporal_factors': self.temporal_factors,
                'trend_analysis': self.trend_analysis.to_dict() if self.trend_analysis else None,
                'calculation_time': self.calculation_time.isoformat()
            }
        }


class DecayEngine:
    """Implements various time-based decay functions."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize decay engine.""" 
        self.config = config or {}
        
        # Default decay parameters
        self.default_half_life = timedelta(days=30)  # Score halves after 30 days
        self.min_decay_factor = 0.01                 # Minimum 1% of original score
        self.max_age = timedelta(days=365)           # Maximum age before zero score
        
        logger.debug("Decay engine initialized")
    
    def calculate_decay(self, 
                       age: timedelta,
                       decay_function: DecayFunction = DecayFunction.EXPONENTIAL,
                       half_life: Optional[timedelta] = None) -> float:
        """Calculate decay factor based on age."""
        
        if age <= timedelta(0):
            return 1.0  # No decay for future/current times
        
        if age >= self.max_age:
            return self.min_decay_factor
        
        half_life = half_life or self.default_half_life
        
        # Calculate decay based on function type
        if decay_function == DecayFunction.EXPONENTIAL:
            return self._exponential_decay(age, half_life)
        elif decay_function == DecayFunction.LINEAR:
            return self._linear_decay(age, half_life)
        elif decay_function == DecayFunction.LOGARITHMIC:
            return self._logarithmic_decay(age, half_life)
        elif decay_function == DecayFunction.STEP:
            return self._step_decay(age, half_life)
        else:
            # Default to exponential
            return self._exponential_decay(age, half_life)
    
    def _exponential_decay(self, age: timedelta, half_life: timedelta) -> float:
        """Exponential decay: score = e^(-λt) where λ = ln(2)/half_life."""
        
        lambda_val = math.log(2) / half_life.total_seconds()
        age_seconds = age.total_seconds()
        
        decay_factor = math.exp(-lambda_val * age_seconds)
        return max(self.min_decay_factor, decay_factor)
    
    def _linear_decay(self, age: timedelta, half_life: timedelta) -> float:
        """Linear decay: score decreases at constant rate."""
        
        # Linear decay over 2x half_life period  
        max_decay_age = half_life * 2
        if age >= max_decay_age:
            return self.min_decay_factor
        
        decay_factor = 1.0 - (age.total_seconds() / max_decay_age.total_seconds())
        return max(self.min_decay_factor, decay_factor)
    
    def _logarithmic_decay(self, age: timedelta, half_life: timedelta) -> float:
        """Logarithmic decay: score decreases at decelerating rate."""
        
        age_hours = age.total_seconds() / 3600
        half_life_hours = half_life.total_seconds() / 3600
        
        if age_hours <= 0:
            return 1.0
        
        # Logarithmic decay with base adjustment
        decay_factor = 1.0 - (math.log(1 + age_hours) / math.log(1 + half_life_hours * 10))
        return max(self.min_decay_factor, decay_factor)
    
    def _step_decay(self, age: timedelta, half_life: timedelta) -> float:
        """Step decay: score drops at specific thresholds."""
        
        # Define step thresholds
        steps = [
            (timedelta(hours=1), 1.0),     # 100% for first hour
            (timedelta(hours=24), 0.9),    # 90% for first day
            (timedelta(days=7), 0.7),      # 70% for first week
            (timedelta(days=30), 0.5),     # 50% for first month
            (timedelta(days=90), 0.3),     # 30% for first quarter
            (timedelta(days=365), 0.1),    # 10% for first year
        ]
        
        for threshold, factor in steps:
            if age <= threshold:
                return factor
        
        return self.min_decay_factor


class TrendAnalyzer:
    """Analyzes temporal trends and patterns in indicator activity."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize trend analyzer."""
        self.config = config or {}
        
        # Analysis parameters
        self.min_observations = 3           # Minimum observations for trend analysis
        self.trend_window = timedelta(days=30)  # Default analysis window
        self.burst_threshold = 3.0          # Threshold for burst detection (std devs)
        self.frequency_bins = 24            # Hours for daily pattern analysis
        
        logger.debug("Trend analyzer initialized")
    
    def analyze_trends(self, 
                      indicator_id: str,
                      observations: List[TemporalObservation],
                      analysis_window: Optional[timedelta] = None) -> TemporalTrendAnalysis:
        """Analyze temporal trends in observations."""
        
        analysis = TemporalTrendAnalysis(
            indicator_id=indicator_id,
            analysis_period=analysis_window or self.trend_window
        )
        
        if len(observations) < self.min_observations:
            logger.debug(f"Insufficient observations ({len(observations)}) for trend analysis")
            return analysis
        
        # Filter observations to analysis window
        cutoff_time = datetime.utcnow() - analysis.analysis_period
        recent_observations = [obs for obs in observations if obs.timestamp >= cutoff_time]
        
        if len(recent_observations) < self.min_observations:
            return analysis
        
        # Sort observations by timestamp
        recent_observations.sort(key=lambda x: x.timestamp)
        
        # Analyze patterns
        analysis.detected_pattern = self._detect_pattern(recent_observations)
        analysis.pattern_confidence = self._calculate_pattern_confidence(recent_observations, analysis.detected_pattern)
        analysis.pattern_strength = self._calculate_pattern_strength(recent_observations)
        
        # Analyze trends
        analysis.activity_trend = self._calculate_activity_trend(recent_observations)
        analysis.velocity = self._calculate_velocity(recent_observations)
        analysis.acceleration = self._calculate_acceleration(recent_observations)
        
        # Analyze frequency
        analysis.observation_frequency = self._calculate_frequency(recent_observations, analysis.analysis_period)
        analysis.peak_activity_times = self._find_peak_times(recent_observations)
        
        # Analyze volatility
        analysis.activity_variance = self._calculate_variance(recent_observations)
        analysis.burst_events = self._count_burst_events(recent_observations)
        analysis.quiet_periods = self._count_quiet_periods(recent_observations)
        
        # Analyze seasonality
        analysis.weekly_pattern = self._analyze_weekly_pattern(recent_observations)
        analysis.daily_pattern = self._analyze_daily_pattern(recent_observations)
        
        # Make predictions
        analysis.predicted_next_activity = self._predict_next_activity(recent_observations, analysis.detected_pattern)
        analysis.activity_forecast = self._forecast_activity(recent_observations, analysis)
        
        return analysis
    
    def _detect_pattern(self, observations: List[TemporalObservation]) -> TemporalPattern:
        """Detect dominant temporal pattern in observations."""
        
        timestamps = [obs.timestamp for obs in observations]
        
        if len(timestamps) < 3:
            return TemporalPattern.SPORADIC
        
        # Calculate time intervals between observations
        intervals = []
        for i in range(1, len(timestamps)):
            interval = (timestamps[i] - timestamps[i-1]).total_seconds() / 3600  # Hours
            intervals.append(interval)
        
        if not intervals:
            return TemporalPattern.SPORADIC
        
        # Analyze interval patterns
        mean_interval = statistics.mean(intervals)
        std_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0
        cv_interval = std_interval / mean_interval if mean_interval > 0 else 0
        
        # Recent activity analysis
        now = datetime.utcnow()
        recent_count = sum(1 for obs in observations if (now - obs.timestamp) <= timedelta(hours=24))
        total_span = (timestamps[-1] - timestamps[0]).total_seconds() / 3600  # Hours
        
        # Pattern detection logic
        if recent_count >= 5 and total_span <= 48:  # Many observations in short time
            return TemporalPattern.BURST
        elif cv_interval <= 0.3 and mean_interval <= 24:  # Regular, frequent intervals
            return TemporalPattern.PERIODIC  
        elif len(observations) >= 10 and cv_interval <= 0.5:  # Consistent activity
            return TemporalPattern.SUSTAINED
        elif self._is_emerging_pattern(timestamps):
            return TemporalPattern.EMERGING
        elif self._is_declining_pattern(timestamps):
            return TemporalPattern.DECLINING
        elif total_span >= 168 and len(observations) <= 3:  # Few observations over long time
            return TemporalPattern.DORMANT
        else:
            return TemporalPattern.SPORADIC
    
    def _is_emerging_pattern(self, timestamps: List[datetime]) -> bool:
        """Check if pattern shows emerging activity."""
        
        if len(timestamps) < 4:
            return False
        
        # Check if activity is increasing over time
        now = datetime.utcnow()
        
        # Recent half vs older half
        mid_point = len(timestamps) // 2
        recent_half = timestamps[mid_point:]
        older_half = timestamps[:mid_point]
        
        recent_span = (recent_half[-1] - recent_half[0]).total_seconds() / 3600
        older_span = (older_half[-1] - older_half[0]).total_seconds() / 3600
        
        if recent_span <= 0 or older_span <= 0:
            return False
        
        recent_frequency = len(recent_half) / recent_span
        older_frequency = len(older_half) / older_span
        
        return recent_frequency > older_frequency * 1.5  # 50% increase in frequency
    
    def _is_declining_pattern(self, timestamps: List[datetime]) -> bool:
        """Check if pattern shows declining activity."""
        
        if len(timestamps) < 4:
            return False
        
        # Check if activity is decreasing over time
        now = datetime.utcnow()
        
        # Recent quarter vs older activity
        quarter_point = len(timestamps) * 3 // 4
        recent_quarter = timestamps[quarter_point:]
        older_portion = timestamps[:quarter_point]
        
        if len(recent_quarter) < 2 or len(older_portion) < 2:
            return False
        
        recent_span = (recent_quarter[-1] - recent_quarter[0]).total_seconds() / 3600
        older_span = (older_portion[-1] - older_portion[0]).total_seconds() / 3600
        
        if recent_span <= 0 or older_span <= 0:
            return False
        
        recent_frequency = len(recent_quarter) / recent_span
        older_frequency = len(older_portion) / older_span
        
        return recent_frequency < older_frequency * 0.5  # 50% decrease in frequency
    
    def _calculate_pattern_confidence(self, 
                                    observations: List[TemporalObservation],
                                    pattern: TemporalPattern) -> float:
        """Calculate confidence in detected pattern."""
        
        if len(observations) < 3:
            return 0.0
        
        # Base confidence on observation count
        count_factor = min(len(observations) / 10.0, 1.0)  # Max at 10 observations
        
        # Pattern-specific confidence adjustments
        pattern_factors = {
            TemporalPattern.BURST: 0.8,
            TemporalPattern.PERIODIC: 0.9,
            TemporalPattern.SUSTAINED: 0.7,
            TemporalPattern.EMERGING: 0.6,
            TemporalPattern.DECLINING: 0.6,
            TemporalPattern.DORMANT: 0.5,
            TemporalPattern.SPORADIC: 0.3
        }
        
        pattern_factor = pattern_factors.get(pattern, 0.5)
        
        return count_factor * pattern_factor
    
    def _calculate_pattern_strength(self, observations: List[TemporalObservation]) -> float:
        """Calculate strength/intensity of the temporal pattern."""
        
        if len(observations) < 2:
            return 0.0
        
        # Calculate based on observation concentration and regularity
        timestamps = [obs.timestamp for obs in observations]
        total_span = (timestamps[-1] - timestamps[0]).total_seconds() / 3600  # Hours
        
        if total_span <= 0:
            return 1.0  # All at same time = very strong
        
        # Observation density
        density = len(observations) / total_span
        
        # Normalize density (observations per hour)
        max_expected_density = 1.0  # 1 per hour is high
        normalized_density = min(density / max_expected_density, 1.0)
        
        return normalized_density
    
    def _calculate_activity_trend(self, observations: List[TemporalObservation]) -> float:
        """Calculate overall activity trend (-1 to +1)."""
        
        if len(observations) < 3:
            return 0.0
        
        timestamps = [obs.timestamp for obs in observations]
        
        # Split into early and late periods
        mid_point = len(timestamps) // 2
        early_period = timestamps[:mid_point]
        late_period = timestamps[mid_point:]
        
        if not early_period or not late_period:
            return 0.0
        
        # Calculate activity rates
        early_span = (early_period[-1] - early_period[0]).total_seconds() / 3600
        late_span = (late_period[-1] - late_period[0]).total_seconds() / 3600
        
        if early_span <= 0 or late_span <= 0:
            return 0.0
        
        early_rate = len(early_period) / early_span
        late_rate = len(late_period) / late_span
        
        # Calculate trend
        if early_rate == 0:
            return 1.0 if late_rate > 0 else 0.0
        
        trend_ratio = (late_rate - early_rate) / early_rate
        
        # Normalize to -1 to +1 range
        return max(-1.0, min(1.0, trend_ratio))
    
    def _calculate_velocity(self, observations: List[TemporalObservation]) -> float:
        """Calculate velocity of activity change."""
        
        if len(observations) < 3:
            return 0.0
        
        timestamps = [obs.timestamp for obs in observations]
        
        # Calculate activity rate over sliding windows
        window_size = max(2, len(timestamps) // 3)
        rates = []
        
        for i in range(len(timestamps) - window_size + 1):
            window = timestamps[i:i + window_size]
            span = (window[-1] - window[0]).total_seconds() / 3600
            if span > 0:
                rate = len(window) / span
                rates.append(rate)
        
        if len(rates) < 2:
            return 0.0
        
        # Calculate rate of change in rates (velocity)
        rate_changes = []
        for i in range(1, len(rates)):
            change = rates[i] - rates[i-1]
            rate_changes.append(change)
        
        return statistics.mean(rate_changes) if rate_changes else 0.0
    
    def _calculate_acceleration(self, observations: List[TemporalObservation]) -> float:
        """Calculate acceleration of activity change."""
        
        if len(observations) < 4:
            return 0.0
        
        # Calculate velocity changes over time
        velocities = []
        
        # Use sliding windows to calculate velocities
        window_size = max(3, len(observations) // 2)
        
        for i in range(len(observations) - window_size + 1):
            window = observations[i:i + window_size]
            velocity = self._calculate_velocity(window)
            velocities.append(velocity)
        
        if len(velocities) < 2:
            return 0.0
        
        # Calculate change in velocities (acceleration)
        accelerations = []
        for i in range(1, len(velocities)):
            accel = velocities[i] - velocities[i-1]
            accelerations.append(accel)
        
        return statistics.mean(accelerations) if accelerations else 0.0
    
    def _calculate_frequency(self, 
                           observations: List[TemporalObservation],
                           period: timedelta) -> float:
        """Calculate observation frequency (observations per day)."""
        
        if not observations or period.total_seconds() <= 0:
            return 0.0
        
        period_days = period.total_seconds() / (24 * 3600)
        return len(observations) / period_days
    
    def _find_peak_times(self, observations: List[TemporalObservation]) -> List[int]:
        """Find peak activity hours (0-23)."""
        
        if not observations:
            return []
        
        # Count observations by hour
        hour_counts = defaultdict(int)
        for obs in observations:
            hour = obs.timestamp.hour
            hour_counts[hour] += 1
        
        if not hour_counts:
            return []
        
        # Find hours with above-average activity
        mean_count = statistics.mean(hour_counts.values())
        std_count = statistics.stdev(hour_counts.values()) if len(hour_counts) > 1 else 0
        
        threshold = mean_count + std_count
        peak_hours = [hour for hour, count in hour_counts.items() if count >= threshold]
        
        return sorted(peak_hours)
    
    def _calculate_variance(self, observations: List[TemporalObservation]) -> float:
        """Calculate variance in temporal activity."""
        
        if len(observations) < 2:
            return 0.0
        
        timestamps = [obs.timestamp for obs in observations]
        
        # Calculate intervals between observations
        intervals = []
        for i in range(1, len(timestamps)):
            interval_hours = (timestamps[i] - timestamps[i-1]).total_seconds() / 3600
            intervals.append(interval_hours)
        
        return statistics.variance(intervals) if intervals else 0.0
    
    def _count_burst_events(self, observations: List[TemporalObservation]) -> int:
        """Count burst events in activity."""
        
        if len(observations) < 3:
            return 0
        
        timestamps = [obs.timestamp for obs in observations]
        
        # Calculate intervals
        intervals = []
        for i in range(1, len(timestamps)):
            interval_hours = (timestamps[i] - timestamps[i-1]).total_seconds() / 3600
            intervals.append(interval_hours)
        
        if not intervals:
            return 0
        
        mean_interval = statistics.mean(intervals)
        std_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0
        
        if std_interval == 0:
            return 0
        
        # Count intervals significantly shorter than average (burst indicators)
        burst_threshold = mean_interval - (self.burst_threshold * std_interval)
        bursts = sum(1 for interval in intervals if interval < burst_threshold)
        
        return bursts
    
    def _count_quiet_periods(self, observations: List[TemporalObservation]) -> int:
        """Count quiet periods in activity."""
        
        if len(observations) < 2:
            return 0
        
        timestamps = [obs.timestamp for obs in observations]
        
        # Calculate intervals
        intervals = []
        for i in range(1, len(timestamps)):
            interval_hours = (timestamps[i] - timestamps[i-1]).total_seconds() / 3600
            intervals.append(interval_hours)
        
        if not intervals:
            return 0
        
        mean_interval = statistics.mean(intervals)
        std_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0
        
        if std_interval == 0:
            return 0
        
        # Count intervals significantly longer than average (quiet periods)
        quiet_threshold = mean_interval + (2 * std_interval)
        quiet_periods = sum(1 for interval in intervals if interval > quiet_threshold)
        
        return quiet_periods
    
    def _analyze_weekly_pattern(self, observations: List[TemporalObservation]) -> List[float]:
        """Analyze weekly activity patterns (7 values for days of week)."""
        
        if not observations:
            return [0.0] * 7
        
        # Count observations by day of week (0=Monday, 6=Sunday)
        day_counts = defaultdict(int)
        for obs in observations:
            day_of_week = obs.timestamp.weekday()
            day_counts[day_of_week] += 1
        
        # Normalize to proportions
        total_observations = len(observations)
        weekly_pattern = []
        
        for day in range(7):
            count = day_counts.get(day, 0)
            proportion = count / total_observations if total_observations > 0 else 0.0
            weekly_pattern.append(proportion)
        
        return weekly_pattern
    
    def _analyze_daily_pattern(self, observations: List[TemporalObservation]) -> List[float]:
        """Analyze daily activity patterns (24 values for hours of day)."""
        
        if not observations:
            return [0.0] * 24
        
        # Count observations by hour of day
        hour_counts = defaultdict(int)
        for obs in observations:
            hour = obs.timestamp.hour
            hour_counts[hour] += 1
        
        # Normalize to proportions
        total_observations = len(observations)
        daily_pattern = []
        
        for hour in range(24):
            count = hour_counts.get(hour, 0)
            proportion = count / total_observations if total_observations > 0 else 0.0
            daily_pattern.append(proportion)
        
        return daily_pattern
    
    def _predict_next_activity(self, 
                             observations: List[TemporalObservation],
                             pattern: TemporalPattern) -> Optional[datetime]:
        """Predict next activity based on observed pattern."""
        
        if len(observations) < 2:
            return None
        
        timestamps = [obs.timestamp for obs in observations]
        last_observation = timestamps[-1]
        
        # Pattern-based prediction
        if pattern == TemporalPattern.PERIODIC:
            # Use average interval for periodic patterns
            intervals = []
            for i in range(1, len(timestamps)):
                interval = (timestamps[i] - timestamps[i-1]).total_seconds()
                intervals.append(interval)
            
            if intervals:
                avg_interval = statistics.mean(intervals)
                return last_observation + timedelta(seconds=avg_interval)
        
        elif pattern == TemporalPattern.BURST:
            # Burst patterns likely to continue soon
            return last_observation + timedelta(minutes=30)
        
        elif pattern == TemporalPattern.SUSTAINED:
            # Use recent interval trend
            if len(timestamps) >= 3:
                recent_interval = (timestamps[-1] - timestamps[-2]).total_seconds()
                return last_observation + timedelta(seconds=recent_interval)
        
        return None
    
    def _forecast_activity(self, 
                         observations: List[TemporalObservation],
                         analysis: TemporalTrendAnalysis) -> Dict[str, float]:
        """Generate activity forecasts for different time periods."""
        
        forecast = {}
        
        if not observations:
            return forecast
        
        base_frequency = analysis.observation_frequency
        trend_multiplier = 1.0 + (analysis.activity_trend * 0.1)  # 10% impact per trend unit
        
        # Forecast for different periods
        periods = {
            'next_hour': 1/24,
            'next_6_hours': 6/24,
            'next_day': 1.0,
            'next_week': 7.0,
            'next_month': 30.0
        }
        
        for period_name, period_days in periods.items():
            expected_activity = base_frequency * period_days * trend_multiplier
            
            # Apply pattern adjustments
            if analysis.detected_pattern == TemporalPattern.BURST:
                expected_activity *= 1.5  # Higher near-term activity
            elif analysis.detected_pattern == TemporalPattern.DECLINING:
                expected_activity *= 0.7  # Lower future activity
            elif analysis.detected_pattern == TemporalPattern.EMERGING:
                expected_activity *= 1.2  # Growing activity
            
            forecast[period_name] = max(0.0, expected_activity)
        
        return forecast


class AdvancedTemporalScoring:
    """Advanced temporal scoring engine with comprehensive time-based analysis."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize advanced temporal scoring engine."""
        self.config = config or {}
        
        # Initialize components
        self.decay_engine = DecayEngine(self.config.get('decay_config', {}))
        self.trend_analyzer = TrendAnalyzer(self.config.get('trend_config', {}))
        
        # Temporal weight configuration
        self.temporal_weights = {
            TemporalWeight.RECENCY: 0.30,      # 30% weight for recency
            TemporalWeight.FREQUENCY: 0.20,    # 20% weight for frequency  
            TemporalWeight.PERSISTENCE: 0.15,  # 15% weight for persistence
            TemporalWeight.VOLATILITY: 0.15,   # 15% weight for volatility
            TemporalWeight.ACCELERATION: 0.10, # 10% weight for acceleration
            TemporalWeight.SEASONALITY: 0.10   # 10% weight for seasonality
        }
        
        # Scoring parameters
        self.freshness_threshold = timedelta(hours=24)  # Fresh if within 24 hours
        self.staleness_threshold = timedelta(days=90)   # Stale if older than 90 days
        self.high_frequency_threshold = 5.0             # High frequency = 5+ per day
        
        logger.info("Advanced temporal scoring engine initialized")
    
    def calculate_temporal_score(self, 
                               indicator: NormalizedIndicator,
                               observations: Optional[List[TemporalObservation]] = None) -> TemporalScore:
        """Calculate comprehensive temporal score for an indicator."""
        
        score = TemporalScore(indicator_id=indicator.id)
        
        # Extract or create observations from indicator
        if observations is None:
            observations = self._extract_observations_from_indicator(indicator)
        
        if not observations:
            logger.debug(f"No temporal observations for indicator {indicator.id}")
            return score
        
        # Perform trend analysis
        trend_analysis = self.trend_analyzer.analyze_trends(indicator.id, observations)
        score.trend_analysis = trend_analysis
        
        # Calculate component scores
        score.recency_score = self._calculate_recency_score(observations)
        score.frequency_score = self._calculate_frequency_score(observations, trend_analysis)
        score.persistence_score = self._calculate_persistence_score(observations, trend_analysis)
        score.volatility_score = self._calculate_volatility_score(observations, trend_analysis)
        score.trend_score = self._calculate_trend_score(trend_analysis)
        score.pattern_score = self._calculate_pattern_score(trend_analysis)
        
        # Calculate base temporal score (weighted average)
        component_scores = [
            (score.recency_score, self.temporal_weights[TemporalWeight.RECENCY]),
            (score.frequency_score, self.temporal_weights[TemporalWeight.FREQUENCY]),
            (score.persistence_score, self.temporal_weights[TemporalWeight.PERSISTENCE]),
            (score.volatility_score, self.temporal_weights[TemporalWeight.VOLATILITY]),
            (score.trend_score, self.temporal_weights[TemporalWeight.ACCELERATION]),
            (score.pattern_score, self.temporal_weights[TemporalWeight.SEASONALITY])
        ]
        
        weighted_sum = sum(component * weight for component, weight in component_scores)
        total_weight = sum(weight for _, weight in component_scores)
        
        score.base_temporal_score = weighted_sum / total_weight if total_weight > 0 else 0.0
        
        # Apply decay factor
        most_recent = max(obs.timestamp for obs in observations)
        age = datetime.utcnow() - most_recent
        score.decay_factor = self.decay_engine.calculate_decay(age)
        
        # Calculate freshness bonus and staleness penalty
        if age <= self.freshness_threshold:
            score.freshness_bonus = 0.1 * (1.0 - age.total_seconds() / self.freshness_threshold.total_seconds())
        
        if age >= self.staleness_threshold:
            excess_age = age - self.staleness_threshold
            max_penalty_age = timedelta(days=365)
            penalty_ratio = min(excess_age.total_seconds() / max_penalty_age.total_seconds(), 1.0)
            score.staleness_penalty = -0.2 * penalty_ratio
        
        # Calculate final adjusted score
        score.adjusted_temporal_score = (
            score.base_temporal_score * score.decay_factor + 
            score.freshness_bonus + 
            score.staleness_penalty
        )
        
        # Ensure score is in valid range
        score.adjusted_temporal_score = max(0.0, min(1.0, score.adjusted_temporal_score))
        
        # Calculate temporal multiplier (for use in overall threat scoring)
        score.temporal_multiplier = 0.7 + (score.adjusted_temporal_score * 0.6)  # Range: 0.7 to 1.3
        
        # Generate temporal factors
        score.temporal_factors = self._generate_temporal_factors(score, trend_analysis, age)
        
        return score
    
    def _extract_observations_from_indicator(self, indicator: NormalizedIndicator) -> List[TemporalObservation]:
        """Extract temporal observations from indicator properties."""
        
        observations = []
        
        # Extract from basic properties
        if indicator.first_seen:
            try:
                first_seen_dt = datetime.fromisoformat(indicator.first_seen.replace('Z', '+00:00'))
                observations.append(TemporalObservation(
                    timestamp=first_seen_dt,
                    source='first_seen',
                    confidence=0.8
                ))
            except:
                pass
        
        if indicator.last_seen:
            try:
                last_seen_dt = datetime.fromisoformat(indicator.last_seen.replace('Z', '+00:00'))
                observations.append(TemporalObservation(
                    timestamp=last_seen_dt,
                    source='last_seen', 
                    confidence=0.9
                ))
            except:
                pass
        
        # Extract from enrichment data
        enrichment_history = indicator.properties.get('enrichment_history', [])
        for entry in enrichment_history:
            try:
                timestamp_str = entry.get('timestamp')
                if timestamp_str:
                    timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                    source = entry.get('source', 'enrichment')
                    confidence = entry.get('confidence', 0.7)
                    
                    observations.append(TemporalObservation(
                        timestamp=timestamp,
                        source=source,
                        confidence=confidence
                    ))
            except:
                continue
        
        # Extract from sources
        sources = indicator.properties.get('sources', [])
        for source_info in sources:
            try:
                if isinstance(source_info, dict):
                    timestamp_str = source_info.get('timestamp') or source_info.get('first_seen')
                    if timestamp_str:
                        timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                        source_name = source_info.get('name', 'unknown')
                        confidence = source_info.get('confidence', 0.8)
                        
                        observations.append(TemporalObservation(
                            timestamp=timestamp,
                            source=source_name,
                            confidence=confidence
                        ))
            except:
                continue
        
        # Remove duplicates and sort by timestamp
        unique_observations = []
        seen_timestamps = set()
        
        for obs in observations:
            timestamp_key = (obs.timestamp, obs.source)
            if timestamp_key not in seen_timestamps:
                unique_observations.append(obs)
                seen_timestamps.add(timestamp_key)
        
        unique_observations.sort(key=lambda x: x.timestamp)
        return unique_observations
    
    def _calculate_recency_score(self, observations: List[TemporalObservation]) -> float:
        """Calculate recency score based on most recent observation."""
        
        if not observations:
            return 0.0
        
        most_recent = max(obs.timestamp for obs in observations)
        age = datetime.utcnow() - most_recent
        
        # Exponential decay with 7-day half-life for recency
        half_life = timedelta(days=7)
        decay_factor = self.decay_engine.calculate_decay(age, DecayFunction.EXPONENTIAL, half_life)
        
        return decay_factor
    
    def _calculate_frequency_score(self, 
                                 observations: List[TemporalObservation],
                                 trend_analysis: TemporalTrendAnalysis) -> float:
        """Calculate frequency score based on observation frequency."""
        
        frequency = trend_analysis.observation_frequency
        
        # Normalize frequency (logarithmic scale)
        if frequency <= 0:
            return 0.0
        elif frequency >= self.high_frequency_threshold:
            return 1.0
        else:
            # Logarithmic scaling
            normalized_freq = math.log(frequency + 1) / math.log(self.high_frequency_threshold + 1)
            return min(normalized_freq, 1.0)
    
    def _calculate_persistence_score(self, 
                                   observations: List[TemporalObservation],
                                   trend_analysis: TemporalTrendAnalysis) -> float:
        """Calculate persistence score based on activity duration."""
        
        if len(observations) < 2:
            return 0.0
        
        timestamps = [obs.timestamp for obs in observations]
        activity_span = (timestamps[-1] - timestamps[0]).total_seconds() / (24 * 3600)  # Days
        
        # Score based on activity span (longer = higher persistence)
        if activity_span <= 1:
            return 0.2  # Single day
        elif activity_span <= 7:
            return 0.4  # One week
        elif activity_span <= 30:
            return 0.6  # One month
        elif activity_span <= 90:
            return 0.8  # Three months
        else:
            return 1.0  # Long-term persistence
    
    def _calculate_volatility_score(self, 
                                  observations: List[TemporalObservation],
                                  trend_analysis: TemporalTrendAnalysis) -> float:
        """Calculate volatility score (higher volatility = higher threat)."""
        
        if trend_analysis.activity_variance <= 0:
            return 0.5  # Neutral score for no variance
        
        # Normalize variance (log scale)
        normalized_variance = math.log(trend_analysis.activity_variance + 1) / 10.0
        volatility_score = min(normalized_variance, 1.0)
        
        # Boost score for burst events
        if trend_analysis.burst_events > 0:
            burst_bonus = min(trend_analysis.burst_events * 0.1, 0.3)
            volatility_score += burst_bonus
        
        return min(volatility_score, 1.0)
    
    def _calculate_trend_score(self, trend_analysis: TemporalTrendAnalysis) -> float:
        """Calculate trend score based on activity trends."""
        
        # Positive trend (growing activity) = higher score
        trend_score = 0.5 + (trend_analysis.activity_trend * 0.3)  # Range: 0.2 to 0.8
        
        # Boost for acceleration
        if trend_analysis.acceleration > 0:
            accel_bonus = min(trend_analysis.acceleration * 0.1, 0.2)
            trend_score += accel_bonus
        
        # Boost for emerging patterns
        if trend_analysis.detected_pattern == TemporalPattern.EMERGING:
            trend_score += 0.1
        elif trend_analysis.detected_pattern == TemporalPattern.BURST:
            trend_score += 0.15
        
        return max(0.0, min(1.0, trend_score))
    
    def _calculate_pattern_score(self, trend_analysis: TemporalTrendAnalysis) -> float:
        """Calculate pattern score based on detected temporal patterns."""
        
        # Base score from pattern confidence and strength
        base_score = (trend_analysis.pattern_confidence + trend_analysis.pattern_strength) / 2
        
        # Pattern-specific adjustments
        pattern_multipliers = {
            TemporalPattern.BURST: 1.3,        # High threat
            TemporalPattern.EMERGING: 1.2,     # Growing threat
            TemporalPattern.SUSTAINED: 1.1,    # Persistent threat
            TemporalPattern.PERIODIC: 1.0,     # Regular threat
            TemporalPattern.SPORADIC: 0.8,     # Irregular threat
            TemporalPattern.DECLINING: 0.7,    # Decreasing threat
            TemporalPattern.DORMANT: 0.5       # Low current threat
        }
        
        multiplier = pattern_multipliers.get(trend_analysis.detected_pattern, 1.0)
        pattern_score = base_score * multiplier
        
        return max(0.0, min(1.0, pattern_score))
    
    def _generate_temporal_factors(self, 
                                 score: TemporalScore,
                                 trend_analysis: TemporalTrendAnalysis,
                                 age: timedelta) -> List[str]:
        """Generate human-readable temporal factors."""
        
        factors = []
        
        # Age-based factors
        if age <= timedelta(hours=1):
            factors.append("very_recent_activity")
        elif age <= timedelta(hours=24):
            factors.append("recent_activity")
        elif age >= timedelta(days=90):
            factors.append("stale_indicator")
        
        # Pattern factors
        if trend_analysis.detected_pattern != TemporalPattern.SPORADIC:
            factors.append(f"pattern_{trend_analysis.detected_pattern.value}")
        
        # Frequency factors
        if trend_analysis.observation_frequency >= self.high_frequency_threshold:
            factors.append("high_frequency_activity")
        elif trend_analysis.observation_frequency >= 1.0:
            factors.append("moderate_frequency_activity")
        
        # Trend factors
        if trend_analysis.activity_trend > 0.5:
            factors.append("increasing_activity_trend")
        elif trend_analysis.activity_trend < -0.5:
            factors.append("decreasing_activity_trend")
        
        # Volatility factors
        if trend_analysis.burst_events > 0:
            factors.append(f"burst_events_{trend_analysis.burst_events}")
        
        if trend_analysis.activity_variance > 100:  # High variance
            factors.append("high_volatility")
        
        # Score-based factors
        if score.adjusted_temporal_score >= 0.8:
            factors.append("high_temporal_score")
        elif score.adjusted_temporal_score >= 0.6:
            factors.append("moderate_temporal_score")
        elif score.adjusted_temporal_score < 0.3:
            factors.append("low_temporal_score")
        
        return factors
    
    def batch_calculate_temporal_scores(self, 
                                      indicators: List[NormalizedIndicator]) -> List[TemporalScore]:
        """Batch calculate temporal scores for multiple indicators."""
        
        logger.info(f"Batch temporal scoring for {len(indicators)} indicators")
        
        scores = []
        
        for i, indicator in enumerate(indicators):
            try:
                temporal_score = self.calculate_temporal_score(indicator)
                scores.append(temporal_score)
                
                # Log progress for large batches
                if (i + 1) % 50 == 0:
                    logger.debug(f"Processed {i + 1}/{len(indicators)} temporal scores")
                    
            except Exception as e:
                logger.error(f"Temporal scoring failed for {indicator.id}: {e}")
                # Create minimal error score
                error_score = TemporalScore(indicator_id=indicator.id)
                error_score.temporal_factors.append("scoring_error")
                scores.append(error_score)
        
        logger.info(f"Temporal scoring completed for {len(scores)} indicators")
        return scores
    
    def get_temporal_statistics(self) -> Dict[str, Any]:
        """Get temporal scoring system statistics."""
        
        return {
            'components': {
                'decay_engine': bool(self.decay_engine),
                'trend_analyzer': bool(self.trend_analyzer)
            },
            'configuration': {
                'temporal_weights': {weight.value: value for weight, value in self.temporal_weights.items()},
                'freshness_threshold_hours': self.freshness_threshold.total_seconds() / 3600,
                'staleness_threshold_days': self.staleness_threshold.days,
                'high_frequency_threshold': self.high_frequency_threshold
            }
        }