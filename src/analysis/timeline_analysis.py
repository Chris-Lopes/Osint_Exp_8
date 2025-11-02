"""
Timeline analysis engine for threat intelligence.

This module creates temporal analysis capabilities to identify attack sequences,
campaign timelines, and chronological patterns in threat indicators. It builds
comprehensive timelines showing how attacks unfold over time.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
import statistics

try:
    from ..normalizers.schema import NormalizedIndicator, IndicatorType
    from .correlation import CorrelationResult, CorrelationType
    from .clustering import IndicatorCluster, ClusterType
    from .risk_scoring import RiskAssessment, ThreatCategory
except ImportError:
    from normalizers.schema import NormalizedIndicator, IndicatorType
    from analysis.correlation import CorrelationResult, CorrelationType
    from analysis.clustering import IndicatorCluster, ClusterType
    from analysis.risk_scoring import RiskAssessment, ThreatCategory

logger = logging.getLogger(__name__)


class TimelineEventType(Enum):
    """Types of timeline events."""
    INITIAL_COMPROMISE = "initial_compromise"
    RECONNAISSANCE = "reconnaissance"
    DELIVERY = "delivery"
    EXPLOITATION = "exploitation"
    INSTALLATION = "installation"
    COMMAND_CONTROL = "command_control"
    ACTION_OBJECTIVES = "action_objectives"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"
    UNKNOWN = "unknown"


class AttackPhase(Enum):
    """Attack lifecycle phases."""
    PRE_ATTACK = "pre_attack"
    INITIAL_ACCESS = "initial_access"
    POST_COMPROMISE = "post_compromise"
    OBJECTIVE_COMPLETION = "objective_completion"


@dataclass
class TimelineEvent:
    """Individual event in a timeline."""
    timestamp: datetime
    event_type: TimelineEventType
    attack_phase: AttackPhase
    
    # Associated data
    indicator: NormalizedIndicator
    risk_assessment: Optional[RiskAssessment]
    
    # Context and relationships
    correlations: List[CorrelationResult]
    cluster_memberships: List[str]
    
    # Event metadata
    confidence: float  # 0.0 to 1.0
    event_description: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    
    # Sequence information
    sequence_number: Optional[int] = None
    is_pivotal: bool = False  # Key events in attack progression
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            'timestamp': self.timestamp.isoformat(),
            'event_type': self.event_type.value,
            'attack_phase': self.attack_phase.value,
            'indicator_id': self.indicator.id,
            'indicator_type': self.indicator.indicator_type.value,
            'indicator_value': self.indicator.value,
            'risk_score': self.risk_assessment.risk_score if self.risk_assessment else 0.0,
            'confidence': self.confidence,
            'event_description': self.event_description,
            'correlations_count': len(self.correlations),
            'cluster_memberships': self.cluster_memberships,
            'sequence_number': self.sequence_number,
            'is_pivotal': self.is_pivotal,
            'evidence': self.evidence
        }


@dataclass
class AttackTimeline:
    """Complete attack timeline analysis."""
    timeline_id: str
    campaign_name: Optional[str]
    
    # Timeline events
    events: List[TimelineEvent]
    start_time: datetime
    end_time: datetime
    duration: timedelta
    
    # Attack characteristics
    attack_phases: Set[AttackPhase]
    threat_categories: Set[ThreatCategory]
    ttp_patterns: List[str]
    
    # Analysis metadata
    confidence: float
    completeness_score: float  # How complete the timeline appears
    analysis_timestamp: datetime
    
    # Campaign information
    indicators_count: int
    unique_sources: Set[str]
    geographic_scope: List[str]
    
    # Timeline patterns
    peak_activity_period: Optional[Tuple[datetime, datetime]]
    activity_pattern: str  # burst, sustained, intermittent
    escalation_detected: bool
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            'timeline_id': self.timeline_id,
            'campaign_name': self.campaign_name,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat(),
            'duration_hours': self.duration.total_seconds() / 3600,
            'events': [event.to_dict() for event in self.events],
            'attack_phases': [phase.value for phase in self.attack_phases],
            'threat_categories': [cat.value for cat in self.threat_categories],
            'ttp_patterns': self.ttp_patterns,
            'confidence': self.confidence,
            'completeness_score': self.completeness_score,
            'analysis_timestamp': self.analysis_timestamp.isoformat(),
            'indicators_count': self.indicators_count,
            'unique_sources': list(self.unique_sources),
            'geographic_scope': self.geographic_scope,
            'peak_activity_period': [
                self.peak_activity_period[0].isoformat(),
                self.peak_activity_period[1].isoformat()
            ] if self.peak_activity_period else None,
            'activity_pattern': self.activity_pattern,
            'escalation_detected': self.escalation_detected
        }


class EventClassifier:
    """Classifies indicators into timeline events."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize event classifier."""
        self.config = config or {}
        
        # TTP to event type mapping
        self.ttp_patterns = {
            # Initial Access
            r'phishing|spear.?phishing|malicious.?attachment': TimelineEventType.INITIAL_COMPROMISE,
            r'exploit|cve-\d+|vulnerability': TimelineEventType.EXPLOITATION,
            r'drive.?by|watering.?hole': TimelineEventType.DELIVERY,
            
            # Discovery and Reconnaissance
            r'reconnaissance|recon|scan|probe': TimelineEventType.RECONNAISSANCE,
            r'discovery|enumeration|whoami|net.user': TimelineEventType.DISCOVERY,
            
            # Execution and Installation
            r'malware|trojan|backdoor|rat': TimelineEventType.INSTALLATION,
            r'dropper|loader|downloader': TimelineEventType.DELIVERY,
            
            # Persistence and Privilege
            r'persistence|registry|startup|service': TimelineEventType.PERSISTENCE,
            r'privilege|escalation|admin|root': TimelineEventType.PRIVILEGE_ESCALATION,
            
            # Command and Control
            r'c2|command.control|callback|beacon': TimelineEventType.COMMAND_CONTROL,
            r'tunnel|proxy|covert.channel': TimelineEventType.COMMAND_CONTROL,
            
            # Credential Access
            r'credential|password|hash|keylog': TimelineEventType.CREDENTIAL_ACCESS,
            r'mimikatz|lsass|sam': TimelineEventType.CREDENTIAL_ACCESS,
            
            # Defense Evasion
            r'evasion|obfuscat|encrypt|pack': TimelineEventType.DEFENSE_EVASION,
            r'disable|antivir|security': TimelineEventType.DEFENSE_EVASION,
            
            # Lateral Movement
            r'lateral|movement|psexec|wmi': TimelineEventType.LATERAL_MOVEMENT,
            r'remote|rdp|ssh|winrm': TimelineEventType.LATERAL_MOVEMENT,
            
            # Collection and Exfiltration
            r'collection|harvest|gather|screenshot': TimelineEventType.COLLECTION,
            r'exfiltrat|upload|steal|data': TimelineEventType.EXFILTRATION,
            
            # Impact
            r'ransom|encrypt|wipe|destroy': TimelineEventType.IMPACT,
            r'dos|ddos|flood': TimelineEventType.IMPACT
        }
        
        # Indicator type to event type mapping
        self.indicator_type_mapping = {
            IndicatorType.MD5: TimelineEventType.INSTALLATION,
            IndicatorType.SHA1: TimelineEventType.INSTALLATION,
            IndicatorType.SHA256: TimelineEventType.INSTALLATION,
            IndicatorType.DOMAIN: TimelineEventType.COMMAND_CONTROL,
            IndicatorType.IP: TimelineEventType.COMMAND_CONTROL,
            IndicatorType.IPV4: TimelineEventType.COMMAND_CONTROL,
            IndicatorType.IPV6: TimelineEventType.COMMAND_CONTROL,
            IndicatorType.URL: TimelineEventType.DELIVERY,
            IndicatorType.EMAIL: TimelineEventType.INITIAL_COMPROMISE
        }
        
        # Event type to attack phase mapping
        self.event_to_phase_mapping = {
            TimelineEventType.RECONNAISSANCE: AttackPhase.PRE_ATTACK,
            TimelineEventType.INITIAL_COMPROMISE: AttackPhase.INITIAL_ACCESS,
            TimelineEventType.DELIVERY: AttackPhase.INITIAL_ACCESS,
            TimelineEventType.EXPLOITATION: AttackPhase.INITIAL_ACCESS,
            TimelineEventType.INSTALLATION: AttackPhase.POST_COMPROMISE,
            TimelineEventType.COMMAND_CONTROL: AttackPhase.POST_COMPROMISE,
            TimelineEventType.PERSISTENCE: AttackPhase.POST_COMPROMISE,
            TimelineEventType.PRIVILEGE_ESCALATION: AttackPhase.POST_COMPROMISE,
            TimelineEventType.DEFENSE_EVASION: AttackPhase.POST_COMPROMISE,
            TimelineEventType.CREDENTIAL_ACCESS: AttackPhase.POST_COMPROMISE,
            TimelineEventType.DISCOVERY: AttackPhase.POST_COMPROMISE,
            TimelineEventType.LATERAL_MOVEMENT: AttackPhase.POST_COMPROMISE,
            TimelineEventType.COLLECTION: AttackPhase.OBJECTIVE_COMPLETION,
            TimelineEventType.EXFILTRATION: AttackPhase.OBJECTIVE_COMPLETION,
            TimelineEventType.ACTION_OBJECTIVES: AttackPhase.OBJECTIVE_COMPLETION,
            TimelineEventType.IMPACT: AttackPhase.OBJECTIVE_COMPLETION
        }
    
    def classify_event(self, indicator: NormalizedIndicator, 
                      risk_assessment: Optional[RiskAssessment],
                      correlations: List[CorrelationResult]) -> Tuple[TimelineEventType, AttackPhase, float]:
        """Classify indicator into timeline event."""
        
        # Check for explicit TTP patterns in tags or description
        tags = indicator.tags or []
        description = indicator.context.get('description', '').lower()
        all_text = ' '.join(tags + [description]).lower()
        
        event_type = TimelineEventType.UNKNOWN
        confidence = 0.3
        
        # Pattern matching in text
        import re
        for pattern, etype in self.ttp_patterns.items():
            if re.search(pattern, all_text, re.IGNORECASE):
                event_type = etype
                confidence = 0.7
                break
        
        # Fallback to indicator type mapping
        if event_type == TimelineEventType.UNKNOWN:
            event_type = self.indicator_type_mapping.get(
                indicator.indicator_type, 
                TimelineEventType.UNKNOWN
            )
            confidence = 0.5
        
        # Adjust confidence based on risk assessment
        if risk_assessment:
            # Handle both dict and object formats
            if isinstance(risk_assessment, dict):
                risk_confidence = risk_assessment.get('confidence', 0.0)
            else:
                risk_confidence = getattr(risk_assessment, 'confidence', 0.0)
                
            if risk_confidence > 0.7:
                confidence = min(confidence + 0.2, 0.9)
        
        # Determine attack phase
        attack_phase = self.event_to_phase_mapping.get(
            event_type, 
            AttackPhase.POST_COMPROMISE
        )
        
        return event_type, attack_phase, confidence


class TimelineBuilder:
    """Builds attack timelines from indicators and analysis results."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize timeline builder."""
        self.config = config or {}
        self.classifier = EventClassifier(self.config.get('classifier', {}))
        
        # Timeline construction parameters
        self.max_timeline_gap = timedelta(hours=self.config.get('max_timeline_gap_hours', 72))
        self.min_timeline_events = self.config.get('min_timeline_events', 2)
        self.pivotal_event_threshold = self.config.get('pivotal_event_threshold', 0.8)
        
        logger.info("Timeline builder initialized")
    
    def build_timelines(self, indicators: List[NormalizedIndicator],
                       risk_assessments: Dict[str, RiskAssessment],
                       correlations: Dict[str, List[CorrelationResult]],
                       clusters: List[IndicatorCluster]) -> List[AttackTimeline]:
        """Build attack timelines from analysis data."""
        
        logger.info(f"Building timelines from {len(indicators)} indicators")
        
        # Create timeline events
        events = self._create_timeline_events(indicators, risk_assessments, correlations)
        
        # Group events into timelines
        timeline_groups = self._group_events_into_timelines(events, clusters)
        
        # Build complete timelines
        timelines = []
        for group_id, event_list in timeline_groups.items():
            if len(event_list) >= self.min_timeline_events:
                timeline = self._build_attack_timeline(group_id, event_list, clusters)
                timelines.append(timeline)
        
        logger.info(f"Built {len(timelines)} attack timelines")
        return timelines
    
    def _create_timeline_events(self, indicators: List[NormalizedIndicator],
                               risk_assessments: Dict[str, RiskAssessment],
                               correlations: Dict[str, List[CorrelationResult]]) -> List[TimelineEvent]:
        """Create individual timeline events from indicators."""
        events = []
        
        for indicator in indicators:
            try:
                # Get indicator timestamp
                timestamp = self._parse_timestamp(indicator.created)
                if not timestamp:
                    continue
                
                # Get associated data
                risk_assessment = risk_assessments.get(indicator.id)
                indicator_correlations = correlations.get(indicator.id, [])
                
                # Classify event
                event_type, attack_phase, confidence = self.classifier.classify_event(
                    indicator, risk_assessment, indicator_correlations
                )
                
                # Create event description
                description = self._generate_event_description(
                    indicator, event_type, risk_assessment
                )
                
                # Extract cluster memberships
                cluster_memberships = []
                if risk_assessment:
                    cluster_memberships = risk_assessment.cluster_memberships
                
                # Create timeline event
                event = TimelineEvent(
                    timestamp=timestamp,
                    event_type=event_type,
                    attack_phase=attack_phase,
                    indicator=indicator,
                    risk_assessment=risk_assessment,
                    correlations=indicator_correlations,
                    cluster_memberships=cluster_memberships,
                    confidence=confidence,
                    event_description=description,
                    evidence=self._extract_event_evidence(indicator, risk_assessment)
                )
                
                events.append(event)
                
            except Exception as e:
                logger.error(f"Error creating timeline event for {indicator.id}: {e}")
        
        return events
    
    def _group_events_into_timelines(self, events: List[TimelineEvent],
                                   clusters: List[IndicatorCluster]) -> Dict[str, List[TimelineEvent]]:
        """Group related events into timeline sequences."""
        
        # Sort events by timestamp
        events.sort(key=lambda e: e.timestamp)
        
        # Group by cluster membership first
        cluster_timelines = defaultdict(list)
        unclustered_events = []
        
        for event in events:
            if event.cluster_memberships:
                # Use the first cluster ID as primary grouping
                cluster_id = event.cluster_memberships[0]
                cluster_timelines[f"cluster_{cluster_id}"].append(event)
            else:
                unclustered_events.append(event)
        
        # Group unclustered events by temporal proximity
        temporal_timelines = self._group_by_temporal_proximity(unclustered_events)
        
        # Merge timeline groups
        all_timelines = dict(cluster_timelines)
        for i, timeline_events in enumerate(temporal_timelines):
            all_timelines[f"temporal_{i}"] = timeline_events
        
        return all_timelines
    
    def _group_by_temporal_proximity(self, events: List[TimelineEvent]) -> List[List[TimelineEvent]]:
        """Group events by temporal proximity."""
        if not events:
            return []
        
        timelines = []
        current_timeline = [events[0]]
        
        for i in range(1, len(events)):
            prev_event = events[i-1]
            curr_event = events[i]
            
            time_gap = curr_event.timestamp - prev_event.timestamp
            
            if time_gap <= self.max_timeline_gap:
                current_timeline.append(curr_event)
            else:
                if len(current_timeline) >= self.min_timeline_events:
                    timelines.append(current_timeline)
                current_timeline = [curr_event]
        
        # Add final timeline
        if len(current_timeline) >= self.min_timeline_events:
            timelines.append(current_timeline)
        
        return timelines
    
    def _build_attack_timeline(self, timeline_id: str, events: List[TimelineEvent],
                              clusters: List[IndicatorCluster]) -> AttackTimeline:
        """Build complete attack timeline from events."""
        
        # Sort events chronologically
        events.sort(key=lambda e: e.timestamp)
        
        # Assign sequence numbers
        for i, event in enumerate(events):
            event.sequence_number = i + 1
        
        # Identify pivotal events
        self._identify_pivotal_events(events)
        
        # Calculate timeline metadata
        start_time = events[0].timestamp
        end_time = events[-1].timestamp
        duration = end_time - start_time
        
        # Analyze attack phases and categories
        attack_phases = set(event.attack_phase for event in events)
        threat_categories = set()
        for event in events:
            if event.risk_assessment:
                threat_categories.add(event.risk_assessment.threat_category)
        
        # Extract TTP patterns
        ttp_patterns = self._extract_ttp_patterns(events)
        
        # Calculate timeline confidence and completeness
        confidence = self._calculate_timeline_confidence(events)
        completeness_score = self._calculate_completeness_score(events, attack_phases)
        
        # Determine campaign name
        campaign_name = self._determine_campaign_name(timeline_id, events, clusters)
        
        # Analyze activity patterns
        peak_period = self._find_peak_activity_period(events)
        activity_pattern = self._classify_activity_pattern(events)
        escalation_detected = self._detect_escalation(events)
        
        # Extract geographic and source information
        unique_sources = set(event.indicator.source_metadata.source_name for event in events)
        geographic_scope = self._extract_geographic_scope(events)
        
        return AttackTimeline(
            timeline_id=timeline_id,
            campaign_name=campaign_name,
            events=events,
            start_time=start_time,
            end_time=end_time,
            duration=duration,
            attack_phases=attack_phases,
            threat_categories=threat_categories,
            ttp_patterns=ttp_patterns,
            confidence=confidence,
            completeness_score=completeness_score,
            analysis_timestamp=datetime.utcnow(),
            indicators_count=len(events),
            unique_sources=unique_sources,
            geographic_scope=geographic_scope,
            peak_activity_period=peak_period,
            activity_pattern=activity_pattern,
            escalation_detected=escalation_detected
        )
    
    def _identify_pivotal_events(self, events: List[TimelineEvent]) -> None:
        """Identify pivotal events in the timeline."""
        for event in events:
            # High-risk events are pivotal
            if (event.risk_assessment and 
                event.risk_assessment.risk_score >= self.pivotal_event_threshold):
                event.is_pivotal = True
            
            # Phase transition events
            if event.attack_phase == AttackPhase.INITIAL_ACCESS:
                event.is_pivotal = True
            
            # High correlation events
            if len(event.correlations) >= 5:
                event.is_pivotal = True
    
    def _extract_ttp_patterns(self, events: List[TimelineEvent]) -> List[str]:
        """Extract TTP patterns from events."""
        patterns = set()
        
        for event in events:
            # Add event type as TTP
            patterns.add(event.event_type.value)
            
            # Extract from indicator tags
            if event.indicator.tags:
                for tag in event.indicator.tags:
                    if any(keyword in tag.lower() for keyword in ['mitre', 'ttp', 'technique']):
                        patterns.add(tag)
        
        return list(patterns)
    
    def _calculate_timeline_confidence(self, events: List[TimelineEvent]) -> float:
        """Calculate overall timeline confidence."""
        if not events:
            return 0.0
        
        event_confidences = [event.confidence for event in events]
        base_confidence = sum(event_confidences) / len(event_confidences)
        
        # Bonus for diverse event types
        event_types = len(set(event.event_type for event in events))
        diversity_bonus = min(event_types * 0.1, 0.3)
        
        # Bonus for attack phase progression
        phases = set(event.attack_phase for event in events)
        if len(phases) >= 3:
            progression_bonus = 0.2
        elif len(phases) >= 2:
            progression_bonus = 0.1
        else:
            progression_bonus = 0.0
        
        return min(base_confidence + diversity_bonus + progression_bonus, 1.0)
    
    def _calculate_completeness_score(self, events: List[TimelineEvent],
                                    attack_phases: Set[AttackPhase]) -> float:
        """Calculate how complete the timeline appears."""
        
        # Expected attack progression
        expected_phases = [
            AttackPhase.PRE_ATTACK,
            AttackPhase.INITIAL_ACCESS,
            AttackPhase.POST_COMPROMISE,
            AttackPhase.OBJECTIVE_COMPLETION
        ]
        
        present_phases = len(attack_phases)
        total_phases = len(expected_phases)
        
        phase_completeness = present_phases / total_phases
        
        # Event type diversity
        event_types = set(event.event_type for event in events)
        type_diversity = min(len(event_types) / 8, 1.0)  # Max 8 different types
        
        # Temporal coverage (events spread over time)
        if len(events) >= 2:
            time_span = (events[-1].timestamp - events[0].timestamp).total_seconds()
            temporal_score = min(time_span / (24 * 3600), 1.0)  # Normalize to 24 hours
        else:
            temporal_score = 0.5
        
        return (phase_completeness * 0.4 + type_diversity * 0.3 + temporal_score * 0.3)
    
    def _determine_campaign_name(self, timeline_id: str, events: List[TimelineEvent],
                               clusters: List[IndicatorCluster]) -> Optional[str]:
        """Determine campaign name from timeline analysis."""
        
        # Check cluster names
        cluster_ids = set()
        for event in events:
            cluster_ids.update(event.cluster_memberships)
        
        relevant_clusters = [c for c in clusters if c.id in cluster_ids]
        
        for cluster in relevant_clusters:
            if cluster.cluster_type == ClusterType.CAMPAIGN:
                # Extract campaign name from cluster features
                if 'campaign_name' in cluster.cluster_features:
                    return cluster.cluster_features['campaign_name']
        
        # Generate name from threat categories and timeframe
        threat_categories = set()
        for event in events:
            if event.risk_assessment:
                threat_categories.add(event.risk_assessment.threat_category.value)
        
        if threat_categories:
            category_name = list(threat_categories)[0].replace('_', ' ').title()
            date_str = events[0].timestamp.strftime('%Y%m%d')
            return f"{category_name} Campaign {date_str}"
        
        return None
    
    def _find_peak_activity_period(self, events: List[TimelineEvent]) -> Optional[Tuple[datetime, datetime]]:
        """Find period of peak activity in the timeline."""
        if len(events) < 3:
            return None
        
        # Use sliding window to find peak activity
        window_size = timedelta(hours=6)
        max_events = 0
        peak_start = None
        peak_end = None
        
        for i, event in enumerate(events):
            window_start = event.timestamp
            window_end = window_start + window_size
            
            # Count events in window
            window_events = sum(
                1 for e in events[i:] 
                if window_start <= e.timestamp <= window_end
            )
            
            if window_events > max_events:
                max_events = window_events
                peak_start = window_start
                peak_end = window_end
        
        return (peak_start, peak_end) if peak_start and max_events >= 3 else None
    
    def _classify_activity_pattern(self, events: List[TimelineEvent]) -> str:
        """Classify the activity pattern of the timeline."""
        if len(events) < 2:
            return "single_event"
        
        # Calculate time intervals between events
        intervals = []
        for i in range(1, len(events)):
            interval = (events[i].timestamp - events[i-1].timestamp).total_seconds()
            intervals.append(interval)
        
        # Analyze interval patterns
        avg_interval = sum(intervals) / len(intervals)
        interval_variance = statistics.variance(intervals) if len(intervals) > 1 else 0
        
        # Classify based on patterns
        if interval_variance / (avg_interval ** 2) < 0.1:  # Low variance
            if avg_interval < 3600:  # Less than 1 hour
                return "burst"
            else:
                return "sustained"
        else:
            return "intermittent"
    
    def _detect_escalation(self, events: List[TimelineEvent]) -> bool:
        """Detect if there's escalation in the attack timeline."""
        
        # Check for risk score progression
        risk_scores = []
        for event in events:
            if event.risk_assessment:
                risk_scores.append(event.risk_assessment.risk_score)
        
        if len(risk_scores) >= 2:
            # Simple trend detection
            increasing_trend = sum(
                1 for i in range(1, len(risk_scores))
                if risk_scores[i] > risk_scores[i-1]
            )
            return increasing_trend > len(risk_scores) / 2
        
        # Check for attack phase progression
        phase_order = [
            AttackPhase.PRE_ATTACK,
            AttackPhase.INITIAL_ACCESS,
            AttackPhase.POST_COMPROMISE,
            AttackPhase.OBJECTIVE_COMPLETION
        ]
        
        seen_phases = []
        for event in events:
            if event.attack_phase not in seen_phases:
                seen_phases.append(event.attack_phase)
        
        # Check if phases follow expected progression
        phase_indices = [phase_order.index(phase) for phase in seen_phases if phase in phase_order]
        return len(phase_indices) >= 2 and sorted(phase_indices) == phase_indices
    
    def _extract_geographic_scope(self, events: List[TimelineEvent]) -> List[str]:
        """Extract geographic scope from events."""
        countries = set()
        
        for event in events:
            enrichment = event.indicator.context.get('enrichment', {})
            geo_data = enrichment.get('geolocation', {})
            
            if geo_data.get('success') and geo_data.get('country'):
                countries.add(geo_data['country'])
        
        return list(countries)
    
    def _parse_timestamp(self, timestamp_input) -> Optional[datetime]:
        """Parse timestamp string or datetime object to datetime object."""
        try:
            # If already a datetime object, return it
            if isinstance(timestamp_input, datetime):
                return timestamp_input
                
            # Handle string input with ISO format and Z suffix
            timestamp_str = str(timestamp_input)
            if timestamp_str.endswith('Z'):
                timestamp_str = timestamp_str[:-1] + '+00:00'
            
            return datetime.fromisoformat(timestamp_str)
        except Exception as e:
            logger.warning(f"Failed to parse timestamp {timestamp_input}: {e}")
            return None
    
    def _generate_event_description(self, indicator: NormalizedIndicator,
                                  event_type: TimelineEventType,
                                  risk_assessment: Optional[RiskAssessment]) -> str:
        """Generate human-readable event description."""
        
        indicator_desc = f"{indicator.indicator_type.value}: {indicator.value}"
        
        if risk_assessment:
            risk_level = risk_assessment.risk_level.value
            return f"{event_type.value.replace('_', ' ').title()} - {indicator_desc} (Risk: {risk_level})"
        else:
            return f"{event_type.value.replace('_', ' ').title()} - {indicator_desc}"
    
    def _extract_event_evidence(self, indicator: NormalizedIndicator,
                              risk_assessment: Optional[RiskAssessment]) -> Dict[str, Any]:
        """Extract evidence supporting the event classification."""
        evidence = {
            'indicator_type': indicator.indicator_type.value,
            'source': indicator.source_metadata.source_name,
            'tags': indicator.tags or []
        }
        
        if risk_assessment:
            evidence['risk_factors'] = [rf.name for rf in risk_assessment.risk_factors]
            evidence['threat_category'] = risk_assessment.threat_category.value
        
        return evidence


class TimelineAnalysisEngine:
    """Main engine for timeline analysis."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize timeline analysis engine."""
        self.config = config or {}
        self.timeline_builder = TimelineBuilder(self.config.get('timeline_builder', {}))
        
        logger.info("Timeline analysis engine initialized")
    
    def analyze_timelines(self, indicators: List[NormalizedIndicator],
                         risk_assessments: Dict[str, RiskAssessment],
                         correlations: Dict[str, List[CorrelationResult]],
                         clusters: List[IndicatorCluster]) -> Dict[str, Any]:
        """Perform comprehensive timeline analysis."""
        
        logger.info("Starting timeline analysis")
        
        # Build attack timelines
        timelines = self.timeline_builder.build_timelines(
            indicators, risk_assessments, correlations, clusters
        )
        
        # Analyze timeline patterns
        timeline_patterns = self._analyze_timeline_patterns(timelines)
        
        # Generate timeline summary
        summary = self._generate_timeline_summary(timelines, timeline_patterns)
        
        result = {
            'timelines': [timeline.to_dict() for timeline in timelines],
            'timeline_patterns': timeline_patterns,
            'summary': summary,
            'analysis_timestamp': datetime.utcnow().isoformat()
        }
        
        logger.info(f"Timeline analysis completed. Generated {len(timelines)} timelines")
        return result
    
    def _analyze_timeline_patterns(self, timelines: List[AttackTimeline]) -> Dict[str, Any]:
        """Analyze patterns across multiple timelines."""
        if not timelines:
            return {}
        
        patterns = {
            'common_attack_phases': self._find_common_attack_phases(timelines),
            'common_ttp_patterns': self._find_common_ttp_patterns(timelines),
            'activity_pattern_distribution': self._analyze_activity_patterns(timelines),
            'escalation_frequency': sum(1 for t in timelines if t.escalation_detected) / len(timelines),
            'avg_timeline_duration_hours': sum(t.duration.total_seconds() for t in timelines) / (len(timelines) * 3600),
            'geographic_patterns': self._analyze_geographic_patterns(timelines)
        }
        
        return patterns
    
    def _find_common_attack_phases(self, timelines: List[AttackTimeline]) -> List[str]:
        """Find commonly occurring attack phases."""
        phase_counts = defaultdict(int)
        
        for timeline in timelines:
            for phase in timeline.attack_phases:
                phase_counts[phase.value] += 1
        
        total_timelines = len(timelines)
        common_phases = [
            phase for phase, count in phase_counts.items()
            if count / total_timelines >= 0.3  # Present in 30%+ of timelines
        ]
        
        return common_phases
    
    def _find_common_ttp_patterns(self, timelines: List[AttackTimeline]) -> List[str]:
        """Find commonly occurring TTP patterns."""
        ttp_counts = defaultdict(int)
        
        for timeline in timelines:
            for ttp in timeline.ttp_patterns:
                ttp_counts[ttp] += 1
        
        total_timelines = len(timelines)
        common_ttps = [
            ttp for ttp, count in ttp_counts.items()
            if count / total_timelines >= 0.2  # Present in 20%+ of timelines
        ]
        
        return common_ttps
    
    def _analyze_activity_patterns(self, timelines: List[AttackTimeline]) -> Dict[str, int]:
        """Analyze distribution of activity patterns."""
        pattern_counts = defaultdict(int)
        
        for timeline in timelines:
            pattern_counts[timeline.activity_pattern] += 1
        
        return dict(pattern_counts)
    
    def _analyze_geographic_patterns(self, timelines: List[AttackTimeline]) -> Dict[str, Any]:
        """Analyze geographic patterns across timelines."""
        all_countries = []
        for timeline in timelines:
            all_countries.extend(timeline.geographic_scope)
        
        country_counts = defaultdict(int)
        for country in all_countries:
            country_counts[country] += 1
        
        return {
            'most_frequent_countries': sorted(
                country_counts.items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:10],
            'multi_country_campaigns': sum(
                1 for t in timelines if len(t.geographic_scope) > 1
            )
        }
    
    def _generate_timeline_summary(self, timelines: List[AttackTimeline],
                                 patterns: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary of timeline analysis."""
        if not timelines:
            return {'total_timelines': 0}
        
        # Calculate timeline statistics
        total_events = sum(len(t.events) for t in timelines)
        avg_confidence = sum(t.confidence for t in timelines) / len(timelines)
        high_confidence_timelines = sum(1 for t in timelines if t.confidence >= 0.7)
        
        # Threat category distribution
        threat_categories = defaultdict(int)
        for timeline in timelines:
            for category in timeline.threat_categories:
                threat_categories[category.value] += 1
        
        return {
            'total_timelines': len(timelines),
            'total_events': total_events,
            'avg_events_per_timeline': total_events / len(timelines),
            'avg_confidence': avg_confidence,
            'high_confidence_timelines': high_confidence_timelines,
            'threat_category_distribution': dict(threat_categories),
            'campaigns_identified': sum(1 for t in timelines if t.campaign_name),
            'escalation_detected_count': sum(1 for t in timelines if t.escalation_detected),
            'patterns': patterns
        }