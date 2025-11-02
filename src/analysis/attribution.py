"""
Attribution engine for threat intelligence analysis.

This module implements attribution analysis to link indicators to known threat actors
and campaigns using TTPs, behavioral patterns, infrastructure overlap, and historical
attack patterns. It provides confidence-scored attributions with supporting evidence.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, Counter
import json
import re

try:
    from ..normalizers.schema import NormalizedIndicator, IndicatorType
    from .correlation import CorrelationResult, CorrelationType
    from .clustering import IndicatorCluster, ClusterType
    from .risk_scoring import RiskAssessment, ThreatCategory
    from .timeline_analysis import AttackTimeline, TimelineEvent, TimelineEventType
except ImportError:
    from normalizers.schema import NormalizedIndicator, IndicatorType
    from analysis.correlation import CorrelationResult, CorrelationType
    from analysis.clustering import IndicatorCluster, ClusterType
    from analysis.risk_scoring import RiskAssessment, ThreatCategory
    from analysis.timeline_analysis import AttackTimeline, TimelineEvent, TimelineEventType

logger = logging.getLogger(__name__)


class AttributionConfidence(Enum):
    """Attribution confidence levels."""
    VERY_HIGH = "very_high"      # 90-100%
    HIGH = "high"                # 70-89%
    MEDIUM = "medium"            # 50-69%
    LOW = "low"                  # 30-49%
    VERY_LOW = "very_low"        # 0-29%


class ThreatActorType(Enum):
    """Types of threat actors."""
    NATION_STATE = "nation_state"
    CYBERCRIMINAL = "cybercriminal"
    HACKTIVIST = "hacktivist"
    INSIDER = "insider"
    OPPORTUNISTIC = "opportunistic"
    UNKNOWN = "unknown"


@dataclass
class ThreatActor:
    """Known threat actor profile."""
    actor_id: str
    name: str
    aliases: List[str]
    actor_type: ThreatActorType
    
    # Attribution characteristics
    known_ttps: List[str]
    infrastructure_patterns: List[str]
    malware_families: List[str]
    target_sectors: List[str]
    geographic_focus: List[str]
    
    # Behavioral patterns
    activity_patterns: Dict[str, Any]
    signature_indicators: List[str]
    
    # Metadata
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    confidence_score: float = 0.8
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            'actor_id': self.actor_id,
            'name': self.name,
            'aliases': self.aliases,
            'actor_type': self.actor_type.value,
            'known_ttps': self.known_ttps,
            'infrastructure_patterns': self.infrastructure_patterns,
            'malware_families': self.malware_families,
            'target_sectors': self.target_sectors,
            'geographic_focus': self.geographic_focus,
            'activity_patterns': self.activity_patterns,
            'signature_indicators': self.signature_indicators,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'confidence_score': self.confidence_score
        }


@dataclass
class AttributionEvidence:
    """Evidence supporting an attribution."""
    evidence_type: str
    description: str
    confidence: float
    indicators: List[str]
    supporting_data: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            'evidence_type': self.evidence_type,
            'description': self.description,
            'confidence': self.confidence,
            'indicators': self.indicators,
            'supporting_data': self.supporting_data
        }


@dataclass
class Attribution:
    """Attribution result linking indicators to threat actors."""
    attribution_id: str
    threat_actor: ThreatActor
    confidence: AttributionConfidence
    confidence_score: float  # 0.0 to 1.0
    
    # Evidence and support
    evidence: List[AttributionEvidence]
    matched_indicators: List[str]
    matching_ttps: List[str]
    infrastructure_overlap: List[str]
    
    # Analysis context
    campaign_name: Optional[str]
    analysis_timestamp: datetime
    
    # Additional context
    attribution_rationale: str
    conflicting_evidence: List[str] = field(default_factory=list)
    alternative_attributions: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            'attribution_id': self.attribution_id,
            'threat_actor': self.threat_actor.to_dict(),
            'confidence': self.confidence.value,
            'confidence_score': self.confidence_score,
            'evidence': [e.to_dict() for e in self.evidence],
            'matched_indicators': self.matched_indicators,
            'matching_ttps': self.matching_ttps,
            'infrastructure_overlap': self.infrastructure_overlap,
            'campaign_name': self.campaign_name,
            'analysis_timestamp': self.analysis_timestamp.isoformat(),
            'attribution_rationale': self.attribution_rationale,
            'conflicting_evidence': self.conflicting_evidence,
            'alternative_attributions': self.alternative_attributions
        }


class ThreatActorDatabase:
    """Database of known threat actors and their characteristics."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize threat actor database."""
        self.config = config or {}
        self.actors: Dict[str, ThreatActor] = {}
        
        # Load default threat actor profiles
        self._load_default_actors()
        
        # Load custom actors if configured
        custom_actors_file = self.config.get('custom_actors_file')
        if custom_actors_file:
            self._load_custom_actors(custom_actors_file)
    
    def _load_default_actors(self) -> None:
        """Load default threat actor profiles."""
        
        # APT29 (Cozy Bear)
        apt29 = ThreatActor(
            actor_id="apt29",
            name="APT29",
            aliases=["Cozy Bear", "The Dukes", "Office Monkeys"],
            actor_type=ThreatActorType.NATION_STATE,
            known_ttps=[
                "spear_phishing", "credential_harvesting", "living_off_land",
                "powershell_execution", "wmi_execution", "steganography",
                "cloud_services_abuse"
            ],
            infrastructure_patterns=[
                r".*\.temp-mail\.org$",
                r".*\.guerrillamail\..*$",
                r".*\.bit\.ly/.*$",
                r".*cloudfront\.net.*"
            ],
            malware_families=[
                "CozyDuke", "MiniDuke", "SeaDuke", "HammerToss", "CloudDuke"
            ],
            target_sectors=[
                "government", "healthcare", "technology", "energy"
            ],
            geographic_focus=["US", "EU", "UK"],
            activity_patterns={
                "typical_campaign_duration_days": 180,
                "preferred_attack_times": ["business_hours"],
                "stealth_level": "high",
                "persistence_methods": ["registry", "scheduled_tasks", "services"]
            },
            signature_indicators=[
                "use of steganography",
                "cloud services for C2",
                "powershell fileless attacks"
            ]
        )
        
        # APT28 (Fancy Bear)
        apt28 = ThreatActor(
            actor_id="apt28",
            name="APT28",
            aliases=["Fancy Bear", "Pawn Storm", "Sofacy", "STRONTIUM"],
            actor_type=ThreatActorType.NATION_STATE,
            known_ttps=[
                "spear_phishing", "zero_day_exploits", "credential_dumping",
                "lateral_movement", "data_exfiltration", "web_shells"
            ],
            infrastructure_patterns=[
                r".*\.bit\.ly/.*$",
                r".*\.tinyurl\.com/.*$",
                r".*-[0-9]{4,6}\..*$"
            ],
            malware_families=[
                "X-Agent", "Seduploader", "GAMEFISH", "Komplex", "CHOPSTICK"
            ],
            target_sectors=[
                "government", "military", "aerospace", "media"
            ],
            geographic_focus=["US", "EU", "NATO"],
            activity_patterns={
                "typical_campaign_duration_days": 90,
                "preferred_attack_times": ["business_hours", "off_hours"],
                "stealth_level": "medium",
                "persistence_methods": ["registry", "scheduled_tasks"]
            },
            signature_indicators=[
                "use of zero-day exploits",
                "targeting of government entities",
                "sophisticated spear phishing"
            ]
        )
        
        # Lazarus Group
        lazarus = ThreatActor(
            actor_id="lazarus",
            name="Lazarus Group",
            aliases=["HIDDEN COBRA", "Zinc", "APT38"],
            actor_type=ThreatActorType.NATION_STATE,
            known_ttps=[
                "destructive_attacks", "financial_theft", "supply_chain_attacks",
                "watering_hole", "cryptocurrency_theft"
            ],
            infrastructure_patterns=[
                r".*\.onion$",
                r".*\.bit\.ly/.*$",
                r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"
            ],
            malware_families=[
                "WannaCry", "BADCALL", "FALLCHILL", "SHARPKNOT", "TYPEFRAME"
            ],
            target_sectors=[
                "financial", "cryptocurrency", "entertainment", "government"
            ],
            geographic_focus=["Global"],
            activity_patterns={
                "typical_campaign_duration_days": 365,
                "preferred_attack_times": ["off_hours"],
                "stealth_level": "variable",
                "persistence_methods": ["registry", "services", "files"]
            },
            signature_indicators=[
                "destructive payloads",
                "cryptocurrency theft",
                "supply chain compromises"
            ]
        )
        
        # FIN7 (Carbanak)
        fin7 = ThreatActor(
            actor_id="fin7",
            name="FIN7",
            aliases=["Carbanak", "Navigator Group", "Carbon Spider"],
            actor_type=ThreatActorType.CYBERCRIMINAL,
            known_ttps=[
                "spear_phishing", "pos_malware", "memory_scraping",
                "lateral_movement", "financial_theft"
            ],
            infrastructure_patterns=[
                r".*\.bit\.ly/.*$",
                r".*\.amazonaws\.com.*",
                r"pos-.*\.com$"
            ],
            malware_families=[
                "CARBANAK", "HALFBAKED", "GRIFFON", "POWERSOURCE"
            ],
            target_sectors=[
                "retail", "hospitality", "restaurant", "financial"
            ],
            geographic_focus=["US", "EU"],
            activity_patterns={
                "typical_campaign_duration_days": 120,
                "preferred_attack_times": ["business_hours"],
                "stealth_level": "high",
                "persistence_methods": ["registry", "scheduled_tasks"]
            },
            signature_indicators=[
                "POS malware deployment",
                "restaurant chain targeting",
                "sophisticated social engineering"
            ]
        )
        
        # Store actors
        self.actors[apt29.actor_id] = apt29
        self.actors[apt28.actor_id] = apt28
        self.actors[lazarus.actor_id] = lazarus
        self.actors[fin7.actor_id] = fin7
        
        logger.info(f"Loaded {len(self.actors)} default threat actors")
    
    def _load_custom_actors(self, actors_file: str) -> None:
        """Load custom threat actors from file."""
        try:
            with open(actors_file, 'r') as f:
                custom_data = json.load(f)
            
            for actor_data in custom_data.get('actors', []):
                actor = ThreatActor(
                    actor_id=actor_data['actor_id'],
                    name=actor_data['name'],
                    aliases=actor_data.get('aliases', []),
                    actor_type=ThreatActorType(actor_data.get('actor_type', 'unknown')),
                    known_ttps=actor_data.get('known_ttps', []),
                    infrastructure_patterns=actor_data.get('infrastructure_patterns', []),
                    malware_families=actor_data.get('malware_families', []),
                    target_sectors=actor_data.get('target_sectors', []),
                    geographic_focus=actor_data.get('geographic_focus', []),
                    activity_patterns=actor_data.get('activity_patterns', {}),
                    signature_indicators=actor_data.get('signature_indicators', [])
                )
                self.actors[actor.actor_id] = actor
            
            logger.info(f"Loaded {len(custom_data.get('actors', []))} custom threat actors")
            
        except Exception as e:
            logger.error(f"Failed to load custom actors from {actors_file}: {e}")
    
    def get_all_actors(self) -> List[ThreatActor]:
        """Get all threat actors."""
        return list(self.actors.values())
    
    def get_actor(self, actor_id: str) -> Optional[ThreatActor]:
        """Get specific threat actor by ID."""
        return self.actors.get(actor_id)
    
    def search_actors_by_ttp(self, ttp_pattern: str) -> List[ThreatActor]:
        """Find actors that use specific TTPs."""
        matching_actors = []
        
        for actor in self.actors.values():
            if any(ttp_pattern.lower() in ttp.lower() for ttp in actor.known_ttps):
                matching_actors.append(actor)
        
        return matching_actors
    
    def search_actors_by_malware(self, malware_name: str) -> List[ThreatActor]:
        """Find actors associated with specific malware."""
        matching_actors = []
        
        for actor in self.actors.values():
            if any(malware_name.lower() in malware.lower() for malware in actor.malware_families):
                matching_actors.append(actor)
        
        return matching_actors


class AttributionAnalyzer:
    """Analyzes patterns to determine threat actor attribution."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize attribution analyzer."""
        self.config = config or {}
        self.actor_db = ThreatActorDatabase(self.config.get('actor_database', {}))
        
        # Attribution weights
        self.weights = {
            'ttp_matching': self.config.get('ttp_weight', 0.3),
            'infrastructure_overlap': self.config.get('infrastructure_weight', 0.25),
            'malware_family': self.config.get('malware_weight', 0.2),
            'target_sector': self.config.get('sector_weight', 0.1),
            'geographic_alignment': self.config.get('geographic_weight', 0.1),
            'temporal_patterns': self.config.get('temporal_weight', 0.05)
        }
        
        # Confidence thresholds
        self.confidence_thresholds = {
            AttributionConfidence.VERY_HIGH: self.config.get('very_high_threshold', 0.9),
            AttributionConfidence.HIGH: self.config.get('high_threshold', 0.7),
            AttributionConfidence.MEDIUM: self.config.get('medium_threshold', 0.5),
            AttributionConfidence.LOW: self.config.get('low_threshold', 0.3),
        }
    
    def analyze_attribution(self, indicators: List[NormalizedIndicator],
                          timelines: List[AttackTimeline],
                          clusters: List[IndicatorCluster],
                          risk_assessments: Dict[str, RiskAssessment]) -> List[Attribution]:
        """Perform comprehensive attribution analysis."""
        
        logger.info(f"Analyzing attribution for {len(indicators)} indicators")
        
        attributions = []
        
        # Extract analysis features
        features = self._extract_attribution_features(indicators, timelines, clusters, risk_assessments)
        
        # Analyze each threat actor for potential matches
        for actor in self.actor_db.get_all_actors():
            attribution = self._analyze_actor_match(actor, features, indicators, timelines)
            
            if attribution and attribution.confidence_score >= self.confidence_thresholds[AttributionConfidence.LOW]:
                attributions.append(attribution)
        
        # Sort by confidence score
        attributions.sort(key=lambda x: x.confidence_score, reverse=True)
        
        logger.info(f"Generated {len(attributions)} potential attributions")
        return attributions
    
    def _extract_attribution_features(self, indicators: List[NormalizedIndicator],
                                    timelines: List[AttackTimeline],
                                    clusters: List[IndicatorCluster],
                                    risk_assessments: Dict[str, RiskAssessment]) -> Dict[str, Any]:
        """Extract features for attribution analysis."""
        
        features = {
            'ttps': set(),
            'infrastructure_patterns': set(),
            'malware_families': set(),
            'target_sectors': set(),
            'geographic_locations': set(),
            'temporal_patterns': {},
            'campaign_characteristics': {},
            'indicator_types': defaultdict(int)
        }
        
        # Extract TTPs from timelines
        for timeline in timelines:
            # Handle both dict and object formats
            if isinstance(timeline, dict):
                ttp_patterns = timeline.get('ttp_patterns', [])
            else:
                ttp_patterns = getattr(timeline, 'ttp_patterns', [])
            
            features['ttps'].update(ttp_patterns)
            
            # Handle geographic scope
            if isinstance(timeline, dict):
                geographic_scope = timeline.get('geographic_scope', [])
            else:
                geographic_scope = getattr(timeline, 'geographic_scope', [])
            
            features['geographic_locations'].update(geographic_scope)
            
            # Extract campaign characteristics
            if isinstance(timeline, dict):
                campaign_name = timeline.get('campaign_name')
                escalation_detected = timeline.get('escalation_detected', False)
                activity_pattern = timeline.get('activity_pattern', 'unknown')
            else:
                campaign_name = getattr(timeline, 'campaign_name', None)
                escalation_detected = getattr(timeline, 'escalation_detected', False)
                activity_pattern = getattr(timeline, 'activity_pattern', 'unknown')
            
            if campaign_name:
                features['campaign_characteristics']['has_named_campaign'] = True
            
            features['campaign_characteristics']['escalation_detected'] = escalation_detected
            features['campaign_characteristics']['activity_pattern'] = activity_pattern
        
        # Extract infrastructure patterns from indicators
        for indicator in indicators:
            features['indicator_types'][indicator.indicator_type] += 1
            
            # Extract infrastructure patterns
            if indicator.indicator_type in {IndicatorType.DOMAIN, IndicatorType.URL}:
                features['infrastructure_patterns'].add(indicator.value)
            
            # Extract malware families from tags
            if indicator.tags:
                for tag in indicator.tags:
                    if any(keyword in tag.lower() for keyword in ['malware', 'family', 'trojan', 'rat']):
                        features['malware_families'].add(tag)
            
            # Extract geographic information
            enrichment = indicator.context.get('enrichment', {})
            geo_data = enrichment.get('geolocation', {})
            if geo_data.get('success') and geo_data.get('country'):
                features['geographic_locations'].add(geo_data['country'])
        
        # Extract cluster-based features
        for cluster in clusters:
            if cluster.cluster_type == ClusterType.MALWARE_FAMILY:
                malware_name = cluster.cluster_features.get('primary_malware_family')
                if malware_name:
                    features['malware_families'].add(malware_name)
            
            elif cluster.cluster_type == ClusterType.CAMPAIGN:
                campaign_ttps = cluster.cluster_features.get('campaign_ttps', [])
                features['ttps'].update(campaign_ttps)
        
        # Convert sets to lists for JSON serialization
        for key, value in features.items():
            if isinstance(value, set):
                features[key] = list(value)
        
        return features
    
    def _analyze_actor_match(self, actor: ThreatActor, features: Dict[str, Any],
                           indicators: List[NormalizedIndicator],
                           timelines: List[AttackTimeline]) -> Optional[Attribution]:
        """Analyze how well an actor matches the observed features."""
        
        evidence = []
        total_score = 0.0
        max_possible_score = sum(self.weights.values())
        
        # TTP matching
        ttp_score, ttp_evidence = self._analyze_ttp_match(actor, features['ttps'])
        if ttp_evidence:
            evidence.append(ttp_evidence)
        total_score += ttp_score * self.weights['ttp_matching']
        
        # Infrastructure overlap
        infra_score, infra_evidence = self._analyze_infrastructure_match(actor, features['infrastructure_patterns'])
        if infra_evidence:
            evidence.append(infra_evidence)
        total_score += infra_score * self.weights['infrastructure_overlap']
        
        # Malware family matching
        malware_score, malware_evidence = self._analyze_malware_match(actor, features['malware_families'])
        if malware_evidence:
            evidence.append(malware_evidence)
        total_score += malware_score * self.weights['malware_family']
        
        # Geographic alignment
        geo_score, geo_evidence = self._analyze_geographic_match(actor, features['geographic_locations'])
        if geo_evidence:
            evidence.append(geo_evidence)
        total_score += geo_score * self.weights['geographic_alignment']
        
        # Temporal pattern analysis
        temporal_score, temporal_evidence = self._analyze_temporal_patterns(actor, timelines)
        if temporal_evidence:
            evidence.append(temporal_evidence)
        total_score += temporal_score * self.weights['temporal_patterns']
        
        # Calculate confidence score
        confidence_score = total_score / max_possible_score if max_possible_score > 0 else 0.0
        
        # Only create attribution if there's meaningful evidence
        if not evidence or confidence_score < 0.1:
            return None
        
        # Determine confidence level
        confidence_level = self._determine_confidence_level(confidence_score)
        
        # Generate attribution rationale
        rationale = self._generate_attribution_rationale(actor, evidence, confidence_score)
        
        # Extract matched indicators
        matched_indicators = [ind.id for ind in indicators[:10]]  # Limit for brevity
        
        # Extract matching TTPs
        matching_ttps = list(set(features['ttps']) & set(actor.known_ttps))
        
        # Extract infrastructure overlap
        infrastructure_overlap = []
        for pattern in actor.infrastructure_patterns:
            for infra in features['infrastructure_patterns']:
                try:
                    if re.search(pattern, infra, re.IGNORECASE):
                        infrastructure_overlap.append(infra)
                except re.error:
                    continue
        
        attribution = Attribution(
            attribution_id=f"attr_{actor.actor_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
            threat_actor=actor,
            confidence=confidence_level,
            confidence_score=confidence_score,
            evidence=evidence,
            matched_indicators=matched_indicators,
            matching_ttps=matching_ttps,
            infrastructure_overlap=infrastructure_overlap,
            campaign_name=timelines[0].get('campaign_name') if timelines and isinstance(timelines[0], dict) else (getattr(timelines[0], 'campaign_name', None) if timelines else None),
            analysis_timestamp=datetime.utcnow(),
            attribution_rationale=rationale
        )
        
        return attribution
    
    def _analyze_ttp_match(self, actor: ThreatActor, observed_ttps: List[str]) -> Tuple[float, Optional[AttributionEvidence]]:
        """Analyze TTP matching between actor and observed behavior."""
        
        if not observed_ttps or not actor.known_ttps:
            return 0.0, None
        
        # Find matching TTPs
        matches = []
        for observed_ttp in observed_ttps:
            for known_ttp in actor.known_ttps:
                if observed_ttp.lower() in known_ttp.lower() or known_ttp.lower() in observed_ttp.lower():
                    matches.append((observed_ttp, known_ttp))
        
        if not matches:
            return 0.0, None
        
        # Calculate match score
        match_ratio = len(matches) / max(len(observed_ttps), len(actor.known_ttps))
        score = min(match_ratio * 2, 1.0)  # Boost score for good matches
        
        evidence = AttributionEvidence(
            evidence_type="ttp_matching",
            description=f"Observed TTPs match known {actor.name} tactics",
            confidence=score,
            indicators=[],
            supporting_data={
                'matched_ttps': matches,
                'total_observed_ttps': len(observed_ttps),
                'total_known_ttps': len(actor.known_ttps),
                'match_ratio': match_ratio
            }
        )
        
        return score, evidence
    
    def _analyze_infrastructure_match(self, actor: ThreatActor, 
                                    observed_infrastructure: List[str]) -> Tuple[float, Optional[AttributionEvidence]]:
        """Analyze infrastructure pattern matching."""
        
        if not observed_infrastructure or not actor.infrastructure_patterns:
            return 0.0, None
        
        matches = []
        
        for pattern in actor.infrastructure_patterns:
            for infra in observed_infrastructure:
                try:
                    if re.search(pattern, infra, re.IGNORECASE):
                        matches.append((infra, pattern))
                except re.error:
                    continue
        
        if not matches:
            return 0.0, None
        
        # Calculate score based on match ratio
        unique_matches = len(set(match[0] for match in matches))
        score = min(unique_matches / len(observed_infrastructure), 1.0)
        
        evidence = AttributionEvidence(
            evidence_type="infrastructure_overlap",
            description=f"Infrastructure patterns match {actor.name} known patterns",
            confidence=score,
            indicators=[match[0] for match in matches],
            supporting_data={
                'matched_patterns': matches,
                'unique_matches': unique_matches,
                'total_observed': len(observed_infrastructure)
            }
        )
        
        return score, evidence
    
    def _analyze_malware_match(self, actor: ThreatActor, 
                             observed_malware: List[str]) -> Tuple[float, Optional[AttributionEvidence]]:
        """Analyze malware family matching."""
        
        if not observed_malware or not actor.malware_families:
            return 0.0, None
        
        matches = []
        
        for observed in observed_malware:
            for known in actor.malware_families:
                if (observed.lower() in known.lower() or 
                    known.lower() in observed.lower() or
                    any(part in known.lower() for part in observed.lower().split())):
                    matches.append((observed, known))
        
        if not matches:
            return 0.0, None
        
        # Malware matches are high confidence indicators
        score = min(len(matches) / len(actor.malware_families) * 1.5, 1.0)
        
        evidence = AttributionEvidence(
            evidence_type="malware_family",
            description=f"Malware families associated with {actor.name}",
            confidence=score,
            indicators=[],
            supporting_data={
                'matched_families': matches,
                'actor_malware_families': actor.malware_families
            }
        )
        
        return score, evidence
    
    def _analyze_geographic_match(self, actor: ThreatActor, 
                                observed_locations: List[str]) -> Tuple[float, Optional[AttributionEvidence]]:
        """Analyze geographic alignment."""
        
        if not observed_locations or not actor.geographic_focus:
            return 0.0, None
        
        # Check for overlap
        actor_regions = set(region.upper() for region in actor.geographic_focus)
        observed_regions = set(loc.upper() for loc in observed_locations)
        
        matches = actor_regions & observed_regions
        
        if not matches:
            return 0.0, None
        
        # Geographic match is supporting evidence but not strong on its own
        score = min(len(matches) / len(actor_regions), 0.5)
        
        evidence = AttributionEvidence(
            evidence_type="geographic_alignment",
            description=f"Geographic activity aligns with {actor.name} focus areas",
            confidence=score,
            indicators=[],
            supporting_data={
                'matched_regions': list(matches),
                'actor_focus': actor.geographic_focus,
                'observed_locations': observed_locations
            }
        )
        
        return score, evidence
    
    def _analyze_temporal_patterns(self, actor: ThreatActor, 
                                 timelines: List[AttackTimeline]) -> Tuple[float, Optional[AttributionEvidence]]:
        """Analyze temporal pattern alignment."""
        
        if not timelines:
            return 0.0, None
        
        # Analyze campaign duration patterns
        expected_duration = actor.activity_patterns.get('typical_campaign_duration_days', 90)
        
        matches = 0
        for timeline in timelines:
            # Handle both dict and object formats
            if isinstance(timeline, dict):
                duration_days = timeline.get('duration_hours', 0) / 24  # Convert hours to days
            else:
                duration_days = getattr(timeline, 'duration', timedelta()).days
            
            # Check if duration is within reasonable range
            if 0.5 * expected_duration <= duration_days <= 2.0 * expected_duration:
                matches += 1
        
        if matches == 0:
            return 0.0, None
        
        score = min(matches / len(timelines) * 0.5, 0.3)  # Temporal evidence is supportive
        
        evidence = AttributionEvidence(
            evidence_type="temporal_patterns",
            description=f"Timeline patterns consistent with {actor.name} behavior",
            confidence=score,
            indicators=[],
            supporting_data={
                'expected_duration_days': expected_duration,
                'matching_timelines': matches,
                'total_timelines': len(timelines)
            }
        )
        
        return score, evidence
    
    def _determine_confidence_level(self, confidence_score: float) -> AttributionConfidence:
        """Determine confidence level from score."""
        
        if confidence_score >= self.confidence_thresholds[AttributionConfidence.VERY_HIGH]:
            return AttributionConfidence.VERY_HIGH
        elif confidence_score >= self.confidence_thresholds[AttributionConfidence.HIGH]:
            return AttributionConfidence.HIGH
        elif confidence_score >= self.confidence_thresholds[AttributionConfidence.MEDIUM]:
            return AttributionConfidence.MEDIUM
        elif confidence_score >= self.confidence_thresholds[AttributionConfidence.LOW]:
            return AttributionConfidence.LOW
        else:
            return AttributionConfidence.VERY_LOW
    
    def _generate_attribution_rationale(self, actor: ThreatActor, 
                                      evidence: List[AttributionEvidence],
                                      confidence_score: float) -> str:
        """Generate human-readable attribution rationale."""
        
        rationale_parts = [
            f"Attribution to {actor.name} ({actor.actor_type.value}) "
            f"with {confidence_score:.1%} confidence based on:"
        ]
        
        for evidence_item in evidence:
            if evidence_item.confidence > 0.3:
                rationale_parts.append(f"- {evidence_item.description} "
                                     f"(confidence: {evidence_item.confidence:.1%})")
        
        if len(evidence) > 1:
            rationale_parts.append("Multiple evidence types support this attribution.")
        
        return " ".join(rationale_parts)


class AttributionEngine:
    """Main attribution analysis engine."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize attribution engine."""
        self.config = config or {}
        self.analyzer = AttributionAnalyzer(self.config.get('analyzer', {}))
        
        logger.info("Attribution engine initialized")
    
    def perform_attribution_analysis(self, indicators: List[NormalizedIndicator],
                                   timelines: List[AttackTimeline],
                                   clusters: List[IndicatorCluster],
                                   risk_assessments: Dict[str, RiskAssessment]) -> Dict[str, Any]:
        """Perform comprehensive attribution analysis."""
        
        logger.info("Starting attribution analysis")
        
        # Perform attribution analysis
        attributions = self.analyzer.analyze_attribution(
            indicators, timelines, clusters, risk_assessments
        )
        
        # Analyze attribution patterns
        attribution_summary = self._generate_attribution_summary(attributions)
        
        # Generate threat actor landscape
        actor_landscape = self._generate_actor_landscape(attributions)
        
        result = {
            'attributions': [attr.to_dict() for attr in attributions],
            'summary': attribution_summary,
            'actor_landscape': actor_landscape,
            'analysis_timestamp': datetime.utcnow().isoformat()
        }
        
        logger.info(f"Attribution analysis completed. Found {len(attributions)} potential attributions")
        return result
    
    def _generate_attribution_summary(self, attributions: List[Attribution]) -> Dict[str, Any]:
        """Generate attribution analysis summary."""
        
        if not attributions:
            return {'total_attributions': 0}
        
        # Confidence distribution
        confidence_dist = defaultdict(int)
        for attr in attributions:
            confidence_dist[attr.confidence.value] += 1
        
        # Actor type distribution
        actor_type_dist = defaultdict(int)
        for attr in attributions:
            actor_type_dist[attr.threat_actor.actor_type.value] += 1
        
        # Top attributed actors
        actor_counts = Counter(attr.threat_actor.name for attr in attributions)
        top_actors = actor_counts.most_common(5)
        
        # Evidence type analysis
        evidence_types = defaultdict(int)
        for attr in attributions:
            for evidence in attr.evidence:
                evidence_types[evidence.evidence_type] += 1
        
        return {
            'total_attributions': len(attributions),
            'confidence_distribution': dict(confidence_dist),
            'actor_type_distribution': dict(actor_type_dist),
            'top_attributed_actors': top_actors,
            'evidence_type_frequency': dict(evidence_types),
            'high_confidence_attributions': sum(
                1 for attr in attributions 
                if attr.confidence in {AttributionConfidence.HIGH, AttributionConfidence.VERY_HIGH}
            )
        }
    
    def _generate_actor_landscape(self, attributions: List[Attribution]) -> Dict[str, Any]:
        """Generate threat actor landscape analysis."""
        
        unique_actors = {}
        for attr in attributions:
            actor_id = attr.threat_actor.actor_id
            if actor_id not in unique_actors:
                unique_actors[actor_id] = {
                    'actor': attr.threat_actor.to_dict(),
                    'attributions_count': 0,
                    'max_confidence': 0.0,
                    'evidence_types': set()
                }
            
            unique_actors[actor_id]['attributions_count'] += 1
            unique_actors[actor_id]['max_confidence'] = max(
                unique_actors[actor_id]['max_confidence'],
                attr.confidence_score
            )
            
            for evidence in attr.evidence:
                unique_actors[actor_id]['evidence_types'].add(evidence.evidence_type)
        
        # Convert sets to lists
        for actor_data in unique_actors.values():
            actor_data['evidence_types'] = list(actor_data['evidence_types'])
        
        # Actor activity patterns
        nation_state_actors = sum(
            1 for data in unique_actors.values()
            if data['actor']['actor_type'] == 'nation_state'
        )
        
        cybercriminal_actors = sum(
            1 for data in unique_actors.values()
            if data['actor']['actor_type'] == 'cybercriminal'
        )
        
        return {
            'unique_actors_detected': len(unique_actors),
            'actors_by_type': {
                'nation_state': nation_state_actors,
                'cybercriminal': cybercriminal_actors,
                'other': len(unique_actors) - nation_state_actors - cybercriminal_actors
            },
            'actor_details': unique_actors
        }