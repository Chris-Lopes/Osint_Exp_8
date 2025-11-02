"""
Advanced correlation engine for threat intelligence analysis.

This module implements a sophisticated correlation system that creates knowledge graphs
showing relationships between indicators, techniques, CVEs, and infrastructure.
It provides graph-based analysis capabilities for identifying attack patterns,
threat actor attribution, and infrastructure connections.
"""

import logging
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any, Optional, Set, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
import networkx as nx
from collections import defaultdict, Counter
import statistics
import math

try:
    from ..normalizers.schema import NormalizedIndicator, IndicatorType
except ImportError:
    from normalizers.schema import NormalizedIndicator, IndicatorType

logger = logging.getLogger(__name__)


class NodeType(Enum):
    """Types of nodes in the knowledge graph."""
    INDICATOR = "indicator"
    TECHNIQUE = "technique"
    CVE = "cve"
    INFRASTRUCTURE = "infrastructure"
    MALWARE_FAMILY = "malware_family"
    THREAT_ACTOR = "threat_actor"
    CAMPAIGN = "campaign"
    ATTACK_PATTERN = "attack_pattern"


class RelationshipType(Enum):
    """Types of relationships between nodes."""
    # Infrastructure relationships
    SHARES_INFRASTRUCTURE = "shares_infrastructure"
    RESOLVES_TO = "resolves_to"
    COMMUNICATES_WITH = "communicates_with"
    
    # Temporal relationships
    OBSERVED_TOGETHER = "observed_together"
    SEQUENTIAL_ACTIVITY = "sequential_activity"
    
    # Technical relationships
    EXPLOITS = "exploits"
    USES_TECHNIQUE = "uses_technique"
    DELIVERS = "delivers"
    
    # Attribution relationships
    ATTRIBUTED_TO = "attributed_to"
    PART_OF_CAMPAIGN = "part_of_campaign"
    SIMILAR_TO = "similar_to"
    
    # Contextual relationships
    SAME_FAMILY = "same_family"
    TARGETS_SAME = "targets_same"
    USES_SAME_TTP = "uses_same_ttp"


@dataclass
class GraphNode:
    """Node in the knowledge graph."""
    
    node_id: str
    node_type: NodeType
    
    # Core attributes
    value: str
    label: str
    
    # Metadata
    properties: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0
    
    # Temporal information
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    
    # Source tracking
    sources: Set[str] = field(default_factory=set)
    source_count: int = 0
    
    # Graph metrics (computed)
    centrality_scores: Dict[str, float] = field(default_factory=dict)
    community_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'node_id': self.node_id,
            'node_type': self.node_type.value,
            'value': self.value,
            'label': self.label,
            'properties': self.properties,
            'confidence': self.confidence,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'sources': list(self.sources),
            'source_count': self.source_count,
            'centrality_scores': self.centrality_scores,
            'community_id': self.community_id
        }


@dataclass
class GraphRelationship:
    """Relationship between nodes in the knowledge graph."""
    
    relationship_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source_node_id: str = ""
    target_node_id: str = ""
    relationship_type: RelationshipType = RelationshipType.SIMILAR_TO
    
    # Relationship strength and confidence
    weight: float = 1.0
    confidence: float = 0.0
    
    # Evidence and provenance
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    sources: Set[str] = field(default_factory=set)
    
    # Temporal information
    first_observed: Optional[datetime] = None
    last_observed: Optional[datetime] = None
    
    # Additional metadata
    properties: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'relationship_id': self.relationship_id,
            'source_node_id': self.source_node_id,
            'target_node_id': self.target_node_id,
            'relationship_type': self.relationship_type.value,
            'weight': self.weight,
            'confidence': self.confidence,
            'evidence': self.evidence,
            'sources': list(self.sources),
            'first_observed': self.first_observed.isoformat() if self.first_observed else None,
            'last_observed': self.last_observed.isoformat() if self.last_observed else None,
            'properties': self.properties
        }


@dataclass
class CorrelationResult:
    """Result of correlation analysis."""
    
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    
    # Input data
    input_indicators: List[NormalizedIndicator] = field(default_factory=list)
    
    # Graph structure
    nodes: Dict[str, GraphNode] = field(default_factory=dict)
    relationships: Dict[str, GraphRelationship] = field(default_factory=dict)
    
    # Analysis results
    communities: Dict[str, List[str]] = field(default_factory=dict)
    key_nodes: List[str] = field(default_factory=list)
    attack_patterns: List[Dict[str, Any]] = field(default_factory=list)
    
    # Statistics
    node_count: int = 0
    relationship_count: int = 0
    density: float = 0.0
    
    # Execution metadata
    execution_time: float = 0.0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'correlation_id': self.correlation_id,
            'input_indicator_count': len(self.input_indicators),
            'nodes': {nid: node.to_dict() for nid, node in self.nodes.items()},
            'relationships': {rid: rel.to_dict() for rid, rel in self.relationships.items()},
            'communities': self.communities,
            'key_nodes': self.key_nodes,
            'attack_patterns': self.attack_patterns,
            'node_count': self.node_count,
            'relationship_count': self.relationship_count,
            'density': self.density,
            'execution_time': self.execution_time,
            'created_at': self.created_at.isoformat()
        }


class NodeExtractor:
    """Extracts nodes from normalized indicators."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize node extractor."""
        self.config = config or {}
        
        # Extraction settings
        self.min_confidence = self.config.get('min_confidence', 50)
        self.extract_infrastructure = self.config.get('extract_infrastructure', True)
        self.extract_techniques = self.config.get('extract_techniques', True)
        self.extract_malware = self.config.get('extract_malware', True)
        
        logger.debug("Node extractor initialized")
    
    def extract_nodes(self, indicators: List[NormalizedIndicator]) -> Dict[str, GraphNode]:
        """Extract nodes from indicators."""
        
        nodes = {}
        
        for indicator in indicators:
            # Skip low confidence indicators
            if hasattr(indicator, 'confidence') and indicator.confidence < self.min_confidence:
                continue
            
            # Extract primary indicator node
            indicator_node = self._create_indicator_node(indicator)
            nodes[indicator_node.node_id] = indicator_node
            
            # Extract technique nodes
            if self.extract_techniques and hasattr(indicator, 'techniques'):
                technique_nodes = self._extract_technique_nodes(indicator)
                nodes.update(technique_nodes)
            
            # Extract CVE nodes
            if hasattr(indicator, 'cves') or hasattr(indicator, 'vulnerabilities'):
                cve_nodes = self._extract_cve_nodes(indicator)
                nodes.update(cve_nodes)
            
            # Extract malware family nodes
            if self.extract_malware and hasattr(indicator, 'malware_families'):
                malware_nodes = self._extract_malware_nodes(indicator)
                nodes.update(malware_nodes)
            
            # Extract infrastructure nodes
            if self.extract_infrastructure:
                infra_nodes = self._extract_infrastructure_nodes(indicator)
                nodes.update(infra_nodes)
        
        logger.info(f"Extracted {len(nodes)} nodes from {len(indicators)} indicators")
        return nodes
    
    def _create_indicator_node(self, indicator: NormalizedIndicator) -> GraphNode:
        """Create node for indicator."""
        
        return GraphNode(
            node_id=f"indicator_{indicator.id}",
            node_type=NodeType.INDICATOR,
            value=indicator.value,
            label=f"{indicator.indicator_type.value}: {indicator.value}",
            properties={
                'indicator_type': indicator.indicator_type.value,
                'tags': getattr(indicator, 'tags', []),
                'threat_types': getattr(indicator, 'threat_types', []),
                'severity': getattr(indicator, 'severity', 'unknown'),
                'original_id': indicator.id
            },
            confidence=getattr(indicator, 'confidence', 50) / 100.0,
            first_seen=getattr(indicator, 'first_seen', None),
            last_seen=getattr(indicator, 'last_seen', None),
            sources={getattr(indicator, 'source', 'unknown')},
            source_count=1
        )
    
    def _extract_technique_nodes(self, indicator: NormalizedIndicator) -> Dict[str, GraphNode]:
        """Extract technique nodes from indicator."""
        
        nodes = {}
        techniques = getattr(indicator, 'techniques', [])
        
        for technique in techniques:
            technique_id = technique if isinstance(technique, str) else technique.get('id', str(technique))
            node_id = f"technique_{technique_id}"
            
            if node_id not in nodes:
                technique_name = technique if isinstance(technique, str) else technique.get('name', technique_id)
                
                nodes[node_id] = GraphNode(
                    node_id=node_id,
                    node_type=NodeType.TECHNIQUE,
                    value=technique_id,
                    label=f"Technique: {technique_name}",
                    properties={
                        'technique_id': technique_id,
                        'technique_name': technique_name,
                        'category': getattr(technique, 'category', 'unknown') if hasattr(technique, 'category') else 'unknown'
                    },
                    confidence=0.8,
                    sources={getattr(indicator, 'source', 'unknown')}
                )
        
        return nodes
    
    def _extract_cve_nodes(self, indicator: NormalizedIndicator) -> Dict[str, GraphNode]:
        """Extract CVE nodes from indicator."""
        
        nodes = {}
        
        # Get CVEs from different possible fields
        cves = []
        if hasattr(indicator, 'cves') and indicator.cves:
            cves.extend(indicator.cves)
        if hasattr(indicator, 'vulnerabilities') and indicator.vulnerabilities:
            cves.extend(indicator.vulnerabilities)
        
        for cve in cves:
            cve_id = cve if isinstance(cve, str) else cve.get('id', str(cve))
            node_id = f"cve_{cve_id}"
            
            if node_id not in nodes:
                cve_name = cve_id
                severity = 'unknown'
                
                if isinstance(cve, dict):
                    cve_name = cve.get('name', cve_id)
                    severity = cve.get('severity', 'unknown')
                
                nodes[node_id] = GraphNode(
                    node_id=node_id,
                    node_type=NodeType.CVE,
                    value=cve_id,
                    label=f"CVE: {cve_name}",
                    properties={
                        'cve_id': cve_id,
                        'cve_name': cve_name,
                        'severity': severity
                    },
                    confidence=0.9,  # CVEs are typically high confidence
                    sources={getattr(indicator, 'source', 'unknown')}
                )
        
        return nodes
    
    def _extract_malware_nodes(self, indicator: NormalizedIndicator) -> Dict[str, GraphNode]:
        """Extract malware family nodes from indicator."""
        
        nodes = {}
        malware_families = getattr(indicator, 'malware_families', [])
        
        for family in malware_families:
            family_name = family if isinstance(family, str) else family.get('name', str(family))
            node_id = f"malware_{family_name.lower().replace(' ', '_')}"
            
            if node_id not in nodes:
                nodes[node_id] = GraphNode(
                    node_id=node_id,
                    node_type=NodeType.MALWARE_FAMILY,
                    value=family_name,
                    label=f"Malware: {family_name}",
                    properties={
                        'family_name': family_name,
                        'category': getattr(family, 'category', 'malware') if hasattr(family, 'category') else 'malware'
                    },
                    confidence=0.8,
                    sources={getattr(indicator, 'source', 'unknown')}
                )
        
        return nodes
    
    def _extract_infrastructure_nodes(self, indicator: NormalizedIndicator) -> Dict[str, GraphNode]:
        """Extract infrastructure nodes from indicator."""
        
        nodes = {}
        
        # Extract based on indicator type and enrichment data
        if indicator.indicator_type in {IndicatorType.IP_ADDRESS, IndicatorType.DOMAIN, IndicatorType.URL}:
            # ASN information
            if hasattr(indicator, 'asn') and indicator.asn:
                asn_id = f"asn_{indicator.asn}"
                nodes[asn_id] = GraphNode(
                    node_id=asn_id,
                    node_type=NodeType.INFRASTRUCTURE,
                    value=str(indicator.asn),
                    label=f"ASN: {indicator.asn}",
                    properties={
                        'asn': indicator.asn,
                        'type': 'asn'
                    },
                    confidence=0.9,
                    sources={getattr(indicator, 'source', 'unknown')}
                )
            
            # Geolocation information
            if hasattr(indicator, 'country') and indicator.country:
                country_id = f"country_{indicator.country.lower()}"
                nodes[country_id] = GraphNode(
                    node_id=country_id,
                    node_type=NodeType.INFRASTRUCTURE,
                    value=indicator.country,
                    label=f"Country: {indicator.country}",
                    properties={
                        'country': indicator.country,
                        'type': 'geolocation'
                    },
                    confidence=0.8,
                    sources={getattr(indicator, 'source', 'unknown')}
                )
        
        return nodes


class CorrelationEngine:
    """Main correlation engine for building knowledge graphs."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize correlation engine."""
        self.config = config or {}
        
        # Initialize components
        self.node_extractor = NodeExtractor(
            self.config.get('node_extraction', {})
        )
        
        # Correlation settings
        self.min_relationship_confidence = self.config.get('min_relationship_confidence', 0.3)
        self.enable_temporal_correlation = self.config.get('enable_temporal_correlation', True)
        self.enable_infrastructure_correlation = self.config.get('enable_infrastructure_correlation', True)
        self.enable_technique_correlation = self.config.get('enable_technique_correlation', True)
        
        # Temporal thresholds
        self.temporal_window_hours = self.config.get('temporal_window_hours', 72)
        self.sequential_threshold_minutes = self.config.get('sequential_threshold_minutes', 30)
        
        logger.info("Correlation engine initialized")
    
    def correlate_indicators(self, indicators: List[NormalizedIndicator]) -> CorrelationResult:
        """Perform correlation analysis on indicators."""
        
        start_time = datetime.now(timezone.utc)
        result = CorrelationResult(input_indicators=indicators)
        
        try:
            logger.info(f"Starting correlation analysis for {len(indicators)} indicators")
            
            # Step 1: Extract nodes
            result.nodes = self.node_extractor.extract_nodes(indicators)
            result.node_count = len(result.nodes)
            
            # Step 2: Detect relationships
            result.relationships = self._detect_relationships(result.nodes, indicators)
            result.relationship_count = len(result.relationships)
            
            # Step 3: Build NetworkX graph for analysis
            graph = self._build_networkx_graph(result.nodes, result.relationships)
            
            # Step 4: Compute graph metrics
            self._compute_graph_metrics(graph, result.nodes)
            
            # Step 5: Detect communities
            result.communities = self._detect_communities(graph)
            
            # Step 6: Identify key nodes
            result.key_nodes = self._identify_key_nodes(result.nodes, graph)
            
            # Step 7: Detect attack patterns
            result.attack_patterns = self._detect_attack_patterns(graph, result.nodes, result.relationships)
            
            # Step 8: Calculate graph statistics
            result.density = nx.density(graph) if graph.number_of_nodes() > 1 else 0.0
            
            logger.info(f"Correlation completed: {result.node_count} nodes, {result.relationship_count} relationships")
            
        except Exception as e:
            logger.error(f"Correlation analysis failed: {e}", exc_info=True)
            raise
        
        finally:
            end_time = datetime.now(timezone.utc)
            result.execution_time = (end_time - start_time).total_seconds()
        
        return result
    
    def _detect_relationships(self, 
                           nodes: Dict[str, GraphNode], 
                           indicators: List[NormalizedIndicator]) -> Dict[str, GraphRelationship]:
        """Detect relationships between nodes."""
        
        relationships = {}
        
        # Infrastructure-based relationships
        if self.enable_infrastructure_correlation:
            infra_relationships = self._detect_infrastructure_relationships(nodes, indicators)
            relationships.update(infra_relationships)
        
        # Temporal relationships
        if self.enable_temporal_correlation:
            temporal_relationships = self._detect_temporal_relationships(nodes, indicators)
            relationships.update(temporal_relationships)
        
        # Technique-based relationships
        if self.enable_technique_correlation:
            technique_relationships = self._detect_technique_relationships(nodes, indicators)
            relationships.update(technique_relationships)
        
        # Tag and context-based relationships
        context_relationships = self._detect_context_relationships(nodes, indicators)
        relationships.update(context_relationships)
        
        # Filter by confidence threshold
        filtered_relationships = {
            rid: rel for rid, rel in relationships.items()
            if rel.confidence >= self.min_relationship_confidence
        }
        
        logger.debug(f"Detected {len(filtered_relationships)} relationships (filtered from {len(relationships)})")
        return filtered_relationships
    
    def _detect_infrastructure_relationships(self, 
                                          nodes: Dict[str, GraphNode], 
                                          indicators: List[NormalizedIndicator]) -> Dict[str, GraphRelationship]:
        """Detect infrastructure-based relationships."""
        
        relationships = {}
        
        # Group indicators by ASN
        asn_groups = defaultdict(list)
        country_groups = defaultdict(list)
        
        for indicator in indicators:
            indicator_node_id = f"indicator_{indicator.id}"
            
            if hasattr(indicator, 'asn') and indicator.asn:
                asn_groups[indicator.asn].append(indicator_node_id)
            
            if hasattr(indicator, 'country') and indicator.country:
                country_groups[indicator.country].append(indicator_node_id)
        
        # Create ASN-based relationships
        for asn, indicator_node_ids in asn_groups.items():
            if len(indicator_node_ids) > 1:
                asn_node_id = f"asn_{asn}"
                
                # Connect indicators to ASN node
                for node_id in indicator_node_ids:
                    relationship = GraphRelationship(
                        source_node_id=node_id,
                        target_node_id=asn_node_id,
                        relationship_type=RelationshipType.SHARES_INFRASTRUCTURE,
                        weight=0.8,
                        confidence=0.9,
                        evidence=[{'type': 'asn_match', 'asn': asn}]
                    )
                    relationships[relationship.relationship_id] = relationship
                
                # Connect indicators that share the same ASN
                for i, node_id1 in enumerate(indicator_node_ids):
                    for node_id2 in indicator_node_ids[i+1:]:
                        relationship = GraphRelationship(
                            source_node_id=node_id1,
                            target_node_id=node_id2,
                            relationship_type=RelationshipType.SHARES_INFRASTRUCTURE,
                            weight=0.6,
                            confidence=0.7,
                            evidence=[{'type': 'shared_asn', 'asn': asn}]
                        )
                        relationships[relationship.relationship_id] = relationship
        
        # Create country-based relationships (lower confidence)
        for country, indicator_node_ids in country_groups.items():
            if len(indicator_node_ids) > 1:
                country_node_id = f"country_{country.lower()}"
                
                for node_id in indicator_node_ids:
                    relationship = GraphRelationship(
                        source_node_id=node_id,
                        target_node_id=country_node_id,
                        relationship_type=RelationshipType.SHARES_INFRASTRUCTURE,
                        weight=0.4,
                        confidence=0.5,
                        evidence=[{'type': 'country_match', 'country': country}]
                    )
                    relationships[relationship.relationship_id] = relationship
        
        return relationships
    
    def _detect_temporal_relationships(self, 
                                    nodes: Dict[str, GraphNode], 
                                    indicators: List[NormalizedIndicator]) -> Dict[str, GraphRelationship]:
        """Detect temporal relationships between indicators."""
        
        relationships = {}
        
        # Sort indicators by time
        timed_indicators = []
        for indicator in indicators:
            if hasattr(indicator, 'first_seen') and indicator.first_seen:
                timed_indicators.append((indicator.first_seen, indicator))
        
        timed_indicators.sort(key=lambda x: x[0])
        
        # Detect temporal patterns
        temporal_window = timedelta(hours=self.temporal_window_hours)
        sequential_threshold = timedelta(minutes=self.sequential_threshold_minutes)
        
        for i, (time1, indicator1) in enumerate(timed_indicators):
            node_id1 = f"indicator_{indicator1.id}"
            
            # Look for indicators in temporal window
            for j, (time2, indicator2) in enumerate(timed_indicators[i+1:], i+1):
                time_diff = time2 - time1
                
                if time_diff > temporal_window:
                    break  # Beyond temporal window
                
                node_id2 = f"indicator_{indicator2.id}"
                
                # Determine relationship type based on time difference
                if time_diff <= sequential_threshold:
                    relationship_type = RelationshipType.SEQUENTIAL_ACTIVITY
                    confidence = 0.8
                    weight = 0.9
                else:
                    relationship_type = RelationshipType.OBSERVED_TOGETHER
                    confidence = 0.6
                    weight = 0.7
                
                relationship = GraphRelationship(
                    source_node_id=node_id1,
                    target_node_id=node_id2,
                    relationship_type=relationship_type,
                    weight=weight,
                    confidence=confidence,
                    evidence=[{
                        'type': 'temporal_correlation',
                        'time_diff_minutes': time_diff.total_seconds() / 60,
                        'first_seen_1': time1.isoformat(),
                        'first_seen_2': time2.isoformat()
                    }],
                    first_observed=time1,
                    last_observed=time2
                )
                
                relationships[relationship.relationship_id] = relationship
        
        return relationships
    
    def _detect_technique_relationships(self, 
                                     nodes: Dict[str, GraphNode], 
                                     indicators: List[NormalizedIndicator]) -> Dict[str, GraphRelationship]:
        """Detect technique-based relationships."""
        
        relationships = {}
        
        # Group indicators by techniques
        technique_groups = defaultdict(list)
        
        for indicator in indicators:
            indicator_node_id = f"indicator_{indicator.id}"
            
            if hasattr(indicator, 'techniques') and indicator.techniques:
                for technique in indicator.techniques:
                    technique_id = technique if isinstance(technique, str) else technique.get('id', str(technique))
                    technique_groups[technique_id].append(indicator_node_id)
        
        # Create technique-based relationships
        for technique_id, indicator_node_ids in technique_groups.items():
            technique_node_id = f"technique_{technique_id}"
            
            # Connect indicators to technique node
            for node_id in indicator_node_ids:
                relationship = GraphRelationship(
                    source_node_id=node_id,
                    target_node_id=technique_node_id,
                    relationship_type=RelationshipType.USES_TECHNIQUE,
                    weight=0.8,
                    confidence=0.8,
                    evidence=[{'type': 'technique_usage', 'technique_id': technique_id}]
                )
                relationships[relationship.relationship_id] = relationship
            
            # Connect indicators that use the same technique
            if len(indicator_node_ids) > 1:
                for i, node_id1 in enumerate(indicator_node_ids):
                    for node_id2 in indicator_node_ids[i+1:]:
                        relationship = GraphRelationship(
                            source_node_id=node_id1,
                            target_node_id=node_id2,
                            relationship_type=RelationshipType.USES_SAME_TTP,
                            weight=0.6,
                            confidence=0.7,
                            evidence=[{'type': 'shared_technique', 'technique_id': technique_id}]
                        )
                        relationships[relationship.relationship_id] = relationship
        
        return relationships
    
    def _detect_context_relationships(self, 
                                   nodes: Dict[str, GraphNode], 
                                   indicators: List[NormalizedIndicator]) -> Dict[str, GraphRelationship]:
        """Detect context-based relationships from tags and metadata."""
        
        relationships = {}
        
        # Group indicators by malware families
        malware_groups = defaultdict(list)
        tag_groups = defaultdict(list)
        
        for indicator in indicators:
            indicator_node_id = f"indicator_{indicator.id}"
            
            # Malware family relationships
            if hasattr(indicator, 'malware_families') and indicator.malware_families:
                for family in indicator.malware_families:
                    family_name = family if isinstance(family, str) else family.get('name', str(family))
                    malware_groups[family_name].append(indicator_node_id)
            
            # Tag-based relationships
            if hasattr(indicator, 'tags') and indicator.tags:
                for tag in indicator.tags:
                    tag_groups[tag].append(indicator_node_id)
        
        # Create malware family relationships
        for family_name, indicator_node_ids in malware_groups.items():
            malware_node_id = f"malware_{family_name.lower().replace(' ', '_')}"
            
            # Connect indicators to malware family
            for node_id in indicator_node_ids:
                relationship = GraphRelationship(
                    source_node_id=node_id,
                    target_node_id=malware_node_id,
                    relationship_type=RelationshipType.SAME_FAMILY,
                    weight=0.9,
                    confidence=0.8,
                    evidence=[{'type': 'malware_family', 'family': family_name}]
                )
                relationships[relationship.relationship_id] = relationship
            
            # Connect indicators in same family
            if len(indicator_node_ids) > 1:
                for i, node_id1 in enumerate(indicator_node_ids):
                    for node_id2 in indicator_node_ids[i+1:]:
                        relationship = GraphRelationship(
                            source_node_id=node_id1,
                            target_node_id=node_id2,
                            relationship_type=RelationshipType.SAME_FAMILY,
                            weight=0.7,
                            confidence=0.7,
                            evidence=[{'type': 'shared_malware_family', 'family': family_name}]
                        )
                        relationships[relationship.relationship_id] = relationship
        
        # Create high-value tag relationships (selective)
        important_tags = ['apt', 'targeted', 'campaign', 'c2', 'exfil', 'lateral', 'persistence']
        
        for tag, indicator_node_ids in tag_groups.items():
            if tag.lower() in important_tags and len(indicator_node_ids) > 1:
                for i, node_id1 in enumerate(indicator_node_ids):
                    for node_id2 in indicator_node_ids[i+1:]:
                        relationship = GraphRelationship(
                            source_node_id=node_id1,
                            target_node_id=node_id2,
                            relationship_type=RelationshipType.SIMILAR_TO,
                            weight=0.5,
                            confidence=0.6,
                            evidence=[{'type': 'shared_tag', 'tag': tag}]
                        )
                        relationships[relationship.relationship_id] = relationship
        
        return relationships
    
    def _build_networkx_graph(self, 
                            nodes: Dict[str, GraphNode], 
                            relationships: Dict[str, GraphRelationship]) -> nx.Graph:
        """Build NetworkX graph for analysis."""
        
        graph = nx.Graph()
        
        # Add nodes
        for node_id, node in nodes.items():
            graph.add_node(
                node_id,
                node_type=node.node_type.value,
                label=node.label,
                confidence=node.confidence,
                **node.properties
            )
        
        # Add edges
        for relationship in relationships.values():
            graph.add_edge(
                relationship.source_node_id,
                relationship.target_node_id,
                relationship_type=relationship.relationship_type.value,
                weight=relationship.weight,
                confidence=relationship.confidence
            )
        
        return graph
    
    def _compute_graph_metrics(self, graph: nx.Graph, nodes: Dict[str, GraphNode]):
        """Compute centrality and other graph metrics."""
        
        if graph.number_of_nodes() < 2:
            return
        
        try:
            # Compute centrality measures
            betweenness = nx.betweenness_centrality(graph, weight='weight')
            closeness = nx.closeness_centrality(graph, distance='weight')
            degree = nx.degree_centrality(graph)
            
            if graph.number_of_nodes() >= 3:
                eigenvector = nx.eigenvector_centrality(graph, weight='weight', max_iter=1000)
            else:
                eigenvector = {node: 0.0 for node in graph.nodes()}
            
            # Update node objects
            for node_id in graph.nodes():
                if node_id in nodes:
                    nodes[node_id].centrality_scores = {
                        'betweenness': betweenness.get(node_id, 0.0),
                        'closeness': closeness.get(node_id, 0.0),
                        'degree': degree.get(node_id, 0.0),
                        'eigenvector': eigenvector.get(node_id, 0.0)
                    }
        
        except Exception as e:
            logger.warning(f"Failed to compute centrality metrics: {e}")
    
    def _detect_communities(self, graph: nx.Graph) -> Dict[str, List[str]]:
        """Detect communities in the graph."""
        
        communities = {}
        
        if graph.number_of_nodes() < 3:
            return communities
        
        try:
            # Use Louvain community detection
            import networkx.algorithms.community as nx_comm
            
            community_sets = nx_comm.louvain_communities(graph, weight='weight', seed=42)
            
            for i, community in enumerate(community_sets):
                community_id = f"community_{i}"
                communities[community_id] = list(community)
        
        except Exception as e:
            logger.warning(f"Failed to detect communities: {e}")
        
        return communities
    
    def _identify_key_nodes(self, nodes: Dict[str, GraphNode], graph: nx.Graph) -> List[str]:
        """Identify key nodes based on centrality measures."""
        
        key_nodes = []
        
        if not nodes:
            return key_nodes
        
        try:
            # Sort nodes by combined centrality score
            node_scores = []
            
            for node_id, node in nodes.items():
                if node.centrality_scores:
                    # Combined score weighted by node type importance
                    type_weight = {
                        NodeType.INDICATOR: 1.0,
                        NodeType.TECHNIQUE: 1.5,
                        NodeType.CVE: 1.3,
                        NodeType.MALWARE_FAMILY: 1.4,
                        NodeType.INFRASTRUCTURE: 1.2
                    }.get(node.node_type, 1.0)
                    
                    combined_score = (
                        node.centrality_scores.get('betweenness', 0) * 0.3 +
                        node.centrality_scores.get('degree', 0) * 0.4 +
                        node.centrality_scores.get('eigenvector', 0) * 0.3
                    ) * type_weight * node.confidence
                    
                    node_scores.append((node_id, combined_score))
            
            # Sort by score and take top nodes
            node_scores.sort(key=lambda x: x[1], reverse=True)
            key_nodes = [node_id for node_id, _ in node_scores[:10]]
        
        except Exception as e:
            logger.warning(f"Failed to identify key nodes: {e}")
        
        return key_nodes
    
    def _detect_attack_patterns(self, 
                              graph: nx.Graph, 
                              nodes: Dict[str, GraphNode], 
                              relationships: Dict[str, GraphRelationship]) -> List[Dict[str, Any]]:
        """Detect attack patterns in the graph."""
        
        patterns = []
        
        try:
            # Pattern 1: Infrastructure sharing with temporal correlation
            infra_temporal_patterns = self._find_infrastructure_temporal_patterns(
                graph, nodes, relationships
            )
            patterns.extend(infra_temporal_patterns)
            
            # Pattern 2: Multi-stage attack chains
            attack_chain_patterns = self._find_attack_chain_patterns(
                graph, nodes, relationships
            )
            patterns.extend(attack_chain_patterns)
            
            # Pattern 3: Campaign clusters
            campaign_patterns = self._find_campaign_patterns(
                graph, nodes, relationships
            )
            patterns.extend(campaign_patterns)
        
        except Exception as e:
            logger.warning(f"Failed to detect attack patterns: {e}")
        
        return patterns
    
    def _find_infrastructure_temporal_patterns(self, 
                                             graph: nx.Graph, 
                                             nodes: Dict[str, GraphNode], 
                                             relationships: Dict[str, GraphRelationship]) -> List[Dict[str, Any]]:
        """Find patterns of infrastructure sharing with temporal correlation."""
        
        patterns = []
        
        # Find nodes that share infrastructure AND have temporal relationships
        for rel_id, rel in relationships.items():
            if (rel.relationship_type == RelationshipType.SHARES_INFRASTRUCTURE and
                rel.confidence > 0.7):
                
                # Look for temporal relationships between the same nodes
                temporal_rels = [
                    r for r in relationships.values()
                    if ((r.source_node_id == rel.source_node_id and r.target_node_id == rel.target_node_id) or
                        (r.source_node_id == rel.target_node_id and r.target_node_id == rel.source_node_id)) and
                    r.relationship_type in {RelationshipType.OBSERVED_TOGETHER, RelationshipType.SEQUENTIAL_ACTIVITY}
                ]
                
                if temporal_rels:
                    pattern = {
                        'pattern_type': 'infrastructure_temporal',
                        'description': 'Indicators sharing infrastructure with temporal correlation',
                        'confidence': (rel.confidence + max(tr.confidence for tr in temporal_rels)) / 2,
                        'nodes': [rel.source_node_id, rel.target_node_id],
                        'evidence': {
                            'infrastructure_relationship': rel.to_dict(),
                            'temporal_relationships': [tr.to_dict() for tr in temporal_rels]
                        }
                    }
                    patterns.append(pattern)
        
        return patterns
    
    def _find_attack_chain_patterns(self, 
                                  graph: nx.Graph, 
                                  nodes: Dict[str, GraphNode], 
                                  relationships: Dict[str, GraphRelationship]) -> List[Dict[str, Any]]:
        """Find multi-stage attack chain patterns."""
        
        patterns = []
        
        # Find sequences of sequential activity relationships
        sequential_rels = [
            rel for rel in relationships.values()
            if rel.relationship_type == RelationshipType.SEQUENTIAL_ACTIVITY
        ]
        
        # Group by temporal chains
        chains = []
        for rel in sequential_rels:
            # Try to extend existing chains
            extended = False
            for chain in chains:
                if chain[-1]['target'] == rel.source_node_id:
                    chain.append({
                        'source': rel.source_node_id,
                        'target': rel.target_node_id,
                        'relationship': rel
                    })
                    extended = True
                    break
            
            if not extended:
                chains.append([{
                    'source': rel.source_node_id,
                    'target': rel.target_node_id,
                    'relationship': rel
                }])
        
        # Convert long chains to patterns
        for chain in chains:
            if len(chain) >= 3:  # At least 3 stages
                pattern = {
                    'pattern_type': 'attack_chain',
                    'description': f'Multi-stage attack chain with {len(chain)} stages',
                    'confidence': statistics.mean(step['relationship'].confidence for step in chain),
                    'nodes': [step['source'] for step in chain] + [chain[-1]['target']],
                    'stages': len(chain),
                    'evidence': {
                        'chain_steps': [step['relationship'].to_dict() for step in chain]
                    }
                }
                patterns.append(pattern)
        
        return patterns
    
    def _find_campaign_patterns(self, 
                              graph: nx.Graph, 
                              nodes: Dict[str, GraphNode], 
                              relationships: Dict[str, GraphRelationship]) -> List[Dict[str, Any]]:
        """Find campaign-like patterns."""
        
        patterns = []
        
        # Find densely connected subgraphs that might represent campaigns
        try:
            # Find nodes with high connectivity
            if graph.number_of_nodes() >= 5:
                # Use k-clique communities
                import networkx.algorithms.community as nx_comm
                
                cliques = list(nx_comm.k_clique_communities(graph, 3))
                
                for i, clique in enumerate(cliques):
                    if len(clique) >= 4:  # Significant size
                        # Calculate average relationship confidence
                        clique_relationships = []
                        for node1 in clique:
                            for node2 in clique:
                                if node1 != node2 and graph.has_edge(node1, node2):
                                    # Find the relationship
                                    for rel in relationships.values():
                                        if ((rel.source_node_id == node1 and rel.target_node_id == node2) or
                                            (rel.source_node_id == node2 and rel.target_node_id == node1)):
                                            clique_relationships.append(rel)
                                            break
                        
                        if clique_relationships:
                            avg_confidence = statistics.mean(rel.confidence for rel in clique_relationships)
                            
                            pattern = {
                                'pattern_type': 'campaign_cluster',
                                'description': f'Dense cluster of {len(clique)} related indicators',
                                'confidence': avg_confidence,
                                'nodes': list(clique),
                                'cluster_size': len(clique),
                                'evidence': {
                                    'relationships': [rel.to_dict() for rel in clique_relationships]
                                }
                            }
                            patterns.append(pattern)
        
        except Exception as e:
            logger.debug(f"Failed to find campaign patterns: {e}")
        
        return patterns