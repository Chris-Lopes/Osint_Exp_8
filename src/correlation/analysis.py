"""
Advanced graph analysis algorithms for threat intelligence knowledge graphs.

This module implements sophisticated graph analysis capabilities including
community detection, centrality analysis, path analysis, and attack pattern
identification to extract insights from threat intelligence correlation networks.
"""

import logging
import statistics
import math
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any, Optional, Set, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, Counter, deque
import heapq

try:
    import networkx as nx
    HAS_NETWORKX = True
except ImportError:
    HAS_NETWORKX = False
    nx = None

try:
    from ..normalizers.schema import NormalizedIndicator, IndicatorType
    from .engine import GraphNode, GraphRelationship, NodeType, RelationshipType, CorrelationResult
except ImportError:
    from normalizers.schema import NormalizedIndicator, IndicatorType
    from correlation.engine import GraphNode, GraphRelationship, NodeType, RelationshipType, CorrelationResult

logger = logging.getLogger(__name__)


class CentralityType(Enum):
    """Types of centrality measures."""
    DEGREE = "degree"
    BETWEENNESS = "betweenness"
    CLOSENESS = "closeness"
    EIGENVECTOR = "eigenvector"
    PAGERANK = "pagerank"
    KATZ = "katz"


class CommunityAlgorithm(Enum):
    """Community detection algorithms."""
    LOUVAIN = "louvain"
    LEIDEN = "leiden"
    MODULARITY_MAXIMIZATION = "modularity_maximization"
    LABEL_PROPAGATION = "label_propagation"
    EDGE_BETWEENNESS = "edge_betweenness"


@dataclass
class CentralityResult:
    """Result of centrality analysis."""
    
    centrality_type: CentralityType
    node_scores: Dict[str, float] = field(default_factory=dict)
    
    # Statistics
    mean_score: float = 0.0
    median_score: float = 0.0
    std_score: float = 0.0
    max_score: float = 0.0
    min_score: float = 0.0
    
    # Top nodes
    top_nodes: List[Tuple[str, float]] = field(default_factory=list)
    
    # Execution metadata
    execution_time: float = 0.0
    algorithm_parameters: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'centrality_type': self.centrality_type.value,
            'node_scores': self.node_scores,
            'statistics': {
                'mean_score': self.mean_score,
                'median_score': self.median_score,
                'std_score': self.std_score,
                'max_score': self.max_score,
                'min_score': self.min_score
            },
            'top_nodes': self.top_nodes,
            'execution_time': self.execution_time,
            'algorithm_parameters': self.algorithm_parameters
        }


@dataclass
class CommunityResult:
    """Result of community detection."""
    
    algorithm: CommunityAlgorithm
    communities: Dict[str, List[str]] = field(default_factory=dict)  # community_id -> node_ids
    node_communities: Dict[str, str] = field(default_factory=dict)   # node_id -> community_id
    
    # Quality metrics
    modularity: float = 0.0
    conductance: Dict[str, float] = field(default_factory=dict)
    
    # Statistics
    community_count: int = 0
    largest_community_size: int = 0
    smallest_community_size: int = 0
    average_community_size: float = 0.0
    
    # Execution metadata
    execution_time: float = 0.0
    algorithm_parameters: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'algorithm': self.algorithm.value,
            'communities': self.communities,
            'node_communities': self.node_communities,
            'quality_metrics': {
                'modularity': self.modularity,
                'conductance': self.conductance
            },
            'statistics': {
                'community_count': self.community_count,
                'largest_community_size': self.largest_community_size,
                'smallest_community_size': self.smallest_community_size,
                'average_community_size': self.average_community_size
            },
            'execution_time': self.execution_time,
            'algorithm_parameters': self.algorithm_parameters
        }


@dataclass
class PathAnalysisResult:
    """Result of path analysis."""
    
    source_node_id: str
    target_node_id: str
    
    # Paths found
    shortest_path: List[str] = field(default_factory=list)
    shortest_path_length: int = 0
    all_shortest_paths: List[List[str]] = field(default_factory=list)
    
    # Path properties
    path_weights: List[float] = field(default_factory=list)
    path_confidence: float = 0.0
    
    # Intermediate analysis
    bottleneck_nodes: List[str] = field(default_factory=list)
    critical_relationships: List[str] = field(default_factory=list)
    
    # Execution metadata
    execution_time: float = 0.0
    max_path_length: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'source_node_id': self.source_node_id,
            'target_node_id': self.target_node_id,
            'shortest_path': self.shortest_path,
            'shortest_path_length': self.shortest_path_length,
            'all_shortest_paths': self.all_shortest_paths,
            'path_properties': {
                'path_weights': self.path_weights,
                'path_confidence': self.path_confidence
            },
            'critical_elements': {
                'bottleneck_nodes': self.bottleneck_nodes,
                'critical_relationships': self.critical_relationships
            },
            'execution_time': self.execution_time,
            'max_path_length': self.max_path_length
        }


@dataclass
class AttackPatternResult:
    """Result of attack pattern analysis."""
    
    pattern_id: str = field(default_factory=lambda: f"pattern_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}")
    pattern_type: str = ""
    description: str = ""
    
    # Pattern elements
    involved_nodes: List[str] = field(default_factory=list)
    involved_relationships: List[str] = field(default_factory=list)
    
    # Pattern characteristics
    confidence: float = 0.0
    complexity: int = 0
    temporal_span: Optional[timedelta] = None
    
    # Attack chain information
    attack_stages: List[Dict[str, Any]] = field(default_factory=list)
    kill_chain_phases: List[str] = field(default_factory=list)
    
    # Evidence and attribution
    evidence_strength: float = 0.0
    attribution_indicators: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'pattern_id': self.pattern_id,
            'pattern_type': self.pattern_type,
            'description': self.description,
            'involved_nodes': self.involved_nodes,
            'involved_relationships': self.involved_relationships,
            'characteristics': {
                'confidence': self.confidence,
                'complexity': self.complexity,
                'temporal_span': self.temporal_span.total_seconds() if self.temporal_span else None
            },
            'attack_chain': {
                'attack_stages': self.attack_stages,
                'kill_chain_phases': self.kill_chain_phases
            },
            'attribution': {
                'evidence_strength': self.evidence_strength,
                'attribution_indicators': self.attribution_indicators
            }
        }


class CentralityAnalyzer:
    """Analyzes node centrality in knowledge graphs."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize centrality analyzer."""
        self.config = config or {}
        
        # Analysis settings
        self.top_n_nodes = self.config.get('top_n_nodes', 20)
        self.normalize_scores = self.config.get('normalize_scores', True)
        
        logger.debug("Centrality analyzer initialized")
    
    def analyze_centrality(self, 
                         nodes: Dict[str, GraphNode],
                         relationships: Dict[str, GraphRelationship],
                         centrality_type: CentralityType = CentralityType.DEGREE) -> CentralityResult:
        """Analyze node centrality."""
        
        start_time = datetime.now(timezone.utc)
        
        if HAS_NETWORKX:
            result = self._analyze_centrality_networkx(nodes, relationships, centrality_type)
        else:
            result = self._analyze_centrality_custom(nodes, relationships, centrality_type)
        
        # Calculate statistics
        if result.node_scores:
            scores = list(result.node_scores.values())
            result.mean_score = statistics.mean(scores)
            result.median_score = statistics.median(scores)
            result.std_score = statistics.stdev(scores) if len(scores) > 1 else 0.0
            result.max_score = max(scores)
            result.min_score = min(scores)
            
            # Get top nodes
            sorted_nodes = sorted(result.node_scores.items(), key=lambda x: x[1], reverse=True)
            result.top_nodes = sorted_nodes[:self.top_n_nodes]
        
        result.execution_time = (datetime.now(timezone.utc) - start_time).total_seconds()
        
        logger.debug(f"Centrality analysis completed: {centrality_type.value}, {len(result.node_scores)} nodes")
        return result
    
    def _analyze_centrality_networkx(self, 
                                   nodes: Dict[str, GraphNode],
                                   relationships: Dict[str, GraphRelationship],
                                   centrality_type: CentralityType) -> CentralityResult:
        """Analyze centrality using NetworkX."""
        
        # Build NetworkX graph
        G = nx.Graph()
        
        # Add nodes
        for node_id in nodes.keys():
            G.add_node(node_id)
        
        # Add edges with weights
        for rel in relationships.values():
            G.add_edge(rel.source_node_id, rel.target_node_id, weight=rel.weight)
        
        # Calculate centrality
        result = CentralityResult(centrality_type=centrality_type)
        
        try:
            if centrality_type == CentralityType.DEGREE:
                centrality = nx.degree_centrality(G)
            elif centrality_type == CentralityType.BETWEENNESS:
                centrality = nx.betweenness_centrality(G, weight='weight')
            elif centrality_type == CentralityType.CLOSENESS:
                centrality = nx.closeness_centrality(G, distance='weight')
            elif centrality_type == CentralityType.EIGENVECTOR:
                centrality = nx.eigenvector_centrality(G, weight='weight', max_iter=1000)
            elif centrality_type == CentralityType.PAGERANK:
                centrality = nx.pagerank(G, weight='weight')
            elif centrality_type == CentralityType.KATZ:
                centrality = nx.katz_centrality(G, weight='weight')
            else:
                raise ValueError(f"Unsupported centrality type: {centrality_type}")
            
            result.node_scores = centrality
            
        except Exception as e:
            logger.warning(f"NetworkX centrality calculation failed: {e}")
            # Fall back to custom implementation
            return self._analyze_centrality_custom(nodes, relationships, centrality_type)
        
        return result
    
    def _analyze_centrality_custom(self, 
                                 nodes: Dict[str, GraphNode],
                                 relationships: Dict[str, GraphRelationship],
                                 centrality_type: CentralityType) -> CentralityResult:
        """Custom centrality implementation (fallback)."""
        
        result = CentralityResult(centrality_type=centrality_type)
        
        # Build adjacency structure
        adjacency = defaultdict(list)
        node_degrees = defaultdict(int)
        
        for rel in relationships.values():
            adjacency[rel.source_node_id].append((rel.target_node_id, rel.weight))
            adjacency[rel.target_node_id].append((rel.source_node_id, rel.weight))
            node_degrees[rel.source_node_id] += 1
            node_degrees[rel.target_node_id] += 1
        
        # Calculate degree centrality (custom implementation)
        if centrality_type == CentralityType.DEGREE:
            max_degree = max(node_degrees.values()) if node_degrees else 1
            
            for node_id in nodes.keys():
                degree = node_degrees.get(node_id, 0)
                normalized_degree = degree / max_degree if self.normalize_scores and max_degree > 0 else degree
                result.node_scores[node_id] = normalized_degree
        
        # For other centrality types, use simplified approximations
        elif centrality_type == CentralityType.BETWEENNESS:
            # Simplified betweenness (based on local bridging)
            for node_id in nodes.keys():
                neighbors = [n for n, _ in adjacency[node_id]]
                if len(neighbors) <= 1:
                    result.node_scores[node_id] = 0.0
                else:
                    # Count neighbor-neighbor connections
                    neighbor_connections = 0
                    for i, n1 in enumerate(neighbors):
                        for n2 in neighbors[i+1:]:
                            if n2 in [nn for nn, _ in adjacency[n1]]:
                                neighbor_connections += 1
                    
                    max_connections = len(neighbors) * (len(neighbors) - 1) // 2
                    bridging_score = 1.0 - (neighbor_connections / max_connections if max_connections > 0 else 0)
                    result.node_scores[node_id] = bridging_score
        
        else:
            # Default to degree centrality for unsupported types
            logger.warning(f"Centrality type {centrality_type} not supported in custom implementation, using degree")
            return self._analyze_centrality_custom(nodes, relationships, CentralityType.DEGREE)
        
        return result
    
    def analyze_all_centralities(self, 
                               nodes: Dict[str, GraphNode],
                               relationships: Dict[str, GraphRelationship]) -> Dict[str, CentralityResult]:
        """Analyze multiple centrality measures."""
        
        centrality_types = [
            CentralityType.DEGREE,
            CentralityType.BETWEENNESS,
            CentralityType.CLOSENESS,
            CentralityType.EIGENVECTOR
        ]
        
        results = {}
        
        for centrality_type in centrality_types:
            try:
                result = self.analyze_centrality(nodes, relationships, centrality_type)
                results[centrality_type.value] = result
            except Exception as e:
                logger.warning(f"Failed to calculate {centrality_type.value} centrality: {e}")
        
        return results


class CommunityDetector:
    """Detects communities in knowledge graphs."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize community detector."""
        self.config = config or {}
        
        # Detection settings
        self.min_community_size = self.config.get('min_community_size', 3)
        self.resolution = self.config.get('resolution', 1.0)
        
        logger.debug("Community detector initialized")
    
    def detect_communities(self, 
                         nodes: Dict[str, GraphNode],
                         relationships: Dict[str, GraphRelationship],
                         algorithm: CommunityAlgorithm = CommunityAlgorithm.LOUVAIN) -> CommunityResult:
        """Detect communities in the graph."""
        
        start_time = datetime.now(timezone.utc)
        
        if HAS_NETWORKX:
            result = self._detect_communities_networkx(nodes, relationships, algorithm)
        else:
            result = self._detect_communities_custom(nodes, relationships, algorithm)
        
        # Calculate statistics
        if result.communities:
            community_sizes = [len(community) for community in result.communities.values()]
            result.community_count = len(result.communities)
            result.largest_community_size = max(community_sizes)
            result.smallest_community_size = min(community_sizes)
            result.average_community_size = statistics.mean(community_sizes)
        
        result.execution_time = (datetime.now(timezone.utc) - start_time).total_seconds()
        
        logger.debug(f"Community detection completed: {algorithm.value}, {result.community_count} communities")
        return result
    
    def _detect_communities_networkx(self, 
                                   nodes: Dict[str, GraphNode],
                                   relationships: Dict[str, GraphRelationship],
                                   algorithm: CommunityAlgorithm) -> CommunityResult:
        """Detect communities using NetworkX."""
        
        # Build NetworkX graph
        G = nx.Graph()
        
        # Add nodes
        for node_id in nodes.keys():
            G.add_node(node_id)
        
        # Add edges
        for rel in relationships.values():
            G.add_edge(rel.source_node_id, rel.target_node_id, weight=rel.weight)
        
        result = CommunityResult(algorithm=algorithm)
        
        try:
            import networkx.algorithms.community as nx_comm
            
            if algorithm == CommunityAlgorithm.LOUVAIN:
                communities = nx_comm.louvain_communities(G, weight='weight', resolution=self.resolution, seed=42)
            elif algorithm == CommunityAlgorithm.LABEL_PROPAGATION:
                communities = nx_comm.label_propagation_communities(G, weight='weight', seed=42)
            elif algorithm == CommunityAlgorithm.EDGE_BETWEENNESS:
                # Use hierarchical clustering based on edge betweenness
                communities = nx_comm.girvan_newman(G)
                communities = next(communities)  # Take first level
            else:
                raise ValueError(f"Unsupported community algorithm: {algorithm}")
            
            # Convert to our format
            for i, community in enumerate(communities):
                if len(community) >= self.min_community_size:
                    community_id = f"community_{i}"
                    result.communities[community_id] = list(community)
                    
                    for node_id in community:
                        result.node_communities[node_id] = community_id
            
            # Calculate modularity
            if result.communities:
                community_list = [set(community) for community in result.communities.values()]
                result.modularity = nx_comm.modularity(G, community_list, weight='weight')
            
        except Exception as e:
            logger.warning(f"NetworkX community detection failed: {e}")
            return self._detect_communities_custom(nodes, relationships, algorithm)
        
        return result
    
    def _detect_communities_custom(self, 
                                 nodes: Dict[str, GraphNode],
                                 relationships: Dict[str, GraphRelationship],
                                 algorithm: CommunityAlgorithm) -> CommunityResult:
        """Custom community detection implementation."""
        
        result = CommunityResult(algorithm=algorithm)
        
        # Build adjacency structure
        adjacency = defaultdict(set)
        
        for rel in relationships.values():
            adjacency[rel.source_node_id].add(rel.target_node_id)
            adjacency[rel.target_node_id].add(rel.source_node_id)
        
        # Simple label propagation algorithm
        node_labels = {node_id: i for i, node_id in enumerate(nodes.keys())}
        
        # Iterate until convergence
        max_iterations = 100
        for iteration in range(max_iterations):
            changes = 0
            
            for node_id in nodes.keys():
                neighbors = adjacency[node_id]
                if not neighbors:
                    continue
                
                # Count neighbor labels
                label_counts = Counter()
                for neighbor in neighbors:
                    label_counts[node_labels[neighbor]] += 1
                
                # Choose most frequent label
                if label_counts:
                    most_common_label = label_counts.most_common(1)[0][0]
                    if node_labels[node_id] != most_common_label:
                        node_labels[node_id] = most_common_label
                        changes += 1
            
            if changes == 0:
                break
        
        # Convert labels to communities
        label_to_community = defaultdict(list)
        for node_id, label in node_labels.items():
            label_to_community[label].append(node_id)
        
        # Create communities
        for i, (label, node_list) in enumerate(label_to_community.items()):
            if len(node_list) >= self.min_community_size:
                community_id = f"community_{i}"
                result.communities[community_id] = node_list
                
                for node_id in node_list:
                    result.node_communities[node_id] = community_id
        
        return result


class PathAnalyzer:
    """Analyzes paths in knowledge graphs."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize path analyzer."""
        self.config = config or {}
        
        # Path analysis settings
        self.max_path_length = self.config.get('max_path_length', 10)
        self.max_paths_to_find = self.config.get('max_paths_to_find', 5)
        
        logger.debug("Path analyzer initialized")
    
    def find_shortest_path(self, 
                          nodes: Dict[str, GraphNode],
                          relationships: Dict[str, GraphRelationship],
                          source_node_id: str,
                          target_node_id: str) -> PathAnalysisResult:
        """Find shortest path between two nodes."""
        
        start_time = datetime.now(timezone.utc)
        
        if HAS_NETWORKX:
            result = self._find_path_networkx(nodes, relationships, source_node_id, target_node_id)
        else:
            result = self._find_path_custom(nodes, relationships, source_node_id, target_node_id)
        
        result.execution_time = (datetime.now(timezone.utc) - start_time).total_seconds()
        result.max_path_length = self.max_path_length
        
        logger.debug(f"Path analysis completed: {source_node_id} -> {target_node_id}, length: {result.shortest_path_length}")
        return result
    
    def _find_path_networkx(self, 
                          nodes: Dict[str, GraphNode],
                          relationships: Dict[str, GraphRelationship],
                          source_node_id: str,
                          target_node_id: str) -> PathAnalysisResult:
        """Find path using NetworkX."""
        
        # Build NetworkX graph
        G = nx.Graph()
        
        # Add nodes
        for node_id in nodes.keys():
            G.add_node(node_id)
        
        # Add edges
        for rel in relationships.values():
            G.add_edge(rel.source_node_id, rel.target_node_id, weight=1/rel.weight)  # Invert for shortest path
        
        result = PathAnalysisResult(
            source_node_id=source_node_id,
            target_node_id=target_node_id
        )
        
        try:
            # Find shortest path
            if nx.has_path(G, source_node_id, target_node_id):
                shortest_path = nx.shortest_path(G, source_node_id, target_node_id, weight='weight')
                result.shortest_path = shortest_path
                result.shortest_path_length = len(shortest_path) - 1
                
                # Find all shortest paths (up to limit)
                all_paths = list(nx.all_shortest_paths(G, source_node_id, target_node_id, weight='weight'))
                result.all_shortest_paths = all_paths[:self.max_paths_to_find]
                
                # Calculate path properties
                if result.shortest_path:
                    result.path_weights, result.path_confidence = self._calculate_path_properties(
                        result.shortest_path, relationships
                    )
                
                # Identify bottleneck nodes
                result.bottleneck_nodes = self._identify_bottleneck_nodes(
                    G, source_node_id, target_node_id, result.all_shortest_paths
                )
        
        except Exception as e:
            logger.warning(f"NetworkX path analysis failed: {e}")
            return self._find_path_custom(nodes, relationships, source_node_id, target_node_id)
        
        return result
    
    def _find_path_custom(self, 
                        nodes: Dict[str, GraphNode],
                        relationships: Dict[str, GraphRelationship],
                        source_node_id: str,
                        target_node_id: str) -> PathAnalysisResult:
        """Custom path finding implementation using BFS."""
        
        # Build adjacency structure
        adjacency = defaultdict(list)
        
        for rel in relationships.values():
            adjacency[rel.source_node_id].append((rel.target_node_id, rel.weight))
            adjacency[rel.target_node_id].append((rel.source_node_id, rel.weight))
        
        result = PathAnalysisResult(
            source_node_id=source_node_id,
            target_node_id=target_node_id
        )
        
        # BFS to find shortest path
        queue = deque([(source_node_id, [source_node_id])])
        visited = set()
        
        while queue:
            current_node, path = queue.popleft()
            
            if current_node == target_node_id:
                result.shortest_path = path
                result.shortest_path_length = len(path) - 1
                break
            
            if current_node in visited or len(path) > self.max_path_length:
                continue
            
            visited.add(current_node)
            
            for neighbor, weight in adjacency[current_node]:
                if neighbor not in visited:
                    new_path = path + [neighbor]
                    queue.append((neighbor, new_path))
        
        # Calculate path properties if path found
        if result.shortest_path:
            result.path_weights, result.path_confidence = self._calculate_path_properties(
                result.shortest_path, relationships
            )
        
        return result
    
    def _calculate_path_properties(self, 
                                 path: List[str], 
                                 relationships: Dict[str, GraphRelationship]) -> Tuple[List[float], float]:
        """Calculate properties of a path."""
        
        path_weights = []
        confidences = []
        
        # Build relationship lookup
        rel_lookup = {}
        for rel in relationships.values():
            key1 = (rel.source_node_id, rel.target_node_id)
            key2 = (rel.target_node_id, rel.source_node_id)
            rel_lookup[key1] = rel
            rel_lookup[key2] = rel
        
        # Calculate weights and confidences for each edge in path
        for i in range(len(path) - 1):
            node1, node2 = path[i], path[i + 1]
            key = (node1, node2)
            
            if key in rel_lookup:
                rel = rel_lookup[key]
                path_weights.append(rel.weight)
                confidences.append(rel.confidence)
            else:
                path_weights.append(0.0)
                confidences.append(0.0)
        
        # Calculate overall path confidence
        if confidences:
            path_confidence = statistics.mean(confidences)
        else:
            path_confidence = 0.0
        
        return path_weights, path_confidence
    
    def _identify_bottleneck_nodes(self, 
                                 graph, 
                                 source_node_id: str, 
                                 target_node_id: str,
                                 all_paths: List[List[str]]) -> List[str]:
        """Identify bottleneck nodes in paths."""
        
        if not all_paths:
            return []
        
        # Count how often each node appears in paths (excluding source and target)
        node_counts = Counter()
        
        for path in all_paths:
            for node in path[1:-1]:  # Exclude source and target
                node_counts[node] += 1
        
        # Nodes that appear in all or most paths are bottlenecks
        total_paths = len(all_paths)
        bottleneck_threshold = total_paths * 0.8  # 80% of paths
        
        bottlenecks = [
            node for node, count in node_counts.items()
            if count >= bottleneck_threshold
        ]
        
        return bottlenecks


class AttackPatternDetector:
    """Detects attack patterns in knowledge graphs."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize attack pattern detector."""
        self.config = config or {}
        
        # Detection settings
        self.min_pattern_confidence = self.config.get('min_pattern_confidence', 0.6)
        self.min_pattern_nodes = self.config.get('min_pattern_nodes', 3)
        
        # Kill chain phases
        self.kill_chain_phases = [
            'reconnaissance', 'weaponization', 'delivery', 'exploitation',
            'installation', 'command_control', 'actions_on_objectives'
        ]
        
        logger.debug("Attack pattern detector initialized")
    
    def detect_attack_patterns(self, 
                             nodes: Dict[str, GraphNode],
                             relationships: Dict[str, GraphRelationship],
                             communities: Optional[Dict[str, List[str]]] = None) -> List[AttackPatternResult]:
        """Detect attack patterns in the graph."""
        
        patterns = []
        
        # Detect different types of patterns
        kill_chain_patterns = self._detect_kill_chain_patterns(nodes, relationships)
        patterns.extend(kill_chain_patterns)
        
        infrastructure_patterns = self._detect_infrastructure_patterns(nodes, relationships)
        patterns.extend(infrastructure_patterns)
        
        temporal_patterns = self._detect_temporal_attack_patterns(nodes, relationships)
        patterns.extend(temporal_patterns)
        
        if communities:
            community_patterns = self._detect_community_based_patterns(nodes, relationships, communities)
            patterns.extend(community_patterns)
        
        # Filter by confidence threshold
        filtered_patterns = [
            pattern for pattern in patterns
            if pattern.confidence >= self.min_pattern_confidence
        ]
        
        logger.debug(f"Detected {len(filtered_patterns)} attack patterns (filtered from {len(patterns)})")
        return filtered_patterns
    
    def _detect_kill_chain_patterns(self, 
                                  nodes: Dict[str, GraphNode],
                                  relationships: Dict[str, GraphRelationship]) -> List[AttackPatternResult]:
        """Detect patterns following cyber kill chain phases."""
        
        patterns = []
        
        # Group nodes by kill chain phases (simplified heuristic)
        phase_nodes = defaultdict(list)
        
        for node_id, node in nodes.items():
            if node.node_type == NodeType.TECHNIQUE:
                # Extract phase from node properties or tags
                phase = self._extract_kill_chain_phase(node)
                if phase:
                    phase_nodes[phase].append(node_id)
            elif node.node_type == NodeType.INDICATOR:
                # Classify indicator by type and context
                phase = self._classify_indicator_phase(node)
                if phase:
                    phase_nodes[phase].append(node_id)
        
        # Look for sequential patterns across phases
        phases_with_nodes = [phase for phase in self.kill_chain_phases if phase in phase_nodes]
        
        if len(phases_with_nodes) >= 3:  # At least 3 phases
            
            # Find connections between phases
            connected_phases = []
            for i, phase1 in enumerate(phases_with_nodes):
                for j, phase2 in enumerate(phases_with_nodes[i+1:], i+1):
                    
                    # Check for connections between nodes in different phases
                    connections = self._find_phase_connections(
                        phase_nodes[phase1], phase_nodes[phase2], relationships
                    )
                    
                    if connections:
                        connected_phases.append((phase1, phase2, connections))
            
            if len(connected_phases) >= 2:  # At least 2 phase transitions
                
                # Create kill chain pattern
                involved_nodes = []
                involved_relationships = []
                attack_stages = []
                
                for phase1, phase2, connections in connected_phases:
                    involved_nodes.extend(phase_nodes[phase1])
                    involved_nodes.extend(phase_nodes[phase2])
                    involved_relationships.extend([conn[2] for conn in connections])
                    
                    attack_stages.append({
                        'from_phase': phase1,
                        'to_phase': phase2,
                        'connections': len(connections)
                    })
                
                pattern = AttackPatternResult(
                    pattern_type="kill_chain",
                    description=f"Cyber kill chain pattern spanning {len(phases_with_nodes)} phases",
                    involved_nodes=list(set(involved_nodes)),
                    involved_relationships=list(set(involved_relationships)),
                    confidence=min(0.9, len(connected_phases) / len(self.kill_chain_phases)),
                    complexity=len(phases_with_nodes),
                    attack_stages=attack_stages,
                    kill_chain_phases=phases_with_nodes
                )
                
                patterns.append(pattern)
        
        return patterns
    
    def _detect_infrastructure_patterns(self, 
                                      nodes: Dict[str, GraphNode],
                                      relationships: Dict[str, GraphRelationship]) -> List[AttackPatternResult]:
        """Detect infrastructure-based attack patterns."""
        
        patterns = []
        
        # Find infrastructure sharing patterns
        infra_groups = defaultdict(list)
        
        for node_id, node in nodes.items():
            if node.node_type == NodeType.INFRASTRUCTURE:
                # Group by ASN, country, or other infrastructure properties
                if 'asn' in node.properties:
                    infra_groups[f"asn_{node.properties['asn']}"].append(node_id)
                if 'country' in node.properties:
                    infra_groups[f"country_{node.properties['country']}"].append(node_id)
        
        # Find large infrastructure groups with multiple indicators
        for infra_key, infra_nodes in infra_groups.items():
            if len(infra_nodes) >= 3:  # Significant infrastructure sharing
                
                # Find connected indicators
                connected_indicators = []
                for rel in relationships.values():
                    if rel.source_node_id in infra_nodes:
                        target_node = nodes.get(rel.target_node_id)
                        if target_node and target_node.node_type == NodeType.INDICATOR:
                            connected_indicators.append(rel.target_node_id)
                    elif rel.target_node_id in infra_nodes:
                        source_node = nodes.get(rel.source_node_id)
                        if source_node and source_node.node_type == NodeType.INDICATOR:
                            connected_indicators.append(rel.source_node_id)
                
                if len(connected_indicators) >= self.min_pattern_nodes:
                    
                    pattern = AttackPatternResult(
                        pattern_type="infrastructure_sharing",
                        description=f"Infrastructure sharing pattern: {infra_key}",
                        involved_nodes=infra_nodes + connected_indicators,
                        confidence=min(0.8, len(connected_indicators) / 10),
                        complexity=len(connected_indicators),
                        attribution_indicators=connected_indicators[:5]  # Top indicators for attribution
                    )
                    
                    patterns.append(pattern)
        
        return patterns
    
    def _detect_temporal_attack_patterns(self, 
                                       nodes: Dict[str, GraphNode],
                                       relationships: Dict[str, GraphRelationship]) -> List[AttackPatternResult]:
        """Detect temporal attack patterns."""
        
        patterns = []
        
        # Find temporal clusters of activity
        timed_relationships = []
        
        for rel in relationships.values():
            if rel.first_observed and rel.last_observed:
                timed_relationships.append(rel)
        
        if len(timed_relationships) >= self.min_pattern_nodes:
            
            # Sort by time
            timed_relationships.sort(key=lambda x: x.first_observed)
            
            # Find temporal clusters (events within short time windows)
            time_window = timedelta(hours=24)  # 24-hour window
            clusters = []
            current_cluster = [timed_relationships[0]]
            
            for rel in timed_relationships[1:]:
                if rel.first_observed - current_cluster[-1].first_observed <= time_window:
                    current_cluster.append(rel)
                else:
                    if len(current_cluster) >= self.min_pattern_nodes:
                        clusters.append(current_cluster)
                    current_cluster = [rel]
            
            # Check last cluster
            if len(current_cluster) >= self.min_pattern_nodes:
                clusters.append(current_cluster)
            
            # Create patterns from significant clusters
            for i, cluster in enumerate(clusters):
                if len(cluster) >= self.min_pattern_nodes:
                    
                    involved_nodes = set()
                    involved_relationships = []
                    
                    for rel in cluster:
                        involved_nodes.add(rel.source_node_id)
                        involved_nodes.add(rel.target_node_id)
                        involved_relationships.append(rel.relationship_id)
                    
                    temporal_span = cluster[-1].first_observed - cluster[0].first_observed
                    
                    pattern = AttackPatternResult(
                        pattern_type="temporal_cluster",
                        description=f"Temporal activity cluster with {len(cluster)} events",
                        involved_nodes=list(involved_nodes),
                        involved_relationships=involved_relationships,
                        confidence=min(0.8, len(cluster) / 10),
                        complexity=len(cluster),
                        temporal_span=temporal_span
                    )
                    
                    patterns.append(pattern)
        
        return patterns
    
    def _detect_community_based_patterns(self, 
                                       nodes: Dict[str, GraphNode],
                                       relationships: Dict[str, GraphRelationship],
                                       communities: Dict[str, List[str]]) -> List[AttackPatternResult]:
        """Detect patterns based on community structure."""
        
        patterns = []
        
        for community_id, node_list in communities.items():
            if len(node_list) >= self.min_pattern_nodes:
                
                # Analyze community composition
                node_types = Counter()
                indicator_types = Counter()
                
                for node_id in node_list:
                    node = nodes.get(node_id)
                    if node:
                        node_types[node.node_type.value] += 1
                        
                        if node.node_type == NodeType.INDICATOR:
                            indicator_type = node.properties.get('indicator_type', 'unknown')
                            indicator_types[indicator_type] += 1
                
                # Check for interesting community patterns
                confidence = 0.0
                pattern_type = "community_cluster"
                description = f"Community cluster with {len(node_list)} nodes"
                
                # High-value communities (diverse node types)
                if len(node_types) >= 3:
                    confidence = 0.7
                    pattern_type = "diverse_community"
                    description = f"Diverse threat community with {len(node_types)} node types"
                
                # Indicator-heavy communities
                elif node_types.get('indicator', 0) >= 5:
                    confidence = 0.6
                    pattern_type = "indicator_cluster"
                    description = f"Indicator cluster with {node_types['indicator']} indicators"
                
                if confidence >= self.min_pattern_confidence:
                    
                    pattern = AttackPatternResult(
                        pattern_type=pattern_type,
                        description=description,
                        involved_nodes=node_list,
                        confidence=confidence,
                        complexity=len(node_list),
                        attribution_indicators=[
                            node_id for node_id in node_list[:5]
                            if nodes.get(node_id, {}).node_type == NodeType.INDICATOR
                        ]
                    )
                    
                    patterns.append(pattern)
        
        return patterns
    
    def _extract_kill_chain_phase(self, node: GraphNode) -> Optional[str]:
        """Extract kill chain phase from technique node."""
        
        # Check node properties
        if 'phase' in node.properties:
            return node.properties['phase']
        
        # Check tags for phase indicators
        tags = node.properties.get('tags', [])
        
        for tag in tags:
            tag_lower = tag.lower()
            for phase in self.kill_chain_phases:
                if phase in tag_lower or phase.replace('_', ' ') in tag_lower:
                    return phase
        
        # Heuristic based on technique name/value
        value_lower = node.value.lower()
        
        if any(keyword in value_lower for keyword in ['recon', 'scan', 'enumerate']):
            return 'reconnaissance'
        elif any(keyword in value_lower for keyword in ['exploit', 'vulnerability']):
            return 'exploitation'
        elif any(keyword in value_lower for keyword in ['c2', 'command', 'control']):
            return 'command_control'
        elif any(keyword in value_lower for keyword in ['persist', 'backdoor']):
            return 'installation'
        
        return None
    
    def _classify_indicator_phase(self, node: GraphNode) -> Optional[str]:
        """Classify indicator by kill chain phase."""
        
        indicator_type = node.properties.get('indicator_type', '')
        tags = node.properties.get('tags', [])
        
        # Check tags first
        for tag in tags:
            tag_lower = tag.lower()
            if any(keyword in tag_lower for keyword in ['recon', 'scanning']):
                return 'reconnaissance'
            elif any(keyword in tag_lower for keyword in ['delivery', 'dropper']):
                return 'delivery'
            elif any(keyword in tag_lower for keyword in ['c2', 'command', 'control']):
                return 'command_control'
            elif any(keyword in tag_lower for keyword in ['exfil', 'theft']):
                return 'actions_on_objectives'
        
        # Classify by indicator type
        if indicator_type in ['email', 'url'] and any(keyword in str(tags).lower() for keyword in ['phishing', 'malicious']):
            return 'delivery'
        elif indicator_type in ['ip_address', 'domain'] and any(keyword in str(tags).lower() for keyword in ['c2', 'command']):
            return 'command_control'
        elif indicator_type in ['file_hash', 'file']:
            return 'weaponization'
        
        return None
    
    def _find_phase_connections(self, 
                              phase1_nodes: List[str], 
                              phase2_nodes: List[str],
                              relationships: Dict[str, GraphRelationship]) -> List[Tuple[str, str, str]]:
        """Find connections between nodes in different phases."""
        
        connections = []
        
        for rel in relationships.values():
            if ((rel.source_node_id in phase1_nodes and rel.target_node_id in phase2_nodes) or
                (rel.source_node_id in phase2_nodes and rel.target_node_id in phase1_nodes)):
                
                connections.append((rel.source_node_id, rel.target_node_id, rel.relationship_id))
        
        return connections


class GraphAnalysisOrchestrator:
    """Orchestrates comprehensive graph analysis."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize graph analysis orchestrator."""
        self.config = config or {}
        
        # Initialize analyzers
        self.centrality_analyzer = CentralityAnalyzer(
            self.config.get('centrality', {})
        )
        
        self.community_detector = CommunityDetector(
            self.config.get('community', {})
        )
        
        self.path_analyzer = PathAnalyzer(
            self.config.get('path', {})
        )
        
        self.attack_pattern_detector = AttackPatternDetector(
            self.config.get('attack_patterns', {})
        )
        
        logger.info("Graph analysis orchestrator initialized")
    
    def analyze_complete_graph(self, 
                             nodes: Dict[str, GraphNode],
                             relationships: Dict[str, GraphRelationship]) -> Dict[str, Any]:
        """Perform comprehensive graph analysis."""
        
        start_time = datetime.now(timezone.utc)
        results = {
            'analysis_timestamp': start_time.isoformat(),
            'input_stats': {
                'node_count': len(nodes),
                'relationship_count': len(relationships)
            }
        }
        
        try:
            logger.info(f"Starting comprehensive graph analysis: {len(nodes)} nodes, {len(relationships)} relationships")
            
            # Centrality analysis
            logger.debug("Analyzing centrality measures")
            centrality_results = self.centrality_analyzer.analyze_all_centralities(nodes, relationships)
            results['centrality'] = {k: v.to_dict() for k, v in centrality_results.items()}
            
            # Community detection
            logger.debug("Detecting communities")
            community_result = self.community_detector.detect_communities(nodes, relationships)
            results['communities'] = community_result.to_dict()
            
            # Attack pattern detection
            logger.debug("Detecting attack patterns")
            attack_patterns = self.attack_pattern_detector.detect_attack_patterns(
                nodes, relationships, community_result.communities
            )
            results['attack_patterns'] = [pattern.to_dict() for pattern in attack_patterns]
            
            # Key insights
            results['insights'] = self._generate_insights(
                centrality_results, community_result, attack_patterns, nodes, relationships
            )
            
            logger.info("Graph analysis completed successfully")
            
        except Exception as e:
            logger.error(f"Graph analysis failed: {e}", exc_info=True)
            results['error'] = str(e)
        
        finally:
            end_time = datetime.now(timezone.utc)
            results['execution_time'] = (end_time - start_time).total_seconds()
        
        return results
    
    def _generate_insights(self, 
                         centrality_results: Dict[str, CentralityResult],
                         community_result: CommunityResult,
                         attack_patterns: List[AttackPatternResult],
                         nodes: Dict[str, GraphNode],
                         relationships: Dict[str, GraphRelationship]) -> Dict[str, Any]:
        """Generate high-level insights from analysis results."""
        
        insights = {
            'key_nodes': [],
            'critical_communities': [],
            'threat_assessment': {},
            'recommendations': []
        }
        
        # Identify key nodes across centrality measures
        all_top_nodes = set()
        for centrality_result in centrality_results.values():
            all_top_nodes.update([node_id for node_id, _ in centrality_result.top_nodes[:5]])
        
        insights['key_nodes'] = list(all_top_nodes)
        
        # Identify critical communities
        if community_result.communities:
            sorted_communities = sorted(
                community_result.communities.items(),
                key=lambda x: len(x[1]),
                reverse=True
            )
            insights['critical_communities'] = [
                {'community_id': comm_id, 'size': len(node_list)}
                for comm_id, node_list in sorted_communities[:3]
            ]
        
        # Threat assessment
        threat_level = "LOW"
        if len(attack_patterns) >= 3:
            threat_level = "HIGH"
        elif len(attack_patterns) >= 1:
            threat_level = "MEDIUM"
        
        insights['threat_assessment'] = {
            'level': threat_level,
            'pattern_count': len(attack_patterns),
            'complexity_score': sum(pattern.complexity for pattern in attack_patterns) / len(attack_patterns) if attack_patterns else 0
        }
        
        # Generate recommendations
        recommendations = []
        
        if len(insights['key_nodes']) > 0:
            recommendations.append(f"Monitor {len(insights['key_nodes'])} key nodes with high centrality scores")
        
        if len(attack_patterns) > 0:
            recommendations.append(f"Investigate {len(attack_patterns)} detected attack patterns")
        
        if community_result.community_count > 5:
            recommendations.append(f"Analyze {community_result.community_count} communities for threat actor attribution")
        
        insights['recommendations'] = recommendations
        
        return insights