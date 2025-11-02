"""
Knowledge graph storage system for threat intelligence correlation.

This module provides comprehensive storage capabilities for knowledge graphs
using various formats (GraphML, JSON, Neo4j) with support for different
node types (indicators, techniques, CVEs, infrastructure) and relationship
management.
"""

import logging
import json
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import uuid
import pickle
import gzip
from pathlib import Path
import statistics 
from collections import Counter

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


class StorageFormat(Enum):
    """Supported storage formats for knowledge graphs."""
    JSON = "json"
    GRAPHML = "graphml"
    PICKLE = "pickle"
    GEXF = "gexf"
    DOT = "dot"
    COMPRESSED_JSON = "json_gz"


class QueryOperator(Enum):
    """Query operators for graph searches."""
    EQUALS = "eq"
    CONTAINS = "contains"
    STARTS_WITH = "starts_with"
    IN = "in"
    GREATER_THAN = "gt"
    LESS_THAN = "lt"
    BETWEEN = "between"


@dataclass
class GraphQuery:
    """Query specification for searching the knowledge graph."""
    
    # Node filters
    node_types: Optional[List[NodeType]] = None
    node_properties: Optional[Dict[str, Any]] = None
    
    # Relationship filters
    relationship_types: Optional[List[RelationshipType]] = None
    relationship_properties: Optional[Dict[str, Any]] = None
    
    # Confidence and quality filters
    min_confidence: Optional[float] = None
    min_weight: Optional[float] = None
    
    # Temporal filters
    created_after: Optional[datetime] = None
    created_before: Optional[datetime] = None
    
    # Source filters
    sources: Optional[List[str]] = None
    
    # Graph structure filters
    max_distance: Optional[int] = None  # For path queries
    min_degree: Optional[int] = None    # Minimum node degree
    
    # Result limits
    limit: Optional[int] = None
    offset: Optional[int] = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert query to dictionary."""
        return {
            'node_types': [nt.value for nt in self.node_types] if self.node_types else None,
            'node_properties': self.node_properties,
            'relationship_types': [rt.value for rt in self.relationship_types] if self.relationship_types else None,
            'relationship_properties': self.relationship_properties,
            'min_confidence': self.min_confidence,
            'min_weight': self.min_weight,
            'created_after': self.created_after.isoformat() if self.created_after else None,
            'created_before': self.created_before.isoformat() if self.created_before else None,
            'sources': self.sources,
            'max_distance': self.max_distance,
            'min_degree': self.min_degree,
            'limit': self.limit,
            'offset': self.offset
        }


@dataclass
class GraphMetadata:
    """Metadata for stored knowledge graphs."""
    
    graph_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""
    
    # Statistics
    node_count: int = 0
    relationship_count: int = 0
    node_type_counts: Dict[str, int] = field(default_factory=dict)
    relationship_type_counts: Dict[str, int] = field(default_factory=dict)
    
    # Temporal information
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    modified_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Source tracking
    source_indicators: int = 0
    source_files: List[str] = field(default_factory=list)
    
    # Quality metrics
    avg_confidence: float = 0.0
    density: float = 0.0
    
    # Storage information
    storage_format: StorageFormat = StorageFormat.JSON
    file_size_bytes: int = 0
    compression_used: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'graph_id': self.graph_id,
            'name': self.name,
            'description': self.description,
            'node_count': self.node_count,
            'relationship_count': self.relationship_count,
            'node_type_counts': self.node_type_counts,
            'relationship_type_counts': self.relationship_type_counts,
            'created_at': self.created_at.isoformat(),
            'modified_at': self.modified_at.isoformat(),
            'source_indicators': self.source_indicators,
            'source_files': self.source_files,
            'avg_confidence': self.avg_confidence,
            'density': self.density,
            'storage_format': self.storage_format.value,
            'file_size_bytes': self.file_size_bytes,
            'compression_used': self.compression_used
        }


class GraphStorage:
    """Base class for knowledge graph storage backends."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize graph storage."""
        self.config = config or {}
        
    def store_graph(self, 
                   nodes: Dict[str, GraphNode], 
                   relationships: Dict[str, GraphRelationship],
                   metadata: Optional[GraphMetadata] = None) -> str:
        """Store a knowledge graph."""
        raise NotImplementedError
    
    def load_graph(self, graph_id: str) -> Tuple[Dict[str, GraphNode], Dict[str, GraphRelationship], GraphMetadata]:
        """Load a knowledge graph."""
        raise NotImplementedError
    
    def query_graph(self, query: GraphQuery, graph_id: Optional[str] = None) -> Dict[str, Any]:
        """Query the knowledge graph."""
        raise NotImplementedError
    
    def list_graphs(self) -> List[GraphMetadata]:
        """List available graphs."""
        raise NotImplementedError
    
    def delete_graph(self, graph_id: str) -> bool:
        """Delete a graph."""
        raise NotImplementedError


class FileBasedStorage(GraphStorage):
    """File-based storage for knowledge graphs."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize file-based storage."""
        super().__init__(config)
        
        # Storage settings
        self.storage_dir = Path(self.config.get('storage_dir', 'data/graphs'))
        self.default_format = StorageFormat(self.config.get('default_format', 'json'))
        self.enable_compression = self.config.get('enable_compression', True)
        
        # Create storage directory
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        
        # Metadata storage
        self.metadata_file = self.storage_dir / 'metadata.json'
        self._load_metadata_index()
        
        logger.info(f"File-based graph storage initialized: {self.storage_dir}")
    
    def store_graph(self, 
                   nodes: Dict[str, GraphNode], 
                   relationships: Dict[str, GraphRelationship],
                   metadata: Optional[GraphMetadata] = None) -> str:
        """Store a knowledge graph to files."""
        
        if not metadata:
            metadata = GraphMetadata()
        
        # Update metadata statistics
        metadata.node_count = len(nodes)
        metadata.relationship_count = len(relationships)
        metadata.modified_at = datetime.now(timezone.utc)
        
        # Calculate node type counts
        metadata.node_type_counts = {}
        for node in nodes.values():
            node_type = node.node_type.value
            metadata.node_type_counts[node_type] = metadata.node_type_counts.get(node_type, 0) + 1
        
        # Calculate relationship type counts
        metadata.relationship_type_counts = {}
        for rel in relationships.values():
            rel_type = rel.relationship_type.value
            metadata.relationship_type_counts[rel_type] = metadata.relationship_type_counts.get(rel_type, 0) + 1
        
        # Calculate average confidence
        if nodes:
            avg_confidence = sum(node.confidence for node in nodes.values()) / len(nodes)
            metadata.avg_confidence = avg_confidence
        
        try:
            # Store graph data
            graph_file = self.storage_dir / f"{metadata.graph_id}.{self.default_format.value}"
            
            if self.default_format == StorageFormat.JSON:
                self._store_json(nodes, relationships, metadata, graph_file)
            elif self.default_format == StorageFormat.GRAPHML:
                self._store_graphml(nodes, relationships, metadata, graph_file)
            elif self.default_format == StorageFormat.PICKLE:
                self._store_pickle(nodes, relationships, metadata, graph_file)
            elif self.default_format == StorageFormat.COMPRESSED_JSON:
                self._store_compressed_json(nodes, relationships, metadata, graph_file)
            else:
                raise ValueError(f"Unsupported storage format: {self.default_format}")
            
            # Update metadata
            metadata.storage_format = self.default_format
            if graph_file.exists():
                metadata.file_size_bytes = graph_file.stat().st_size
            
            # Update metadata index
            self.metadata_index[metadata.graph_id] = metadata
            self._save_metadata_index()
            
            logger.info(f"Stored graph {metadata.graph_id} with {metadata.node_count} nodes and {metadata.relationship_count} relationships")
            return metadata.graph_id
            
        except Exception as e:
            logger.error(f"Failed to store graph: {e}", exc_info=True)
            raise
    
    def load_graph(self, graph_id: str) -> Tuple[Dict[str, GraphNode], Dict[str, GraphRelationship], GraphMetadata]:
        """Load a knowledge graph from files."""
        
        if graph_id not in self.metadata_index:
            raise ValueError(f"Graph {graph_id} not found")
        
        metadata = self.metadata_index[graph_id]
        graph_file = self.storage_dir / f"{graph_id}.{metadata.storage_format.value}"
        
        if not graph_file.exists():
            raise FileNotFoundError(f"Graph file not found: {graph_file}")
        
        try:
            if metadata.storage_format == StorageFormat.JSON:
                nodes, relationships = self._load_json(graph_file)
            elif metadata.storage_format == StorageFormat.GRAPHML:
                nodes, relationships = self._load_graphml(graph_file)
            elif metadata.storage_format == StorageFormat.PICKLE:
                nodes, relationships = self._load_pickle(graph_file)
            elif metadata.storage_format == StorageFormat.COMPRESSED_JSON:
                nodes, relationships = self._load_compressed_json(graph_file)
            else:
                raise ValueError(f"Unsupported storage format: {metadata.storage_format}")
            
            logger.debug(f"Loaded graph {graph_id} with {len(nodes)} nodes and {len(relationships)} relationships")
            return nodes, relationships, metadata
            
        except Exception as e:
            logger.error(f"Failed to load graph {graph_id}: {e}", exc_info=True)
            raise
    
    def query_graph(self, query: GraphQuery, graph_id: Optional[str] = None) -> Dict[str, Any]:
        """Query the knowledge graph."""
        
        results = {
            'nodes': {},
            'relationships': {},
            'metadata': {
                'query': query.to_dict(),
                'total_results': 0,
                'execution_time': 0.0
            }
        }
        
        start_time = datetime.now(timezone.utc)
        
        try:
            # If no specific graph, query all graphs
            graph_ids = [graph_id] if graph_id else list(self.metadata_index.keys())
            
            for gid in graph_ids:
                try:
                    nodes, relationships, metadata = self.load_graph(gid)
                    
                    # Filter nodes
                    filtered_nodes = self._filter_nodes(nodes, query)
                    
                    # Filter relationships
                    filtered_relationships = self._filter_relationships(
                        relationships, query, filtered_nodes
                    )
                    
                    # Merge results
                    results['nodes'].update(filtered_nodes)
                    results['relationships'].update(filtered_relationships)
                    
                except Exception as e:
                    logger.warning(f"Failed to query graph {gid}: {e}")
                    continue
            
            # Apply limits
            if query.limit:
                node_items = list(results['nodes'].items())
                if query.offset:
                    node_items = node_items[query.offset:]
                node_items = node_items[:query.limit]
                results['nodes'] = dict(node_items)
            
            results['metadata']['total_results'] = len(results['nodes'])
            
        except Exception as e:
            logger.error(f"Graph query failed: {e}", exc_info=True)
            results['metadata']['error'] = str(e)
        
        finally:
            end_time = datetime.now(timezone.utc)
            results['metadata']['execution_time'] = (end_time - start_time).total_seconds()
        
        return results
    
    def list_graphs(self) -> List[GraphMetadata]:
        """List available graphs."""
        return list(self.metadata_index.values())
    
    def delete_graph(self, graph_id: str) -> bool:
        """Delete a graph."""
        
        if graph_id not in self.metadata_index:
            return False
        
        try:
            metadata = self.metadata_index[graph_id]
            graph_file = self.storage_dir / f"{graph_id}.{metadata.storage_format.value}"
            
            if graph_file.exists():
                graph_file.unlink()
            
            del self.metadata_index[graph_id]
            self._save_metadata_index()
            
            logger.info(f"Deleted graph {graph_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete graph {graph_id}: {e}", exc_info=True)
            return False
    
    def _load_metadata_index(self):
        """Load metadata index from file."""
        self.metadata_index = {}
        
        if self.metadata_file.exists():
            try:
                with open(self.metadata_file, 'r') as f:
                    data = json.load(f)
                
                for graph_id, metadata_dict in data.items():
                    metadata = self._dict_to_metadata(metadata_dict)
                    self.metadata_index[graph_id] = metadata
                    
                logger.debug(f"Loaded metadata for {len(self.metadata_index)} graphs")
                
            except Exception as e:
                logger.warning(f"Failed to load metadata index: {e}")
    
    def _save_metadata_index(self):
        """Save metadata index to file."""
        try:
            data = {}
            for graph_id, metadata in self.metadata_index.items():
                data[graph_id] = metadata.to_dict()
            
            with open(self.metadata_file, 'w') as f:
                json.dump(data, f, indent=2)
                
        except Exception as e:
            logger.error(f"Failed to save metadata index: {e}")
    
    def _dict_to_metadata(self, metadata_dict: Dict[str, Any]) -> GraphMetadata:
        """Convert dictionary to GraphMetadata object."""
        
        metadata = GraphMetadata()
        metadata.graph_id = metadata_dict.get('graph_id', str(uuid.uuid4()))
        metadata.name = metadata_dict.get('name', '')
        metadata.description = metadata_dict.get('description', '')
        metadata.node_count = metadata_dict.get('node_count', 0)
        metadata.relationship_count = metadata_dict.get('relationship_count', 0)
        metadata.node_type_counts = metadata_dict.get('node_type_counts', {})
        metadata.relationship_type_counts = metadata_dict.get('relationship_type_counts', {})
        
        # Parse datetime fields
        if 'created_at' in metadata_dict:
            metadata.created_at = datetime.fromisoformat(metadata_dict['created_at'])
        if 'modified_at' in metadata_dict:
            metadata.modified_at = datetime.fromisoformat(metadata_dict['modified_at'])
        
        metadata.source_indicators = metadata_dict.get('source_indicators', 0)
        metadata.source_files = metadata_dict.get('source_files', [])
        metadata.avg_confidence = metadata_dict.get('avg_confidence', 0.0)
        metadata.density = metadata_dict.get('density', 0.0)
        
        # Parse storage format
        if 'storage_format' in metadata_dict:
            metadata.storage_format = StorageFormat(metadata_dict['storage_format'])
        
        metadata.file_size_bytes = metadata_dict.get('file_size_bytes', 0)
        metadata.compression_used = metadata_dict.get('compression_used', False)
        
        return metadata
    
    def _store_json(self, 
                   nodes: Dict[str, GraphNode], 
                   relationships: Dict[str, GraphRelationship],
                   metadata: GraphMetadata,
                   file_path: Path):
        """Store graph as JSON."""
        
        data = {
            'metadata': metadata.to_dict(),
            'nodes': {nid: node.to_dict() for nid, node in nodes.items()},
            'relationships': {rid: rel.to_dict() for rid, rel in relationships.items()}
        }
        
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=2)
    
    def _load_json(self, file_path: Path) -> Tuple[Dict[str, GraphNode], Dict[str, GraphRelationship]]:
        """Load graph from JSON."""
        
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        # Reconstruct nodes
        nodes = {}
        for nid, node_dict in data['nodes'].items():
            node = self._dict_to_node(node_dict)
            nodes[nid] = node
        
        # Reconstruct relationships
        relationships = {}
        for rid, rel_dict in data['relationships'].items():
            rel = self._dict_to_relationship(rel_dict)
            relationships[rid] = rel
        
        return nodes, relationships
    
    def _store_compressed_json(self, 
                              nodes: Dict[str, GraphNode], 
                              relationships: Dict[str, GraphRelationship],
                              metadata: GraphMetadata,
                              file_path: Path):
        """Store graph as compressed JSON."""
        
        data = {
            'metadata': metadata.to_dict(),
            'nodes': {nid: node.to_dict() for nid, node in nodes.items()},
            'relationships': {rid: rel.to_dict() for rid, rel in relationships.items()}
        }
        
        with gzip.open(f"{file_path}.gz", 'wt') as f:
            json.dump(data, f)
        
        metadata.compression_used = True
    
    def _load_compressed_json(self, file_path: Path) -> Tuple[Dict[str, GraphNode], Dict[str, GraphRelationship]]:
        """Load graph from compressed JSON."""
        
        compressed_path = f"{file_path}.gz" if not str(file_path).endswith('.gz') else file_path
        
        with gzip.open(compressed_path, 'rt') as f:
            data = json.load(f)
        
        # Reconstruct nodes
        nodes = {}
        for nid, node_dict in data['nodes'].items():
            node = self._dict_to_node(node_dict)
            nodes[nid] = node
        
        # Reconstruct relationships
        relationships = {}
        for rid, rel_dict in data['relationships'].items():
            rel = self._dict_to_relationship(rel_dict)
            relationships[rid] = rel
        
        return nodes, relationships
    
    def _store_pickle(self, 
                     nodes: Dict[str, GraphNode], 
                     relationships: Dict[str, GraphRelationship],
                     metadata: GraphMetadata,
                     file_path: Path):
        """Store graph using pickle format."""
        
        data = {
            'metadata': metadata,
            'nodes': nodes,
            'relationships': relationships
        }
        
        with open(file_path, 'wb') as f:
            pickle.dump(data, f)
    
    def _load_pickle(self, file_path: Path) -> Tuple[Dict[str, GraphNode], Dict[str, GraphRelationship]]:
        """Load graph from pickle format."""
        
        with open(file_path, 'rb') as f:
            data = pickle.load(f)
        
        return data['nodes'], data['relationships']
    
    def _store_graphml(self, 
                      nodes: Dict[str, GraphNode], 
                      relationships: Dict[str, GraphRelationship],
                      metadata: GraphMetadata,
                      file_path: Path):
        """Store graph in GraphML format."""
        
        if not HAS_NETWORKX:
            raise ImportError("NetworkX required for GraphML format")
        
        # Create NetworkX graph
        G = nx.Graph()
        
        # Add nodes
        for node_id, node in nodes.items():
            G.add_node(
                node_id,
                node_type=node.node_type.value,
                value=node.value,
                label=node.label,
                confidence=node.confidence,
                **node.properties
            )
        
        # Add edges
        for rel in relationships.values():
            G.add_edge(
                rel.source_node_id,
                rel.target_node_id,
                relationship_type=rel.relationship_type.value,
                weight=rel.weight,
                confidence=rel.confidence,
                **rel.properties
            )
        
        # Write GraphML
        nx.write_graphml(G, file_path)
    
    def _load_graphml(self, file_path: Path) -> Tuple[Dict[str, GraphNode], Dict[str, GraphRelationship]]:
        """Load graph from GraphML format."""
        
        if not HAS_NETWORKX:
            raise ImportError("NetworkX required for GraphML format")
        
        # Load NetworkX graph
        G = nx.read_graphml(file_path)
        
        # Reconstruct nodes
        nodes = {}
        for node_id, node_data in G.nodes(data=True):
            node = GraphNode(
                node_id=node_id,
                node_type=NodeType(node_data.get('node_type', 'indicator')),
                value=node_data.get('value', ''),
                label=node_data.get('label', ''),
                confidence=float(node_data.get('confidence', 0.0)),
                properties={k: v for k, v in node_data.items() 
                          if k not in {'node_type', 'value', 'label', 'confidence'}}
            )
            nodes[node_id] = node
        
        # Reconstruct relationships
        relationships = {}
        for source, target, edge_data in G.edges(data=True):
            rel = GraphRelationship(
                source_node_id=source,
                target_node_id=target,
                relationship_type=RelationshipType(edge_data.get('relationship_type', 'similar_to')),
                weight=float(edge_data.get('weight', 1.0)),
                confidence=float(edge_data.get('confidence', 0.0)),
                properties={k: v for k, v in edge_data.items() 
                          if k not in {'relationship_type', 'weight', 'confidence'}}
            )
            relationships[rel.relationship_id] = rel
        
        return nodes, relationships
    
    def _dict_to_node(self, node_dict: Dict[str, Any]) -> GraphNode:
        """Convert dictionary to GraphNode object."""
        
        node = GraphNode(
            node_id=node_dict['node_id'],
            node_type=NodeType(node_dict['node_type']),
            value=node_dict['value'],
            label=node_dict['label'],
            properties=node_dict.get('properties', {}),
            confidence=node_dict.get('confidence', 0.0)
        )
        
        # Parse optional datetime fields
        if 'first_seen' in node_dict and node_dict['first_seen']:
            node.first_seen = datetime.fromisoformat(node_dict['first_seen'])
        if 'last_seen' in node_dict and node_dict['last_seen']:
            node.last_seen = datetime.fromisoformat(node_dict['last_seen'])
        
        # Parse sets
        if 'sources' in node_dict:
            node.sources = set(node_dict['sources'])
        
        node.source_count = node_dict.get('source_count', 0)
        node.centrality_scores = node_dict.get('centrality_scores', {})
        node.community_id = node_dict.get('community_id')
        
        return node
    
    def _dict_to_relationship(self, rel_dict: Dict[str, Any]) -> GraphRelationship:
        """Convert dictionary to GraphRelationship object."""
        
        rel = GraphRelationship(
            relationship_id=rel_dict['relationship_id'],
            source_node_id=rel_dict['source_node_id'],
            target_node_id=rel_dict['target_node_id'],
            relationship_type=RelationshipType(rel_dict['relationship_type']),
            weight=rel_dict.get('weight', 1.0),
            confidence=rel_dict.get('confidence', 0.0),
            evidence=rel_dict.get('evidence', []),
            properties=rel_dict.get('properties', {})
        )
        
        # Parse optional datetime fields
        if 'first_observed' in rel_dict and rel_dict['first_observed']:
            rel.first_observed = datetime.fromisoformat(rel_dict['first_observed'])
        if 'last_observed' in rel_dict and rel_dict['last_observed']:
            rel.last_observed = datetime.fromisoformat(rel_dict['last_observed'])
        
        # Parse sets
        if 'sources' in rel_dict:
            rel.sources = set(rel_dict['sources'])
        
        return rel
    
    def _filter_nodes(self, nodes: Dict[str, GraphNode], query: GraphQuery) -> Dict[str, GraphNode]:
        """Filter nodes based on query criteria."""
        
        filtered = {}
        
        for node_id, node in nodes.items():
            
            # Node type filter
            if query.node_types and node.node_type not in query.node_types:
                continue
            
            # Confidence filter
            if query.min_confidence and node.confidence < query.min_confidence:
                continue
            
            # Source filter
            if query.sources and not any(source in node.sources for source in query.sources):
                continue
            
            # Property filters
            if query.node_properties:
                if not self._matches_properties(node.properties, query.node_properties):
                    continue
            
            # Temporal filters
            if query.created_after or query.created_before:
                node_time = node.first_seen or node.last_seen
                if node_time:
                    if query.created_after and node_time < query.created_after:
                        continue
                    if query.created_before and node_time > query.created_before:
                        continue
            
            filtered[node_id] = node
        
        return filtered
    
    def _filter_relationships(self, 
                            relationships: Dict[str, GraphRelationship], 
                            query: GraphQuery,
                            filtered_nodes: Dict[str, GraphNode]) -> Dict[str, GraphRelationship]:
        """Filter relationships based on query criteria."""
        
        filtered = {}
        
        for rel_id, rel in relationships.items():
            
            # Only include relationships between filtered nodes
            if (rel.source_node_id not in filtered_nodes or 
                rel.target_node_id not in filtered_nodes):
                continue
            
            # Relationship type filter
            if query.relationship_types and rel.relationship_type not in query.relationship_types:
                continue
            
            # Confidence filter
            if query.min_confidence and rel.confidence < query.min_confidence:
                continue
            
            # Weight filter
            if query.min_weight and rel.weight < query.min_weight:
                continue
            
            # Source filter
            if query.sources and not any(source in rel.sources for source in query.sources):
                continue
            
            # Property filters
            if query.relationship_properties:
                if not self._matches_properties(rel.properties, query.relationship_properties):
                    continue
            
            # Temporal filters
            if query.created_after or query.created_before:
                rel_time = rel.first_observed or rel.last_observed
                if rel_time:
                    if query.created_after and rel_time < query.created_after:
                        continue
                    if query.created_before and rel_time > query.created_before:
                        continue
            
            filtered[rel_id] = rel
        
        return filtered
    
    def _matches_properties(self, properties: Dict[str, Any], query_properties: Dict[str, Any]) -> bool:
        """Check if properties match query criteria."""
        
        for key, value in query_properties.items():
            if key not in properties:
                return False
            
            prop_value = properties[key]
            
            # Handle different query operators (simplified for now)
            if isinstance(value, dict) and 'operator' in value:
                operator = QueryOperator(value['operator'])
                query_value = value['value']
                
                if operator == QueryOperator.EQUALS:
                    if prop_value != query_value:
                        return False
                elif operator == QueryOperator.CONTAINS:
                    if query_value not in str(prop_value):
                        return False
                # Add more operators as needed
                
            else:
                # Direct equality
                if prop_value != value:
                    return False
        
        return True


class KnowledgeGraphManager:
    """High-level manager for knowledge graph operations."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize knowledge graph manager."""
        self.config = config or {}
        
        # Initialize storage backend
        storage_type = self.config.get('storage_type', 'file')
        
        if storage_type == 'file':
            self.storage = FileBasedStorage(self.config.get('file_storage', {}))
        else:
            raise ValueError(f"Unsupported storage type: {storage_type}")
        
        logger.info("Knowledge graph manager initialized")
    
    def store_correlation_result(self, result: CorrelationResult, name: Optional[str] = None) -> str:
        """Store a correlation result as a knowledge graph."""
        
        metadata = GraphMetadata(
            name=name or f"Correlation_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            description=f"Correlation result with {result.node_count} nodes and {result.relationship_count} relationships",
            source_indicators=len(result.input_indicators)
        )
        
        return self.storage.store_graph(result.nodes, result.relationships, metadata)
    
    def load_correlation_result(self, graph_id: str) -> CorrelationResult:
        """Load a correlation result from storage."""
        
        nodes, relationships, metadata = self.storage.load_graph(graph_id)
        
        result = CorrelationResult(
            correlation_id=metadata.graph_id,
            nodes=nodes,
            relationships=relationships,
            node_count=metadata.node_count,
            relationship_count=metadata.relationship_count,
            created_at=metadata.created_at
        )
        
        return result
    
    def query_graphs(self, query: GraphQuery) -> Dict[str, Any]:
        """Query knowledge graphs."""
        return self.storage.query_graph(query)
    
    def list_available_graphs(self) -> List[Dict[str, Any]]:
        """List available knowledge graphs."""
        metadata_list = self.storage.list_graphs()
        return [metadata.to_dict() for metadata in metadata_list]
    
    def merge_graphs(self, graph_ids: List[str], merged_name: Optional[str] = None) -> str:
        """Merge multiple graphs into one."""
        
        merged_nodes = {}
        merged_relationships = {}
        
        for graph_id in graph_ids:
            nodes, relationships, _ = self.storage.load_graph(graph_id)
            merged_nodes.update(nodes)
            merged_relationships.update(relationships)
        
        # Create metadata for merged graph
        metadata = GraphMetadata(
            name=merged_name or f"Merged_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            description=f"Merged graph from {len(graph_ids)} source graphs",
            source_files=graph_ids
        )
        
        return self.storage.store_graph(merged_nodes, merged_relationships, metadata)
    
    def export_graph(self, graph_id: str, format: StorageFormat, output_path: Optional[str] = None) -> str:
        """Export graph in specified format."""
        
        nodes, relationships, metadata = self.storage.load_graph(graph_id)
        
        if not output_path:
            output_path = f"graph_{graph_id}.{format.value}"
        
        # Create temporary storage with desired format
        export_config = {
            'storage_dir': str(Path(output_path).parent),
            'default_format': format.value
        }
        
        export_storage = FileBasedStorage(export_config)
        
        # Update metadata for export
        export_metadata = GraphMetadata(
            graph_id=Path(output_path).stem,
            name=metadata.name,
            description=metadata.description
        )
        
        export_storage.store_graph(nodes, relationships, export_metadata)
        
        return output_path
    
    def get_graph_statistics(self, graph_id: str) -> Dict[str, Any]:
        """Get detailed statistics for a graph."""
        
        nodes, relationships, metadata = self.storage.load_graph(graph_id)
        
        # Calculate detailed statistics
        node_types = Counter()
        relationship_types = Counter()
        confidence_scores = []
        
        for node in nodes.values():
            node_types[node.node_type.value] += 1
            confidence_scores.append(node.confidence)
        
        for rel in relationships.values():
            relationship_types[rel.relationship_type.value] += 1
            confidence_scores.append(rel.confidence)
        
        stats = {
            'basic': metadata.to_dict(),
            'node_types': dict(node_types),
            'relationship_types': dict(relationship_types),
            'confidence_stats': {
                'mean': statistics.mean(confidence_scores) if confidence_scores else 0,
                'median': statistics.median(confidence_scores) if confidence_scores else 0,
                'min': min(confidence_scores) if confidence_scores else 0,
                'max': max(confidence_scores) if confidence_scores else 0
            }
        }
        
        # Add NetworkX-based statistics if available
        if HAS_NETWORKX:
            try:
                G = nx.Graph()
                
                for node_id in nodes.keys():
                    G.add_node(node_id)
                
                for rel in relationships.values():
                    G.add_edge(rel.source_node_id, rel.target_node_id, weight=rel.weight)
                
                stats['network_stats'] = {
                    'density': nx.density(G),
                    'connected_components': nx.number_connected_components(G),
                    'average_clustering': nx.average_clustering(G),
                    'diameter': nx.diameter(G) if nx.is_connected(G) else None
                }
                
            except Exception as e:
                logger.debug(f"Failed to calculate network statistics: {e}")
        
        return stats