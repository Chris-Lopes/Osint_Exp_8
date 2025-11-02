"""
Clustering algorithms for threat intelligence indicator analysis.

This module implements clustering algorithms to group related indicators into
campaigns, attack patterns, and threat actor clusters using machine learning
and graph-based techniques.
"""

import logging
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass
from enum import Enum
from collections import defaultdict, Counter
import math

try:
    from ..normalizers.schema import NormalizedIndicator, IndicatorType
    from .correlation import CorrelationResult, CorrelationEngine, CorrelationType, CorrelationStrength
except ImportError:
    from normalizers.schema import NormalizedIndicator, IndicatorType
    from analysis.correlation import CorrelationResult, CorrelationEngine, CorrelationType, CorrelationStrength

logger = logging.getLogger(__name__)


class ClusterType(Enum):
    """Types of indicator clusters."""
    CAMPAIGN = "campaign"
    ATTACK_PATTERN = "attack_pattern"
    INFRASTRUCTURE = "infrastructure"
    MALWARE_FAMILY = "malware_family"
    THREAT_ACTOR = "threat_actor"
    TEMPORAL_BURST = "temporal_burst"


class ClusterQuality(Enum):
    """Quality assessment of clusters."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class IndicatorCluster:
    """Represents a cluster of related indicators."""
    id: str
    cluster_type: ClusterType
    indicator_ids: Set[str]
    cluster_score: float  # Overall cluster coherence score
    quality: ClusterQuality
    created_at: datetime
    
    # Cluster characteristics
    primary_indicator_types: List[IndicatorType]
    timeframe: Tuple[datetime, datetime]  # (start, end)
    geographic_regions: Set[str]
    sources: Set[str]
    
    # Evidence and metadata
    correlation_evidence: List[Dict[str, Any]]
    cluster_features: Dict[str, Any]
    confidence: float
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert cluster to dictionary format."""
        return {
            'id': self.id,
            'cluster_type': self.cluster_type.value,
            'indicator_ids': list(self.indicator_ids),
            'cluster_score': self.cluster_score,
            'quality': self.quality.value,
            'created_at': self.created_at.isoformat(),
            'primary_indicator_types': [t.value for t in self.primary_indicator_types],
            'timeframe': [self.timeframe[0].isoformat(), self.timeframe[1].isoformat()],
            'geographic_regions': list(self.geographic_regions),
            'sources': list(self.sources),
            'correlation_evidence': self.correlation_evidence,
            'cluster_features': self.cluster_features,
            'confidence': self.confidence
        }


class GraphBasedClustering:
    """Graph-based clustering using correlation networks."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize graph-based clustering."""
        self.config = config or {}
        
        # Clustering thresholds
        self.min_correlation_score = self.config.get('min_correlation_score', 0.4)
        self.min_cluster_size = self.config.get('min_cluster_size', 2)
        self.max_cluster_size = self.config.get('max_cluster_size', 50)
        
        # Community detection parameters
        self.modularity_threshold = self.config.get('modularity_threshold', 0.3)
    
    def cluster_indicators(self, indicators: List[NormalizedIndicator], 
                          correlations: List[CorrelationResult]) -> List[IndicatorCluster]:
        """Cluster indicators based on correlation graph."""
        logger.info(f"Starting graph-based clustering for {len(indicators)} indicators")
        
        # Build correlation graph
        graph = self._build_correlation_graph(correlations)
        
        # Detect communities using Louvain-like algorithm
        communities = self._detect_communities(graph)
        
        # Create indicator clusters from communities
        clusters = []
        indicator_map = {ind.id: ind for ind in indicators}
        
        for i, community in enumerate(communities):
            if len(community) >= self.min_cluster_size and len(community) <= self.max_cluster_size:
                cluster = self._create_cluster_from_community(
                    community, indicator_map, correlations, f"graph_cluster_{i}"
                )
                if cluster:
                    clusters.append(cluster)
        
        logger.info(f"Graph-based clustering produced {len(clusters)} clusters")
        return clusters
    
    def _build_correlation_graph(self, correlations: List[CorrelationResult]) -> Dict[str, Dict[str, float]]:
        """Build weighted correlation graph."""
        graph = defaultdict(dict)
        
        for corr in correlations:
            if corr.score >= self.min_correlation_score:
                graph[corr.indicator1_id][corr.indicator2_id] = corr.score
                graph[corr.indicator2_id][corr.indicator1_id] = corr.score
        
        return dict(graph)
    
    def _detect_communities(self, graph: Dict[str, Dict[str, float]]) -> List[Set[str]]:
        """Detect communities using a simple greedy modularity optimization."""
        nodes = set(graph.keys())
        communities = []
        visited = set()
        
        # Simple connected components as a baseline
        def dfs(node, component):
            if node in visited:
                return
            visited.add(node)
            component.add(node)
            
            for neighbor in graph.get(node, {}):
                if graph[node][neighbor] >= self.min_correlation_score:
                    dfs(neighbor, component)
        
        for node in nodes:
            if node not in visited:
                component = set()
                dfs(node, component)
                if len(component) >= self.min_cluster_size:
                    communities.append(component)
        
        # Further refine using modularity-based splitting
        refined_communities = []
        for community in communities:
            refined = self._refine_community(community, graph)
            refined_communities.extend(refined)
        
        return refined_communities
    
    def _refine_community(self, community: Set[str], 
                         graph: Dict[str, Dict[str, float]]) -> List[Set[str]]:
        """Refine community using modularity optimization."""
        # For now, implement a simple density-based refinement
        if len(community) <= 3:
            return [community]
        
        # Calculate internal connectivity
        internal_edges = 0
        total_possible = len(community) * (len(community) - 1) / 2
        
        for node1 in community:
            for node2 in community:
                if node1 < node2 and node2 in graph.get(node1, {}):
                    internal_edges += 1
        
        density = internal_edges / total_possible if total_possible > 0 else 0
        
        # If density is too low, try to split
        if density < 0.3 and len(community) > 5:
            return self._split_community(community, graph)
        
        return [community]
    
    def _split_community(self, community: Set[str], 
                        graph: Dict[str, Dict[str, float]]) -> List[Set[str]]:
        """Split community into subcommunities."""
        # Simple approach: find the most central node and build clusters around it
        community_list = list(community)
        
        # Calculate centrality (sum of edge weights)
        centrality = {}
        for node in community_list:
            centrality[node] = sum(
                graph.get(node, {}).get(neighbor, 0)
                for neighbor in community_list
                if neighbor != node
            )
        
        # Start with most central node
        sorted_nodes = sorted(community_list, key=lambda x: centrality[x], reverse=True)
        
        clusters = []
        remaining = set(community)
        
        for seed in sorted_nodes[:2]:  # Try up to 2 subclusters
            if seed not in remaining:
                continue
                
            subcluster = {seed}
            remaining.remove(seed)
            
            # Add well-connected neighbors
            for node in list(remaining):
                if graph.get(seed, {}).get(node, 0) >= self.min_correlation_score:
                    subcluster.add(node)
                    remaining.remove(node)
            
            if len(subcluster) >= self.min_cluster_size:
                clusters.append(subcluster)
        
        # Add remaining nodes to the best fitting cluster or as a separate cluster
        if remaining:
            if len(remaining) >= self.min_cluster_size:
                clusters.append(remaining)
            elif clusters:
                # Add to the cluster with strongest connection
                best_cluster = max(clusters, key=lambda c: max(
                    graph.get(list(remaining)[0], {}).get(node, 0)
                    for node in c
                ))
                best_cluster.update(remaining)
        
        return clusters if len(clusters) > 1 else [community]
    
    def _create_cluster_from_community(self, community: Set[str], 
                                     indicator_map: Dict[str, NormalizedIndicator],
                                     correlations: List[CorrelationResult],
                                     cluster_id: str) -> Optional[IndicatorCluster]:
        """Create an IndicatorCluster from a community."""
        try:
            indicators = [indicator_map[ind_id] for ind_id in community if ind_id in indicator_map]
            
            if not indicators:
                return None
            
            # Extract cluster features
            indicator_types = [ind.indicator_type for ind in indicators]
            primary_types = [t for t, count in Counter(indicator_types).most_common(3)]
            
            # Time range
            timestamps = []
            for ind in indicators:
                try:
                    ts = datetime.fromisoformat(ind.created.replace('Z', '+00:00'))
                    timestamps.append(ts)
                except:
                    continue
            
            if timestamps:
                timeframe = (min(timestamps), max(timestamps))
            else:
                now = datetime.utcnow()
                timeframe = (now, now)
            
            # Geographic regions from enrichment
            geo_regions = set()
            sources = set()
            
            for ind in indicators:
                sources.add(ind.source)
                enrich = ind.context.get('enrichment', {})
                geo = enrich.get('geolocation', {})
                if geo.get('country'):
                    geo_regions.add(geo['country'])
            
            # Cluster correlations
            cluster_correlations = [
                corr for corr in correlations
                if corr.indicator1_id in community and corr.indicator2_id in community
            ]
            
            # Calculate cluster score
            cluster_score = self._calculate_cluster_score(indicators, cluster_correlations)
            
            # Determine cluster type
            cluster_type = self._determine_cluster_type(indicators, cluster_correlations)
            
            # Assess quality
            quality = self._assess_cluster_quality(cluster_score, len(indicators), cluster_correlations)
            
            # Confidence based on correlation strength and diversity
            confidence = self._calculate_cluster_confidence(cluster_correlations, indicators)
            
            return IndicatorCluster(
                id=cluster_id,
                cluster_type=cluster_type,
                indicator_ids=community,
                cluster_score=cluster_score,
                quality=quality,
                created_at=datetime.utcnow(),
                primary_indicator_types=primary_types,
                timeframe=timeframe,
                geographic_regions=geo_regions,
                sources=sources,
                correlation_evidence=[corr.to_dict() for corr in cluster_correlations],
                cluster_features=self._extract_cluster_features(indicators, cluster_correlations),
                confidence=confidence
            )
            
        except Exception as e:
            logger.error(f"Error creating cluster from community: {e}")
            return None
    
    def _calculate_cluster_score(self, indicators: List[NormalizedIndicator],
                               correlations: List[CorrelationResult]) -> float:
        """Calculate overall cluster coherence score."""
        if not correlations:
            return 0.0
        
        # Average correlation score weighted by correlation strength
        total_weighted_score = 0.0
        total_weight = 0.0
        
        for corr in correlations:
            weight = {
                CorrelationStrength.VERY_STRONG: 1.0,
                CorrelationStrength.STRONG: 0.8,
                CorrelationStrength.MODERATE: 0.6,
                CorrelationStrength.WEAK: 0.4
            }.get(corr.strength, 0.4)
            
            total_weighted_score += corr.score * weight
            total_weight += weight
        
        base_score = total_weighted_score / total_weight if total_weight > 0 else 0.0
        
        # Bonus for temporal clustering
        time_diversity = self._calculate_temporal_diversity(indicators)
        temporal_bonus = max(0, 1 - time_diversity) * 0.2  # Up to 20% bonus for tight temporal clustering
        
        return min(base_score + temporal_bonus, 1.0)
    
    def _calculate_temporal_diversity(self, indicators: List[NormalizedIndicator]) -> float:
        """Calculate temporal diversity (0 = all same time, 1 = very spread out)."""
        timestamps = []
        for ind in indicators:
            try:
                ts = datetime.fromisoformat(ind.created.replace('Z', '+00:00'))
                timestamps.append(ts.timestamp())
            except:
                continue
        
        if len(timestamps) < 2:
            return 0.0
        
        time_span = max(timestamps) - min(timestamps)
        # Normalize by a week (604800 seconds)
        return min(time_span / 604800, 1.0)
    
    def _determine_cluster_type(self, indicators: List[NormalizedIndicator],
                              correlations: List[CorrelationResult]) -> ClusterType:
        """Determine the type of cluster based on indicators and correlations."""
        # Analyze correlation types
        correlation_types = [corr.correlation_type for corr in correlations]
        type_counts = Counter(correlation_types)
        
        # Analyze indicator types
        indicator_types = [ind.indicator_type for ind in indicators]
        indicator_type_counts = Counter(indicator_types)
        
        # Analyze temporal concentration
        time_diversity = self._calculate_temporal_diversity(indicators)
        
        # Decision logic
        if time_diversity < 0.1:  # Very tight temporal clustering
            return ClusterType.TEMPORAL_BURST
        
        # Network infrastructure clustering
        network_types = {IndicatorType.IP, IndicatorType.IPV4, IndicatorType.IPV6, IndicatorType.DOMAIN}
        network_indicators = sum(1 for t in indicator_types if t in network_types)
        
        if network_indicators > len(indicators) * 0.7:
            if type_counts.get(CorrelationType.NETWORK, 0) > len(correlations) * 0.6:
                return ClusterType.INFRASTRUCTURE
        
        # Malware family clustering (file hashes with similar patterns)
        hash_types = {IndicatorType.MD5, IndicatorType.SHA1, IndicatorType.SHA256}
        hash_indicators = sum(1 for t in indicator_types if t in hash_types)
        
        if hash_indicators > len(indicators) * 0.5:
            return ClusterType.MALWARE_FAMILY
        
        # Campaign clustering (mixed indicators with temporal and attribute correlations)
        if (type_counts.get(CorrelationType.TEMPORAL, 0) > 0 and
            type_counts.get(CorrelationType.ATTRIBUTE, 0) > 0 and
            len(set(ind.source for ind in indicators)) > 1):
            return ClusterType.CAMPAIGN
        
        # Attack pattern (behavioral correlations)
        if type_counts.get(CorrelationType.BEHAVIORAL, 0) > len(correlations) * 0.4:
            return ClusterType.ATTACK_PATTERN
        
        # Default to campaign
        return ClusterType.CAMPAIGN
    
    def _assess_cluster_quality(self, cluster_score: float, cluster_size: int,
                              correlations: List[CorrelationResult]) -> ClusterQuality:
        """Assess the quality of the cluster."""
        # Base quality on cluster score
        if cluster_score >= 0.7:
            base_quality = ClusterQuality.HIGH
        elif cluster_score >= 0.5:
            base_quality = ClusterQuality.MEDIUM
        else:
            base_quality = ClusterQuality.LOW
        
        # Adjust based on cluster size and correlation density
        correlation_density = len(correlations) / (cluster_size * (cluster_size - 1) / 2) if cluster_size > 1 else 0
        
        if correlation_density >= 0.3 and base_quality != ClusterQuality.LOW:
            return ClusterQuality.HIGH
        elif correlation_density >= 0.15 and base_quality == ClusterQuality.HIGH:
            return ClusterQuality.HIGH
        elif correlation_density < 0.1:
            return ClusterQuality.LOW
        
        return base_quality
    
    def _calculate_cluster_confidence(self, correlations: List[CorrelationResult],
                                    indicators: List[NormalizedIndicator]) -> float:
        """Calculate confidence in the cluster."""
        if not correlations:
            return 0.3
        
        # Average correlation confidence
        avg_corr_confidence = sum(corr.confidence for corr in correlations) / len(correlations)
        
        # Indicator quality (confidence levels)
        avg_ind_confidence = sum(ind.confidence for ind in indicators) / len(indicators) / 100.0
        
        # Correlation strength diversity
        strength_types = len(set(corr.strength for corr in correlations))
        strength_bonus = min(strength_types * 0.1, 0.2)
        
        # Combine factors
        confidence = (avg_corr_confidence * 0.5 + avg_ind_confidence * 0.3 + strength_bonus)
        
        return min(max(confidence, 0.0), 1.0)
    
    def _extract_cluster_features(self, indicators: List[NormalizedIndicator],
                                correlations: List[CorrelationResult]) -> Dict[str, Any]:
        """Extract descriptive features of the cluster."""
        features = {}
        
        # Size metrics
        features['size'] = len(indicators)
        features['correlation_count'] = len(correlations)
        
        # Type distribution
        type_dist = Counter(ind.indicator_type.value for ind in indicators)
        features['indicator_type_distribution'] = dict(type_dist)
        
        # Source distribution
        source_dist = Counter(ind.source for ind in indicators)
        features['source_distribution'] = dict(source_dist)
        
        # Correlation type distribution
        corr_type_dist = Counter(corr.correlation_type.value for corr in correlations)
        features['correlation_type_distribution'] = dict(corr_type_dist)
        
        # Temporal features
        timestamps = []
        for ind in indicators:
            try:
                ts = datetime.fromisoformat(ind.created.replace('Z', '+00:00'))
                timestamps.append(ts)
            except:
                continue
        
        if timestamps:
            features['temporal_span_hours'] = (max(timestamps) - min(timestamps)).total_seconds() / 3600
            features['earliest_indicator'] = min(timestamps).isoformat()
            features['latest_indicator'] = max(timestamps).isoformat()
        
        # Enrichment features
        geo_countries = []
        reputation_scores = []
        
        for ind in indicators:
            enrich = ind.context.get('enrichment', {})
            
            geo = enrich.get('geolocation', {})
            if geo.get('country'):
                geo_countries.append(geo['country'])
            
            rep = enrich.get('reputation', {})
            if rep.get('reputation_score') is not None:
                reputation_scores.append(rep['reputation_score'])
        
        if geo_countries:
            features['geographic_diversity'] = len(set(geo_countries))
            features['primary_countries'] = [country for country, _ in Counter(geo_countries).most_common(3)]
        
        if reputation_scores:
            features['avg_reputation_score'] = sum(reputation_scores) / len(reputation_scores)
            features['reputation_range'] = [min(reputation_scores), max(reputation_scores)]
        
        return features


class TemporalClustering:
    """Clustering based on temporal patterns and bursts."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize temporal clustering."""
        self.config = config or {}
        
        # Temporal parameters
        self.burst_window = timedelta(minutes=self.config.get('burst_window_minutes', 60))
        self.min_burst_size = self.config.get('min_burst_size', 3)
        self.campaign_window = timedelta(days=self.config.get('campaign_window_days', 7))
    
    def cluster_temporal_bursts(self, indicators: List[NormalizedIndicator]) -> List[IndicatorCluster]:
        """Find temporal bursts of indicators."""
        logger.info(f"Starting temporal burst clustering for {len(indicators)} indicators")
        
        # Sort indicators by timestamp
        timestamped_indicators = []
        for ind in indicators:
            try:
                ts = datetime.fromisoformat(ind.created.replace('Z', '+00:00'))
                timestamped_indicators.append((ts, ind))
            except:
                continue
        
        timestamped_indicators.sort(key=lambda x: x[0])
        
        # Find temporal bursts using sliding window
        bursts = []
        current_burst = []
        
        for i, (timestamp, indicator) in enumerate(timestamped_indicators):
            # Start new burst or continue current one
            if not current_burst:
                current_burst = [(timestamp, indicator)]
            else:
                # Check if within burst window
                burst_start = current_burst[0][0]
                if timestamp - burst_start <= self.burst_window:
                    current_burst.append((timestamp, indicator))
                else:
                    # End current burst if it's large enough
                    if len(current_burst) >= self.min_burst_size:
                        bursts.append(current_burst)
                    
                    # Start new burst
                    current_burst = [(timestamp, indicator)]
        
        # Don't forget the last burst
        if len(current_burst) >= self.min_burst_size:
            bursts.append(current_burst)
        
        # Convert bursts to clusters
        clusters = []
        for i, burst in enumerate(bursts):
            cluster = self._create_temporal_cluster(burst, f"temporal_burst_{i}")
            if cluster:
                clusters.append(cluster)
        
        logger.info(f"Temporal clustering found {len(clusters)} burst clusters")
        return clusters
    
    def _create_temporal_cluster(self, burst: List[Tuple[datetime, NormalizedIndicator]],
                               cluster_id: str) -> Optional[IndicatorCluster]:
        """Create a temporal cluster from a burst."""
        try:
            indicators = [ind for _, ind in burst]
            timestamps = [ts for ts, _ in burst]
            
            # Cluster features
            primary_types = [t for t, count in Counter(ind.indicator_type for ind in indicators).most_common(3)]
            timeframe = (min(timestamps), max(timestamps))
            
            sources = set(ind.source for ind in indicators)
            geo_regions = set()
            
            for ind in indicators:
                geo = ind.context.get('enrichment', {}).get('geolocation', {})
                if geo.get('country'):
                    geo_regions.add(geo['country'])
            
            # Calculate burst intensity
            time_span = (timeframe[1] - timeframe[0]).total_seconds()
            intensity = len(indicators) / max(time_span / 3600, 0.1)  # indicators per hour
            
            cluster_score = min(intensity / 10.0, 1.0)  # Normalize intensity
            
            # High burst intensity gets high quality
            if intensity >= 5:
                quality = ClusterQuality.HIGH
            elif intensity >= 2:
                quality = ClusterQuality.MEDIUM
            else:
                quality = ClusterQuality.LOW
            
            return IndicatorCluster(
                id=cluster_id,
                cluster_type=ClusterType.TEMPORAL_BURST,
                indicator_ids=set(ind.id for ind in indicators),
                cluster_score=cluster_score,
                quality=quality,
                created_at=datetime.utcnow(),
                primary_indicator_types=primary_types,
                timeframe=timeframe,
                geographic_regions=geo_regions,
                sources=sources,
                correlation_evidence=[],
                cluster_features={
                    'burst_intensity_per_hour': intensity,
                    'burst_duration_minutes': time_span / 60,
                    'indicator_density': len(indicators) / max(time_span / 60, 1)
                },
                confidence=min(intensity / 5.0, 1.0)
            )
            
        except Exception as e:
            logger.error(f"Error creating temporal cluster: {e}")
            return None


class ClusteringOrchestrator:
    """Orchestrates different clustering algorithms."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize clustering orchestrator."""
        self.config = config or {}
        
        # Initialize clustering algorithms
        self.graph_clustering = GraphBasedClustering(self.config.get('graph', {}))
        self.temporal_clustering = TemporalClustering(self.config.get('temporal', {}))
        
        # Correlation engine for generating correlations if needed
        self.correlation_engine = CorrelationEngine(self.config.get('correlation', {}))
        
        logger.info("Clustering orchestrator initialized")
    
    def cluster_indicators(self, indicators: List[NormalizedIndicator],
                          correlations: Optional[List[CorrelationResult]] = None) -> List[IndicatorCluster]:
        """Perform comprehensive clustering analysis."""
        logger.info(f"Starting comprehensive clustering for {len(indicators)} indicators")
        
        # Generate correlations if not provided
        if correlations is None:
            logger.info("Generating correlations for clustering...")
            correlations = self.correlation_engine.batch_correlation_analysis(indicators)
        
        all_clusters = []
        
        # Graph-based clustering
        try:
            graph_clusters = self.graph_clustering.cluster_indicators(indicators, correlations)
            all_clusters.extend(graph_clusters)
            logger.info(f"Graph clustering produced {len(graph_clusters)} clusters")
        except Exception as e:
            logger.error(f"Graph clustering failed: {e}")
        
        # Temporal clustering
        try:
            temporal_clusters = self.temporal_clustering.cluster_temporal_bursts(indicators)
            all_clusters.extend(temporal_clusters)
            logger.info(f"Temporal clustering produced {len(temporal_clusters)} clusters")
        except Exception as e:
            logger.error(f"Temporal clustering failed: {e}")
        
        # Remove overlapping clusters and merge similar ones
        deduplicated_clusters = self._deduplicate_clusters(all_clusters)
        
        logger.info(f"Total clusters after deduplication: {len(deduplicated_clusters)}")
        return deduplicated_clusters
    
    def _deduplicate_clusters(self, clusters: List[IndicatorCluster]) -> List[IndicatorCluster]:
        """Remove overlapping clusters and merge similar ones."""
        if not clusters:
            return clusters
        
        # Calculate overlap matrix
        overlap_threshold = 0.5  # 50% overlap threshold
        
        deduplicated = []
        used_indices = set()
        
        for i, cluster1 in enumerate(clusters):
            if i in used_indices:
                continue
            
            # Check for significant overlaps with remaining clusters
            merged_cluster = cluster1
            merged_indices = {i}
            
            for j, cluster2 in enumerate(clusters[i+1:], i+1):
                if j in used_indices:
                    continue
                
                # Calculate Jaccard similarity
                overlap = len(cluster1.indicator_ids.intersection(cluster2.indicator_ids))
                union = len(cluster1.indicator_ids.union(cluster2.indicator_ids))
                jaccard = overlap / union if union > 0 else 0
                
                if jaccard >= overlap_threshold:
                    # Merge clusters
                    merged_cluster = self._merge_clusters(merged_cluster, cluster2)
                    merged_indices.add(j)
            
            # Mark all merged indices as used
            used_indices.update(merged_indices)
            deduplicated.append(merged_cluster)
        
        return deduplicated
    
    def _merge_clusters(self, cluster1: IndicatorCluster, cluster2: IndicatorCluster) -> IndicatorCluster:
        """Merge two overlapping clusters."""
        # Combine indicator IDs
        merged_ids = cluster1.indicator_ids.union(cluster2.indicator_ids)
        
        # Take the better cluster score
        merged_score = max(cluster1.cluster_score, cluster2.cluster_score)
        
        # Take the higher quality
        quality_order = {ClusterQuality.HIGH: 3, ClusterQuality.MEDIUM: 2, ClusterQuality.LOW: 1}
        merged_quality = cluster1.quality if quality_order[cluster1.quality] >= quality_order[cluster2.quality] else cluster2.quality
        
        # Merge timeframes
        merged_timeframe = (
            min(cluster1.timeframe[0], cluster2.timeframe[0]),
            max(cluster1.timeframe[1], cluster2.timeframe[1])
        )
        
        # Combine other attributes
        merged_types = list(set(cluster1.primary_indicator_types + cluster2.primary_indicator_types))
        merged_geo = cluster1.geographic_regions.union(cluster2.geographic_regions)
        merged_sources = cluster1.sources.union(cluster2.sources)
        
        # Combine evidence
        merged_evidence = cluster1.correlation_evidence + cluster2.correlation_evidence
        
        # Merge features
        merged_features = {**cluster1.cluster_features, **cluster2.cluster_features}
        merged_features['merged_from'] = [cluster1.id, cluster2.id]
        
        # Average confidence
        merged_confidence = (cluster1.confidence + cluster2.confidence) / 2
        
        return IndicatorCluster(
            id=f"merged_{cluster1.id}_{cluster2.id}",
            cluster_type=cluster1.cluster_type,  # Keep the first cluster's type
            indicator_ids=merged_ids,
            cluster_score=merged_score,
            quality=merged_quality,
            created_at=datetime.utcnow(),
            primary_indicator_types=merged_types,
            timeframe=merged_timeframe,
            geographic_regions=merged_geo,
            sources=merged_sources,
            correlation_evidence=merged_evidence,
            cluster_features=merged_features,
            confidence=merged_confidence
        )