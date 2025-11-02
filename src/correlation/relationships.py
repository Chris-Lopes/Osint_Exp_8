"""
Advanced relationship detection algorithms for threat intelligence correlation.

This module implements sophisticated algorithms to identify connections between
different threat indicators based on context, timing, infrastructure, attribution
patterns, and behavioral similarities.
"""

import logging
import math
import statistics
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, Counter
import re
import hashlib

try:
    from ..normalizers.schema import NormalizedIndicator, IndicatorType
    from .engine import GraphNode, GraphRelationship, NodeType, RelationshipType
except ImportError:
    from normalizers.schema import NormalizedIndicator, IndicatorType
    from correlation.engine import GraphNode, GraphRelationship, NodeType, RelationshipType

logger = logging.getLogger(__name__)


class RelationshipStrength(Enum):
    """Strength levels for relationships."""
    WEAK = "weak"
    MODERATE = "moderate"
    STRONG = "strong"
    CRITICAL = "critical"


@dataclass
class RelationshipEvidence:
    """Evidence supporting a relationship."""
    
    evidence_type: str
    confidence: float
    details: Dict[str, Any] = field(default_factory=dict)
    source: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'evidence_type': self.evidence_type,
            'confidence': self.confidence,
            'details': self.details,
            'source': self.source
        }


class InfrastructureAnalyzer:
    """Analyzes infrastructure relationships between indicators."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize infrastructure analyzer."""
        self.config = config or {}
        
        # Configuration
        self.asn_confidence = self.config.get('asn_confidence', 0.9)
        self.country_confidence = self.config.get('country_confidence', 0.5)
        self.subnet_confidence = self.config.get('subnet_confidence', 0.8)
        self.domain_similarity_threshold = self.config.get('domain_similarity_threshold', 0.7)
        
        logger.debug("Infrastructure analyzer initialized")
    
    def detect_infrastructure_relationships(self, 
                                         indicators: List[NormalizedIndicator]) -> List[GraphRelationship]:
        """Detect infrastructure-based relationships."""
        
        relationships = []
        
        # ASN-based relationships
        asn_relationships = self._analyze_asn_relationships(indicators)
        relationships.extend(asn_relationships)
        
        # IP subnet relationships
        subnet_relationships = self._analyze_subnet_relationships(indicators)
        relationships.extend(subnet_relationships)
        
        # Domain similarity relationships
        domain_relationships = self._analyze_domain_relationships(indicators)
        relationships.extend(domain_relationships)
        
        # DNS resolution relationships
        dns_relationships = self._analyze_dns_relationships(indicators)
        relationships.extend(dns_relationships)
        
        logger.debug(f"Detected {len(relationships)} infrastructure relationships")
        return relationships
    
    def _analyze_asn_relationships(self, indicators: List[NormalizedIndicator]) -> List[GraphRelationship]:
        """Analyze ASN-based relationships."""
        
        relationships = []
        
        # Group indicators by ASN
        asn_groups = defaultdict(list)
        
        for indicator in indicators:
            if hasattr(indicator, 'asn') and indicator.asn:
                asn_groups[indicator.asn].append(indicator)
        
        # Create relationships for indicators sharing ASNs
        for asn, grouped_indicators in asn_groups.items():
            if len(grouped_indicators) < 2:
                continue
            
            # Calculate ASN reputation (lower ASN numbers often more established)
            asn_reputation = self._calculate_asn_reputation(asn, grouped_indicators)
            
            for i, indicator1 in enumerate(grouped_indicators):
                for indicator2 in grouped_indicators[i+1:]:
                    
                    # Evidence for ASN sharing
                    evidence = [
                        RelationshipEvidence(
                            evidence_type="shared_asn",
                            confidence=self.asn_confidence,
                            details={
                                'asn': asn,
                                'asn_reputation': asn_reputation,
                                'indicator_count': len(grouped_indicators)
                            }
                        )
                    ]
                    
                    relationship = GraphRelationship(
                        source_node_id=f"indicator_{indicator1.id}",
                        target_node_id=f"indicator_{indicator2.id}",
                        relationship_type=RelationshipType.SHARES_INFRASTRUCTURE,
                        weight=0.8,
                        confidence=self.asn_confidence * asn_reputation,
                        evidence=[e.to_dict() for e in evidence],
                        sources={getattr(indicator1, 'source', 'unknown'), getattr(indicator2, 'source', 'unknown')}
                    )
                    
                    relationships.append(relationship)
        
        return relationships
    
    def _analyze_subnet_relationships(self, indicators: List[NormalizedIndicator]) -> List[GraphRelationship]:
        """Analyze subnet-based relationships for IP indicators."""
        
        relationships = []
        
        # Group IP indicators by /24 and /16 subnets
        subnet_groups_24 = defaultdict(list)
        subnet_groups_16 = defaultdict(list)
        
        for indicator in indicators:
            if indicator.indicator_type == IndicatorType.IP_ADDRESS:
                ip_parts = indicator.value.split('.')
                if len(ip_parts) == 4:
                    subnet_24 = '.'.join(ip_parts[:3]) + '.0/24'
                    subnet_16 = '.'.join(ip_parts[:2]) + '.0.0/16'
                    
                    subnet_groups_24[subnet_24].append(indicator)
                    subnet_groups_16[subnet_16].append(indicator)
        
        # Analyze /24 relationships (higher confidence)
        for subnet, grouped_indicators in subnet_groups_24.items():
            if len(grouped_indicators) >= 2:
                relationships.extend(
                    self._create_subnet_relationships(grouped_indicators, subnet, 0.8)
                )
        
        # Analyze /16 relationships (lower confidence, only if significant clustering)
        for subnet, grouped_indicators in subnet_groups_16.items():
            if len(grouped_indicators) >= 5:  # More stringent threshold
                relationships.extend(
                    self._create_subnet_relationships(grouped_indicators, subnet, 0.4)
                )
        
        return relationships
    
    def _analyze_domain_relationships(self, indicators: List[NormalizedIndicator]) -> List[GraphRelationship]:
        """Analyze domain similarity relationships."""
        
        relationships = []
        
        # Get domain indicators
        domain_indicators = [
            ind for ind in indicators 
            if ind.indicator_type in {IndicatorType.DOMAIN, IndicatorType.URL}
        ]
        
        for i, indicator1 in enumerate(domain_indicators):
            for indicator2 in domain_indicators[i+1:]:
                
                domain1 = self._extract_domain(indicator1.value)
                domain2 = self._extract_domain(indicator2.value)
                
                if domain1 and domain2:
                    similarity = self._calculate_domain_similarity(domain1, domain2)
                    
                    if similarity >= self.domain_similarity_threshold:
                        
                        evidence = [
                            RelationshipEvidence(
                                evidence_type="domain_similarity",
                                confidence=similarity,
                                details={
                                    'domain1': domain1,
                                    'domain2': domain2,
                                    'similarity_score': similarity,
                                    'similarity_type': self._determine_similarity_type(domain1, domain2)
                                }
                            )
                        ]
                        
                        relationship = GraphRelationship(
                            source_node_id=f"indicator_{indicator1.id}",
                            target_node_id=f"indicator_{indicator2.id}",
                            relationship_type=RelationshipType.SIMILAR_TO,
                            weight=similarity,
                            confidence=similarity,
                            evidence=[e.to_dict() for e in evidence],
                            sources={getattr(indicator1, 'source', 'unknown'), getattr(indicator2, 'source', 'unknown')}
                        )
                        
                        relationships.append(relationship)
        
        return relationships
    
    def _analyze_dns_relationships(self, indicators: List[NormalizedIndicator]) -> List[GraphRelationship]:
        """Analyze DNS resolution relationships."""
        
        relationships = []
        
        # This would ideally use DNS resolution data
        # For now, we'll simulate based on enrichment data
        
        for indicator in indicators:
            if hasattr(indicator, 'dns_resolutions') and indicator.dns_resolutions:
                for resolution in indicator.dns_resolutions:
                    
                    # Find matching indicators
                    target_indicators = [
                        ind for ind in indicators
                        if ind.value == resolution.get('resolved_to') or ind.value == resolution.get('hostname')
                    ]
                    
                    for target_indicator in target_indicators:
                        if target_indicator.id != indicator.id:
                            
                            evidence = [
                                RelationshipEvidence(
                                    evidence_type="dns_resolution",
                                    confidence=0.9,
                                    details={
                                        'resolution_type': resolution.get('type', 'unknown'),
                                        'first_seen': resolution.get('first_seen'),
                                        'last_seen': resolution.get('last_seen')
                                    }
                                )
                            ]
                            
                            relationship = GraphRelationship(
                                source_node_id=f"indicator_{indicator.id}",
                                target_node_id=f"indicator_{target_indicator.id}",
                                relationship_type=RelationshipType.RESOLVES_TO,
                                weight=0.9,
                                confidence=0.9,
                                evidence=[e.to_dict() for e in evidence],
                                sources={getattr(indicator, 'source', 'unknown')}
                            )
                            
                            relationships.append(relationship)
        
        return relationships
    
    def _calculate_asn_reputation(self, asn: int, indicators: List[NormalizedIndicator]) -> float:
        """Calculate ASN reputation score."""
        
        # Lower ASN numbers tend to be more established (simplistic heuristic)
        asn_age_factor = max(0.3, 1.0 - (asn / 100000))  # Normalize by max common ASN
        
        # Factor in number of indicators (more indicators might indicate more activity)
        activity_factor = min(1.0, len(indicators) / 10)
        
        # Combine factors
        reputation = (asn_age_factor + activity_factor) / 2
        
        return min(1.0, max(0.1, reputation))
    
    def _create_subnet_relationships(self, 
                                  indicators: List[NormalizedIndicator], 
                                  subnet: str, 
                                  base_confidence: float) -> List[GraphRelationship]:
        """Create relationships for indicators in same subnet."""
        
        relationships = []
        
        for i, indicator1 in enumerate(indicators):
            for indicator2 in indicators[i+1:]:
                
                evidence = [
                    RelationshipEvidence(
                        evidence_type="subnet_sharing",
                        confidence=base_confidence,
                        details={
                            'subnet': subnet,
                            'ip_count': len(indicators)
                        }
                    )
                ]
                
                relationship = GraphRelationship(
                    source_node_id=f"indicator_{indicator1.id}",
                    target_node_id=f"indicator_{indicator2.id}",
                    relationship_type=RelationshipType.SHARES_INFRASTRUCTURE,
                    weight=base_confidence,
                    confidence=base_confidence,
                    evidence=[e.to_dict() for e in evidence],
                    sources={getattr(indicator1, 'source', 'unknown'), getattr(indicator2, 'source', 'unknown')}
                )
                
                relationships.append(relationship)
        
        return relationships
    
    def _extract_domain(self, value: str) -> Optional[str]:
        """Extract domain from URL or return domain directly."""
        
        if not value:
            return None
        
        # Handle URLs
        if value.startswith(('http://', 'https://')):
            try:
                from urllib.parse import urlparse
                parsed = urlparse(value)
                return parsed.netloc
            except:
                return None
        
        # Already a domain
        return value.lower()
    
    def _calculate_domain_similarity(self, domain1: str, domain2: str) -> float:
        """Calculate similarity between two domains."""
        
        if domain1 == domain2:
            return 1.0
        
        # Split domains into parts
        parts1 = domain1.split('.')
        parts2 = domain2.split('.')
        
        # Check for same TLD and SLD
        if len(parts1) >= 2 and len(parts2) >= 2:
            if parts1[-2:] == parts2[-2:]:  # Same SLD.TLD
                return 0.9
        
        # Check for same TLD
        if parts1[-1] == parts2[-1]:
            # Calculate Levenshtein-like similarity
            similarity = self._string_similarity(domain1, domain2)
            return similarity * 0.7  # Reduce for different SLD
        
        # General string similarity
        return self._string_similarity(domain1, domain2) * 0.5
    
    def _string_similarity(self, str1: str, str2: str) -> float:
        """Calculate string similarity using a simple metric."""
        
        if not str1 or not str2:
            return 0.0
        
        # Simple character-based similarity
        len1, len2 = len(str1), len(str2)
        max_len = max(len1, len2)
        
        if max_len == 0:
            return 1.0
        
        # Count common characters
        common = sum(1 for c1, c2 in zip(str1, str2) if c1 == c2)
        
        return common / max_len
    
    def _determine_similarity_type(self, domain1: str, domain2: str) -> str:
        """Determine the type of domain similarity."""
        
        parts1 = domain1.split('.')
        parts2 = domain2.split('.')
        
        if len(parts1) >= 2 and len(parts2) >= 2:
            if parts1[-2:] == parts2[-2:]:
                return "same_sld_tld"
        
        if parts1[-1] == parts2[-1]:
            return "same_tld"
        
        return "string_similarity"


class TemporalAnalyzer:
    """Analyzes temporal relationships between indicators."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize temporal analyzer."""
        self.config = config or {}
        
        # Temporal windows
        self.simultaneous_window_minutes = self.config.get('simultaneous_window_minutes', 15)
        self.sequential_window_hours = self.config.get('sequential_window_hours', 24)
        self.correlation_window_days = self.config.get('correlation_window_days', 7)
        
        # Confidence thresholds
        self.simultaneous_confidence = self.config.get('simultaneous_confidence', 0.9)
        self.sequential_confidence = self.config.get('sequential_confidence', 0.7)
        self.correlated_confidence = self.config.get('correlated_confidence', 0.5)
        
        logger.debug("Temporal analyzer initialized")
    
    def detect_temporal_relationships(self, 
                                   indicators: List[NormalizedIndicator]) -> List[GraphRelationship]:
        """Detect temporal relationships between indicators."""
        
        relationships = []
        
        # Filter indicators with temporal information
        timed_indicators = []
        for indicator in indicators:
            if hasattr(indicator, 'first_seen') and indicator.first_seen:
                timed_indicators.append(indicator)
        
        if len(timed_indicators) < 2:
            return relationships
        
        # Sort by first_seen time
        timed_indicators.sort(key=lambda x: x.first_seen)
        
        # Analyze temporal patterns
        for i, indicator1 in enumerate(timed_indicators):
            for j in range(i + 1, len(timed_indicators)):
                indicator2 = timed_indicators[j]
                
                # Calculate time difference
                time_diff = indicator2.first_seen - indicator1.first_seen
                
                # Stop if beyond correlation window
                if time_diff.days > self.correlation_window_days:
                    break
                
                # Determine relationship type based on time difference
                relationship = self._analyze_temporal_pair(indicator1, indicator2, time_diff)
                if relationship:
                    relationships.append(relationship)
        
        logger.debug(f"Detected {len(relationships)} temporal relationships")
        return relationships
    
    def _analyze_temporal_pair(self, 
                             indicator1: NormalizedIndicator, 
                             indicator2: NormalizedIndicator, 
                             time_diff: timedelta) -> Optional[GraphRelationship]:
        """Analyze temporal relationship between two indicators."""
        
        # Determine relationship type and confidence
        if time_diff.total_seconds() / 60 <= self.simultaneous_window_minutes:
            relationship_type = RelationshipType.OBSERVED_TOGETHER
            confidence = self.simultaneous_confidence
            weight = 0.9
            pattern_type = "simultaneous"
        elif time_diff.total_seconds() / 3600 <= self.sequential_window_hours:
            relationship_type = RelationshipType.SEQUENTIAL_ACTIVITY
            confidence = self.sequential_confidence
            weight = 0.7
            pattern_type = "sequential"
        else:
            relationship_type = RelationshipType.OBSERVED_TOGETHER
            confidence = self.correlated_confidence
            weight = 0.5
            pattern_type = "correlated"
        
        # Additional confidence factors
        confidence_factors = self._calculate_temporal_confidence_factors(
            indicator1, indicator2, time_diff
        )
        
        adjusted_confidence = confidence * confidence_factors['combined_factor']
        
        evidence = [
            RelationshipEvidence(
                evidence_type="temporal_correlation",
                confidence=adjusted_confidence,
                details={
                    'time_difference_seconds': time_diff.total_seconds(),
                    'pattern_type': pattern_type,
                    'confidence_factors': confidence_factors,
                    'first_seen_1': indicator1.first_seen.isoformat(),
                    'first_seen_2': indicator2.first_seen.isoformat()
                }
            )
        ]
        
        relationship = GraphRelationship(
            source_node_id=f"indicator_{indicator1.id}",
            target_node_id=f"indicator_{indicator2.id}",
            relationship_type=relationship_type,
            weight=weight * confidence_factors['combined_factor'],
            confidence=adjusted_confidence,
            evidence=[e.to_dict() for e in evidence],
            sources={getattr(indicator1, 'source', 'unknown'), getattr(indicator2, 'source', 'unknown')},
            first_observed=indicator1.first_seen,
            last_observed=indicator2.first_seen
        )
        
        return relationship
    
    def _calculate_temporal_confidence_factors(self, 
                                             indicator1: NormalizedIndicator, 
                                             indicator2: NormalizedIndicator, 
                                             time_diff: timedelta) -> Dict[str, float]:
        """Calculate factors that affect temporal correlation confidence."""
        
        factors = {}
        
        # Source reliability factor
        source1 = getattr(indicator1, 'source', 'unknown')
        source2 = getattr(indicator2, 'source', 'unknown')
        
        if source1 == source2:
            factors['source_factor'] = 1.0  # Same source
        else:
            # Different sources increase confidence in correlation
            factors['source_factor'] = 1.2
        
        # Confidence alignment factor
        conf1 = getattr(indicator1, 'confidence', 50)
        conf2 = getattr(indicator2, 'confidence', 50)
        
        avg_confidence = (conf1 + conf2) / 200  # Normalize to [0, 1]
        factors['confidence_factor'] = avg_confidence
        
        # Indicator type compatibility factor
        type_compat = self._calculate_type_compatibility(
            indicator1.indicator_type, indicator2.indicator_type
        )
        factors['type_compatibility'] = type_compat
        
        # Tag similarity factor
        tags1 = set(getattr(indicator1, 'tags', []))
        tags2 = set(getattr(indicator2, 'tags', []))
        
        if tags1 and tags2:
            tag_intersection = len(tags1.intersection(tags2))
            tag_union = len(tags1.union(tags2))
            factors['tag_similarity'] = tag_intersection / tag_union if tag_union > 0 else 0
        else:
            factors['tag_similarity'] = 0.5  # Neutral
        
        # Time precision factor (more precise times = higher confidence)
        time_precision = self._calculate_time_precision_factor(time_diff)
        factors['time_precision'] = time_precision
        
        # Combined factor
        factor_weights = {
            'source_factor': 0.2,
            'confidence_factor': 0.3,
            'type_compatibility': 0.2,
            'tag_similarity': 0.15,
            'time_precision': 0.15
        }
        
        combined = sum(factors[key] * factor_weights[key] for key in factor_weights)
        factors['combined_factor'] = min(1.0, max(0.1, combined))
        
        return factors
    
    def _calculate_type_compatibility(self, type1: IndicatorType, type2: IndicatorType) -> float:
        """Calculate compatibility between indicator types for temporal correlation."""
        
        # Define compatibility matrix
        compatibility_matrix = {
            (IndicatorType.IP_ADDRESS, IndicatorType.DOMAIN): 0.9,
            (IndicatorType.IP_ADDRESS, IndicatorType.URL): 0.8,
            (IndicatorType.DOMAIN, IndicatorType.URL): 0.9,
            (IndicatorType.FILE_HASH, IndicatorType.IP_ADDRESS): 0.7,
            (IndicatorType.FILE_HASH, IndicatorType.DOMAIN): 0.7,
            (IndicatorType.FILE_HASH, IndicatorType.URL): 0.8,
        }
        
        # Same type
        if type1 == type2:
            return 1.0
        
        # Check both directions
        key1 = (type1, type2)
        key2 = (type2, type1)
        
        return compatibility_matrix.get(key1, compatibility_matrix.get(key2, 0.5))
    
    def _calculate_time_precision_factor(self, time_diff: timedelta) -> float:
        """Calculate time precision factor based on time difference."""
        
        total_seconds = time_diff.total_seconds()
        
        # More precise (smaller) time differences get higher scores
        if total_seconds <= 60:  # Within 1 minute
            return 1.0
        elif total_seconds <= 300:  # Within 5 minutes
            return 0.9
        elif total_seconds <= 900:  # Within 15 minutes
            return 0.8
        elif total_seconds <= 3600:  # Within 1 hour
            return 0.7
        elif total_seconds <= 86400:  # Within 1 day
            return 0.6
        else:
            return 0.5


class BehavioralAnalyzer:
    """Analyzes behavioral patterns and contextual relationships."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize behavioral analyzer."""
        self.config = config or {}
        
        # Behavioral analysis settings
        self.tag_weight_threshold = self.config.get('tag_weight_threshold', 0.6)
        self.technique_confidence = self.config.get('technique_confidence', 0.8)
        self.malware_family_confidence = self.config.get('malware_family_confidence', 0.9)
        
        logger.debug("Behavioral analyzer initialized")
    
    def detect_behavioral_relationships(self, 
                                     indicators: List[NormalizedIndicator]) -> List[GraphRelationship]:
        """Detect behavioral and contextual relationships."""
        
        relationships = []
        
        # Tag-based relationships
        tag_relationships = self._analyze_tag_relationships(indicators)
        relationships.extend(tag_relationships)
        
        # Technique-based relationships
        technique_relationships = self._analyze_technique_relationships(indicators)
        relationships.extend(technique_relationships)
        
        # Malware family relationships
        malware_relationships = self._analyze_malware_family_relationships(indicators)
        relationships.extend(malware_relationships)
        
        # Target-based relationships
        target_relationships = self._analyze_target_relationships(indicators)
        relationships.extend(target_relationships)
        
        logger.debug(f"Detected {len(relationships)} behavioral relationships")
        return relationships
    
    def _analyze_tag_relationships(self, indicators: List[NormalizedIndicator]) -> List[GraphRelationship]:
        """Analyze relationships based on shared tags."""
        
        relationships = []
        
        # Calculate tag weights (more specific tags get higher weights)
        tag_weights = self._calculate_tag_weights(indicators)
        
        # Group indicators by tags
        tag_groups = defaultdict(list)
        
        for indicator in indicators:
            tags = getattr(indicator, 'tags', [])
            for tag in tags:
                tag_groups[tag].append(indicator)
        
        # Create relationships for high-value shared tags
        for tag, grouped_indicators in tag_groups.items():
            tag_weight = tag_weights.get(tag, 0.5)
            
            if tag_weight >= self.tag_weight_threshold and len(grouped_indicators) >= 2:
                
                for i, indicator1 in enumerate(grouped_indicators):
                    for indicator2 in grouped_indicators[i+1:]:
                        
                        evidence = [
                            RelationshipEvidence(
                                evidence_type="shared_tag",
                                confidence=tag_weight,
                                details={
                                    'tag': tag,
                                    'tag_weight': tag_weight,
                                    'indicator_count': len(grouped_indicators)
                                }
                            )
                        ]
                        
                        relationship = GraphRelationship(
                            source_node_id=f"indicator_{indicator1.id}",
                            target_node_id=f"indicator_{indicator2.id}",
                            relationship_type=RelationshipType.SIMILAR_TO,
                            weight=tag_weight,
                            confidence=tag_weight,
                            evidence=[e.to_dict() for e in evidence],
                            sources={getattr(indicator1, 'source', 'unknown'), getattr(indicator2, 'source', 'unknown')}
                        )
                        
                        relationships.append(relationship)
        
        return relationships
    
    def _analyze_technique_relationships(self, indicators: List[NormalizedIndicator]) -> List[GraphRelationship]:
        """Analyze relationships based on shared techniques."""
        
        relationships = []
        
        # Group indicators by techniques
        technique_groups = defaultdict(list)
        
        for indicator in indicators:
            techniques = getattr(indicator, 'techniques', [])
            for technique in techniques:
                technique_id = technique if isinstance(technique, str) else technique.get('id', str(technique))
                technique_groups[technique_id].append(indicator)
        
        # Create relationships for shared techniques
        for technique_id, grouped_indicators in technique_groups.items():
            if len(grouped_indicators) >= 2:
                
                # Calculate technique importance
                technique_importance = self._calculate_technique_importance(technique_id, grouped_indicators)
                
                for i, indicator1 in enumerate(grouped_indicators):
                    for indicator2 in grouped_indicators[i+1:]:
                        
                        evidence = [
                            RelationshipEvidence(
                                evidence_type="shared_technique",
                                confidence=self.technique_confidence,
                                details={
                                    'technique_id': technique_id,
                                    'technique_importance': technique_importance,
                                    'indicator_count': len(grouped_indicators)
                                }
                            )
                        ]
                        
                        relationship = GraphRelationship(
                            source_node_id=f"indicator_{indicator1.id}",
                            target_node_id=f"indicator_{indicator2.id}",
                            relationship_type=RelationshipType.USES_SAME_TTP,
                            weight=self.technique_confidence * technique_importance,
                            confidence=self.technique_confidence * technique_importance,
                            evidence=[e.to_dict() for e in evidence],
                            sources={getattr(indicator1, 'source', 'unknown'), getattr(indicator2, 'source', 'unknown')}
                        )
                        
                        relationships.append(relationship)
        
        return relationships
    
    def _analyze_malware_family_relationships(self, indicators: List[NormalizedIndicator]) -> List[GraphRelationship]:
        """Analyze relationships based on malware families."""
        
        relationships = []
        
        # Group indicators by malware families
        family_groups = defaultdict(list)
        
        for indicator in indicators:
            families = getattr(indicator, 'malware_families', [])
            for family in families:
                family_name = family if isinstance(family, str) else family.get('name', str(family))
                family_groups[family_name].append(indicator)
        
        # Create relationships for shared malware families
        for family_name, grouped_indicators in family_groups.items():
            if len(grouped_indicators) >= 2:
                
                for i, indicator1 in enumerate(grouped_indicators):
                    for indicator2 in grouped_indicators[i+1:]:
                        
                        evidence = [
                            RelationshipEvidence(
                                evidence_type="shared_malware_family",
                                confidence=self.malware_family_confidence,
                                details={
                                    'family_name': family_name,
                                    'indicator_count': len(grouped_indicators)
                                }
                            )
                        ]
                        
                        relationship = GraphRelationship(
                            source_node_id=f"indicator_{indicator1.id}",
                            target_node_id=f"indicator_{indicator2.id}",
                            relationship_type=RelationshipType.SAME_FAMILY,
                            weight=self.malware_family_confidence,
                            confidence=self.malware_family_confidence,
                            evidence=[e.to_dict() for e in evidence],
                            sources={getattr(indicator1, 'source', 'unknown'), getattr(indicator2, 'source', 'unknown')}
                        )
                        
                        relationships.append(relationship)
        
        return relationships
    
    def _analyze_target_relationships(self, indicators: List[NormalizedIndicator]) -> List[GraphRelationship]:
        """Analyze relationships based on target patterns."""
        
        relationships = []
        
        # Group indicators by targeting information
        target_groups = defaultdict(list)
        
        for indicator in indicators:
            # Extract targeting information from various fields
            targets = []
            
            if hasattr(indicator, 'targets') and indicator.targets:
                targets.extend(indicator.targets)
            
            if hasattr(indicator, 'sectors') and indicator.sectors:
                targets.extend([f"sector:{sector}" for sector in indicator.sectors])
            
            if hasattr(indicator, 'countries') and indicator.countries:
                targets.extend([f"country:{country}" for country in indicator.countries])
            
            # Extract from tags
            tags = getattr(indicator, 'tags', [])
            for tag in tags:
                if any(keyword in tag.lower() for keyword in ['target', 'victim', 'sector', 'industry']):
                    targets.append(f"tag:{tag}")
            
            for target in targets:
                target_groups[target].append(indicator)
        
        # Create relationships for shared targets
        for target, grouped_indicators in target_groups.items():
            if len(grouped_indicators) >= 2:
                
                target_confidence = self._calculate_target_confidence(target)
                
                for i, indicator1 in enumerate(grouped_indicators):
                    for indicator2 in grouped_indicators[i+1:]:
                        
                        evidence = [
                            RelationshipEvidence(
                                evidence_type="shared_target",
                                confidence=target_confidence,
                                details={
                                    'target': target,
                                    'indicator_count': len(grouped_indicators)
                                }
                            )
                        ]
                        
                        relationship = GraphRelationship(
                            source_node_id=f"indicator_{indicator1.id}",
                            target_node_id=f"indicator_{indicator2.id}",
                            relationship_type=RelationshipType.TARGETS_SAME,
                            weight=target_confidence,
                            confidence=target_confidence,
                            evidence=[e.to_dict() for e in evidence],
                            sources={getattr(indicator1, 'source', 'unknown'), getattr(indicator2, 'source', 'unknown')}
                        )
                        
                        relationships.append(relationship)
        
        return relationships
    
    def _calculate_tag_weights(self, indicators: List[NormalizedIndicator]) -> Dict[str, float]:
        """Calculate weights for tags based on specificity and frequency."""
        
        tag_counts = Counter()
        total_indicators = len(indicators)
        
        # Count tag occurrences
        for indicator in indicators:
            tags = getattr(indicator, 'tags', [])
            for tag in tags:
                tag_counts[tag] += 1
        
        # Calculate weights
        tag_weights = {}
        
        for tag, count in tag_counts.items():
            # Frequency factor (less common = more specific)
            frequency_factor = 1.0 - (count / total_indicators)
            
            # Specificity factor based on tag characteristics
            specificity_factor = self._calculate_tag_specificity(tag)
            
            # Combine factors
            weight = (frequency_factor + specificity_factor) / 2
            tag_weights[tag] = min(1.0, max(0.1, weight))
        
        return tag_weights
    
    def _calculate_tag_specificity(self, tag: str) -> float:
        """Calculate specificity of a tag."""
        
        tag_lower = tag.lower()
        
        # High-specificity tags
        high_specificity_keywords = [
            'apt', 'campaign', 'operation', 'family', 'variant',
            'backdoor', 'trojan', 'ransomware', 'stealer'
        ]
        
        # Medium-specificity tags
        medium_specificity_keywords = [
            'c2', 'cnc', 'exfil', 'lateral', 'persistence',
            'reconnaissance', 'delivery', 'exploitation'
        ]
        
        # Low-specificity tags (generic)
        low_specificity_keywords = [
            'malware', 'malicious', 'suspicious', 'bad',
            'threat', 'security', 'alert'
        ]
        
        if any(keyword in tag_lower for keyword in high_specificity_keywords):
            return 0.9
        elif any(keyword in tag_lower for keyword in medium_specificity_keywords):
            return 0.7
        elif any(keyword in tag_lower for keyword in low_specificity_keywords):
            return 0.3
        else:
            return 0.5  # Default for unknown tags
    
    def _calculate_technique_importance(self, technique_id: str, indicators: List[NormalizedIndicator]) -> float:
        """Calculate importance of a technique."""
        
        # This could be enhanced with MITRE ATT&CK data
        # For now, use simple heuristics
        
        technique_lower = technique_id.lower()
        
        # Critical techniques
        if any(keyword in technique_lower for keyword in ['t1055', 't1059', 't1083', 't1105']):
            return 1.0
        
        # High-importance techniques
        elif technique_lower.startswith('t1'):  # MITRE ATT&CK format
            return 0.8
        
        # Custom techniques or other formats
        else:
            return 0.6
    
    def _calculate_target_confidence(self, target: str) -> float:
        """Calculate confidence for target-based relationships."""
        
        target_lower = target.lower()
        
        # High-confidence targets
        if target.startswith('sector:') or target.startswith('country:'):
            return 0.8
        
        # Medium-confidence targets from tags
        elif target.startswith('tag:'):
            return 0.6
        
        # Direct target specifications
        else:
            return 0.7


class RelationshipDetector:
    """Main relationship detection coordinator."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize relationship detector."""
        self.config = config or {}
        
        # Initialize analyzers
        self.infrastructure_analyzer = InfrastructureAnalyzer(
            self.config.get('infrastructure', {})
        )
        
        self.temporal_analyzer = TemporalAnalyzer(
            self.config.get('temporal', {})
        )
        
        self.behavioral_analyzer = BehavioralAnalyzer(
            self.config.get('behavioral', {})
        )
        
        # Detection settings
        self.min_confidence_threshold = self.config.get('min_confidence_threshold', 0.3)
        self.enable_infrastructure_detection = self.config.get('enable_infrastructure_detection', True)
        self.enable_temporal_detection = self.config.get('enable_temporal_detection', True)
        self.enable_behavioral_detection = self.config.get('enable_behavioral_detection', True)
        
        logger.info("Relationship detector initialized")
    
    def detect_all_relationships(self, indicators: List[NormalizedIndicator]) -> List[GraphRelationship]:
        """Detect all types of relationships between indicators."""
        
        all_relationships = []
        
        try:
            logger.info(f"Detecting relationships for {len(indicators)} indicators")
            
            # Infrastructure relationships
            if self.enable_infrastructure_detection:
                infra_relationships = self.infrastructure_analyzer.detect_infrastructure_relationships(indicators)
                all_relationships.extend(infra_relationships)
                logger.debug(f"Found {len(infra_relationships)} infrastructure relationships")
            
            # Temporal relationships
            if self.enable_temporal_detection:
                temporal_relationships = self.temporal_analyzer.detect_temporal_relationships(indicators)
                all_relationships.extend(temporal_relationships)
                logger.debug(f"Found {len(temporal_relationships)} temporal relationships")
            
            # Behavioral relationships
            if self.enable_behavioral_detection:
                behavioral_relationships = self.behavioral_analyzer.detect_behavioral_relationships(indicators)
                all_relationships.extend(behavioral_relationships)
                logger.debug(f"Found {len(behavioral_relationships)} behavioral relationships")
            
            # Filter by confidence threshold
            filtered_relationships = [
                rel for rel in all_relationships
                if rel.confidence >= self.min_confidence_threshold
            ]
            
            # Deduplicate relationships
            deduplicated_relationships = self._deduplicate_relationships(filtered_relationships)
            
            logger.info(f"Detected {len(deduplicated_relationships)} relationships (filtered from {len(all_relationships)})")
            
            return deduplicated_relationships
            
        except Exception as e:
            logger.error(f"Relationship detection failed: {e}", exc_info=True)
            return []
    
    def _deduplicate_relationships(self, relationships: List[GraphRelationship]) -> List[GraphRelationship]:
        """Remove duplicate relationships."""
        
        seen_pairs = set()
        deduplicated = []
        
        for relationship in relationships:
            # Create normalized pair key
            node1, node2 = relationship.source_node_id, relationship.target_node_id
            pair_key = tuple(sorted([node1, node2]))
            
            relationship_key = (pair_key, relationship.relationship_type.value)
            
            if relationship_key not in seen_pairs:
                seen_pairs.add(relationship_key)
                deduplicated.append(relationship)
            else:
                # If duplicate, merge evidence
                for existing_rel in deduplicated:
                    if ((existing_rel.source_node_id == node1 and existing_rel.target_node_id == node2) or
                        (existing_rel.source_node_id == node2 and existing_rel.target_node_id == node1)) and \
                       existing_rel.relationship_type == relationship.relationship_type:
                        
                        # Merge evidence and update confidence
                        existing_rel.evidence.extend(relationship.evidence)
                        existing_rel.confidence = max(existing_rel.confidence, relationship.confidence)
                        existing_rel.weight = max(existing_rel.weight, relationship.weight)
                        existing_rel.sources.update(relationship.sources)
                        break
        
        return deduplicated