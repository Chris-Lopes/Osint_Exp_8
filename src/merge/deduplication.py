"""
Deduplication engine for threat intelligence indicators.

This module implements sophisticated deduplication algorithms that identify
duplicate indicators based on multiple matching criteria, semantic similarity,
and contextual analysis. It serves as the foundation for the merge system.
"""

import logging
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
import difflib
import ipaddress
import re
from urllib.parse import urlparse

try:
    from ..normalizers.schema import NormalizedIndicator, IndicatorType, ConfidenceLevel
except ImportError:
    from normalizers.schema import NormalizedIndicator, IndicatorType, ConfidenceLevel

logger = logging.getLogger(__name__)


class DuplicateMatchType(Enum):
    """Types of duplicate matches between indicators."""
    EXACT_VALUE = "exact_value"
    SEMANTIC_EQUIVALENT = "semantic_equivalent"
    CONTEXTUAL_SIMILAR = "contextual_similar"
    TEMPORAL_CLUSTER = "temporal_cluster"
    ENRICHMENT_LINKED = "enrichment_linked"


class DuplicateConfidence(Enum):
    """Confidence levels for duplicate matches."""
    CERTAIN = "certain"        # 95-100% confidence
    HIGH = "high"             # 80-94% confidence  
    MODERATE = "moderate"     # 60-79% confidence
    LOW = "low"              # 40-59% confidence
    WEAK = "weak"            # 20-39% confidence


@dataclass
class DuplicateMatch:
    """Represents a potential duplicate match between indicators."""
    
    indicator1_id: str
    indicator2_id: str
    match_type: DuplicateMatchType
    confidence_score: float  # 0.0 - 1.0
    confidence_level: DuplicateConfidence
    similarity_factors: Dict[str, float] = field(default_factory=dict)
    evidence: Dict[str, Any] = field(default_factory=dict)
    match_reason: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert match to dictionary representation."""
        return {
            'indicator1_id': self.indicator1_id,
            'indicator2_id': self.indicator2_id,
            'match_type': self.match_type.value,
            'confidence_score': self.confidence_score,
            'confidence_level': self.confidence_level.value,
            'similarity_factors': self.similarity_factors,
            'evidence': self.evidence,
            'match_reason': self.match_reason,
            'created_at': self.created_at.isoformat()
        }


class ExactValueMatcher:
    """Matches indicators with identical values."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize exact value matcher."""
        self.config = config or {}
        self.case_sensitive = self.config.get('case_sensitive', False)
        self.normalize_domains = self.config.get('normalize_domains', True)
        self.normalize_urls = self.config.get('normalize_urls', True)
        
    def find_matches(self, indicators: List[NormalizedIndicator]) -> List[DuplicateMatch]:
        """Find exact value matches between indicators."""
        matches = []
        
        # Group indicators by normalized value
        value_groups = defaultdict(list)
        
        for indicator in indicators:
            normalized_value = self._normalize_value(indicator)
            value_groups[normalized_value].append(indicator)
        
        # Create matches for groups with multiple indicators
        for normalized_value, group in value_groups.items():
            if len(group) > 1:
                # Create matches for all pairs in the group
                for i in range(len(group)):
                    for j in range(i + 1, len(group)):
                        match = self._create_exact_match(group[i], group[j], normalized_value)
                        matches.append(match)
        
        logger.info(f"Found {len(matches)} exact value matches")
        return matches
    
    def _normalize_value(self, indicator: NormalizedIndicator) -> str:
        """Normalize indicator value for comparison."""
        value = indicator.value
        
        # Case normalization
        if not self.case_sensitive:
            value = value.lower()
        
        # Domain normalization
        if (self.normalize_domains and 
            indicator.indicator_type == IndicatorType.DOMAIN):
            value = value.strip().lower()
            # Remove trailing dots
            if value.endswith('.'):
                value = value[:-1]
        
        # URL normalization
        if (self.normalize_urls and 
            indicator.indicator_type == IndicatorType.URL):
            try:
                parsed = urlparse(value.lower())
                # Normalize scheme and remove default ports
                if parsed.scheme == 'https' and parsed.port == 443:
                    netloc = parsed.hostname
                elif parsed.scheme == 'http' and parsed.port == 80:
                    netloc = parsed.hostname
                else:
                    netloc = parsed.netloc
                
                # Reconstruct normalized URL
                value = f"{parsed.scheme}://{netloc}{parsed.path}"
                if parsed.query:
                    value += f"?{parsed.query}"
                    
            except Exception as e:
                logger.warning(f"Failed to normalize URL {value}: {e}")
        
        return value
    
    def _create_exact_match(self, indicator1: NormalizedIndicator, 
                          indicator2: NormalizedIndicator, 
                          normalized_value: str) -> DuplicateMatch:
        """Create exact match result."""
        return DuplicateMatch(
            indicator1_id=indicator1.id,
            indicator2_id=indicator2.id,
            match_type=DuplicateMatchType.EXACT_VALUE,
            confidence_score=1.0,
            confidence_level=DuplicateConfidence.CERTAIN,
            similarity_factors={'value_match': 1.0},
            evidence={
                'normalized_value': normalized_value,
                'original_value1': indicator1.value,
                'original_value2': indicator2.value
            },
            match_reason=f"Identical values: {normalized_value}"
        )


class SemanticEquivalenceMatcher:
    """Matches indicators that are semantically equivalent but not identical."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize semantic equivalence matcher."""
        self.config = config or {}
        self.min_confidence = self.config.get('min_confidence', 0.8)
        
    def find_matches(self, indicators: List[NormalizedIndicator]) -> List[DuplicateMatch]:
        """Find semantically equivalent indicators."""
        matches = []
        
        # Group by indicator type for focused comparison
        type_groups = defaultdict(list)
        for indicator in indicators:
            type_groups[indicator.indicator_type].append(indicator)
        
        # Process each type group
        for indicator_type, group in type_groups.items():
            if len(group) > 1:
                type_matches = self._find_type_specific_matches(indicator_type, group)
                matches.extend(type_matches)
        
        logger.info(f"Found {len(matches)} semantic equivalence matches")
        return matches
    
    def _find_type_specific_matches(self, indicator_type: IndicatorType, 
                                  indicators: List[NormalizedIndicator]) -> List[DuplicateMatch]:
        """Find matches specific to indicator type."""
        matches = []
        
        if indicator_type in {IndicatorType.IP, IndicatorType.IPV4, IndicatorType.IPV6}:
            matches.extend(self._find_ip_equivalences(indicators))
        elif indicator_type == IndicatorType.DOMAIN:
            matches.extend(self._find_domain_equivalences(indicators))
        elif indicator_type == IndicatorType.URL:
            matches.extend(self._find_url_equivalences(indicators))
        elif indicator_type in {IndicatorType.MD5, IndicatorType.SHA1, IndicatorType.SHA256}:
            matches.extend(self._find_hash_equivalences(indicators))
        
        return matches
    
    def _find_ip_equivalences(self, indicators: List[NormalizedIndicator]) -> List[DuplicateMatch]:
        """Find IP address equivalences (e.g., different representations)."""
        matches = []
        
        # Convert to IP objects for comparison
        ip_indicators = []
        for indicator in indicators:
            try:
                ip_obj = ipaddress.ip_address(indicator.value)
                ip_indicators.append((indicator, ip_obj))
            except ValueError:
                logger.warning(f"Invalid IP address: {indicator.value}")
                continue
        
        # Compare all pairs
        for i in range(len(ip_indicators)):
            for j in range(i + 1, len(ip_indicators)):
                indicator1, ip1 = ip_indicators[i]
                indicator2, ip2 = ip_indicators[j]
                
                # Check for different representations of same IP
                if ip1 == ip2 and indicator1.value != indicator2.value:
                    match = DuplicateMatch(
                        indicator1_id=indicator1.id,
                        indicator2_id=indicator2.id,
                        match_type=DuplicateMatchType.SEMANTIC_EQUIVALENT,
                        confidence_score=0.95,
                        confidence_level=DuplicateConfidence.CERTAIN,
                        similarity_factors={'ip_equivalence': 1.0},
                        evidence={
                            'ip_canonical': str(ip1),
                            'representation1': indicator1.value,
                            'representation2': indicator2.value
                        },
                        match_reason=f"Different representations of IP {ip1}"
                    )
                    matches.append(match)
        
        return matches
    
    def _find_domain_equivalences(self, indicators: List[NormalizedIndicator]) -> List[DuplicateMatch]:
        """Find domain equivalences (e.g., with/without www, internationalized domains)."""
        matches = []
        
        # Group by normalized domain
        domain_groups = defaultdict(list)
        
        for indicator in indicators:
            normalized = self._normalize_domain_advanced(indicator.value)
            domain_groups[normalized].append(indicator)
        
        # Create matches within groups
        for normalized_domain, group in domain_groups.items():
            if len(group) > 1:
                for i in range(len(group)):
                    for j in range(i + 1, len(group)):
                        if group[i].value != group[j].value:  # Not exact duplicates
                            match = DuplicateMatch(
                                indicator1_id=group[i].id,
                                indicator2_id=group[j].id,
                                match_type=DuplicateMatchType.SEMANTIC_EQUIVALENT,
                                confidence_score=0.9,
                                confidence_level=DuplicateConfidence.HIGH,
                                similarity_factors={'domain_equivalence': 0.9},
                                evidence={
                                    'normalized_domain': normalized_domain,
                                    'domain1': group[i].value,
                                    'domain2': group[j].value
                                },
                                match_reason=f"Domain equivalents: {normalized_domain}"
                            )
                            matches.append(match)
        
        return matches
    
    def _normalize_domain_advanced(self, domain: str) -> str:
        """Advanced domain normalization."""
        domain = domain.lower().strip()
        
        # Remove trailing dot
        if domain.endswith('.'):
            domain = domain[:-1]
        
        # Remove www prefix
        if domain.startswith('www.'):
            domain = domain[4:]
        
        # Handle internationalized domains (basic)
        try:
            domain = domain.encode('idna').decode('ascii')
        except UnicodeError:
            pass  # Keep original if conversion fails
        
        return domain
    
    def _find_url_equivalences(self, indicators: List[NormalizedIndicator]) -> List[DuplicateMatch]:
        """Find URL equivalences (normalized forms, parameter order, etc.)."""
        matches = []
        
        # Normalize and compare URLs
        url_groups = defaultdict(list)
        
        for indicator in indicators:
            normalized = self._normalize_url_advanced(indicator.value)
            if normalized:
                url_groups[normalized].append(indicator)
        
        # Create matches within groups
        for normalized_url, group in url_groups.items():
            if len(group) > 1:
                for i in range(len(group)):
                    for j in range(i + 1, len(group)):
                        if group[i].value != group[j].value:
                            match = DuplicateMatch(
                                indicator1_id=group[i].id,
                                indicator2_id=group[j].id,
                                match_type=DuplicateMatchType.SEMANTIC_EQUIVALENT,
                                confidence_score=0.85,
                                confidence_level=DuplicateConfidence.HIGH,
                                similarity_factors={'url_equivalence': 0.85},
                                evidence={
                                    'normalized_url': normalized_url,
                                    'url1': group[i].value,
                                    'url2': group[j].value
                                },
                                match_reason=f"URL equivalents: {normalized_url}"
                            )
                            matches.append(match)
        
        return matches
    
    def _normalize_url_advanced(self, url: str) -> Optional[str]:
        """Advanced URL normalization."""
        try:
            parsed = urlparse(url.lower())
            
            # Normalize domain
            domain = self._normalize_domain_advanced(parsed.hostname or '')
            
            # Normalize path (remove trailing slash if not root)
            path = parsed.path
            if len(path) > 1 and path.endswith('/'):
                path = path[:-1]
            
            # Sort query parameters for consistent comparison
            if parsed.query:
                query_params = sorted(parsed.query.split('&'))
                query = '&'.join(query_params)
            else:
                query = ''
            
            # Reconstruct normalized URL
            scheme = parsed.scheme or 'http'
            
            normalized = f"{scheme}://{domain}{path}"
            if query:
                normalized += f"?{query}"
            if parsed.fragment:
                normalized += f"#{parsed.fragment}"
            
            return normalized
            
        except Exception as e:
            logger.warning(f"Failed to normalize URL {url}: {e}")
            return None
    
    def _find_hash_equivalences(self, indicators: List[NormalizedIndicator]) -> List[DuplicateMatch]:
        """Find hash equivalences (case differences)."""
        matches = []
        
        # Group by normalized hash
        hash_groups = defaultdict(list)
        
        for indicator in indicators:
            normalized_hash = indicator.value.lower()
            hash_groups[normalized_hash].append(indicator)
        
        # Create matches within groups where original values differ
        for normalized_hash, group in hash_groups.items():
            if len(group) > 1:
                for i in range(len(group)):
                    for j in range(i + 1, len(group)):
                        if group[i].value != group[j].value:
                            match = DuplicateMatch(
                                indicator1_id=group[i].id,
                                indicator2_id=group[j].id,
                                match_type=DuplicateMatchType.SEMANTIC_EQUIVALENT,
                                confidence_score=0.95,
                                confidence_level=DuplicateConfidence.CERTAIN,
                                similarity_factors={'hash_case_equivalence': 1.0},
                                evidence={
                                    'normalized_hash': normalized_hash,
                                    'hash1': group[i].value,
                                    'hash2': group[j].value
                                },
                                match_reason=f"Case-different hash: {normalized_hash}"
                            )
                            matches.append(match)
        
        return matches


class ContextualSimilarityMatcher:
    """Matches indicators based on contextual similarity."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize contextual similarity matcher."""
        self.config = config or {}
        self.min_confidence = self.config.get('min_confidence', 0.6)
        self.tag_weight = self.config.get('tag_weight', 0.3)
        self.source_weight = self.config.get('source_weight', 0.2)
        self.enrichment_weight = self.config.get('enrichment_weight', 0.3)
        self.temporal_weight = self.config.get('temporal_weight', 0.2)
        
    def find_matches(self, indicators: List[NormalizedIndicator]) -> List[DuplicateMatch]:
        """Find contextually similar indicators."""
        matches = []
        
        # Compare all pairs for contextual similarity
        for i in range(len(indicators)):
            for j in range(i + 1, len(indicators)):
                match = self._analyze_contextual_similarity(indicators[i], indicators[j])
                if match and match.confidence_score >= self.min_confidence:
                    matches.append(match)
        
        logger.info(f"Found {len(matches)} contextual similarity matches")
        return matches
    
    def _analyze_contextual_similarity(self, indicator1: NormalizedIndicator, 
                                     indicator2: NormalizedIndicator) -> Optional[DuplicateMatch]:
        """Analyze contextual similarity between two indicators."""
        similarity_factors = {}
        
        # Tag similarity
        tag_sim = self._calculate_tag_similarity(indicator1.tags, indicator2.tags)
        similarity_factors['tag_similarity'] = tag_sim
        
        # Source similarity
        source_sim = self._calculate_source_similarity(indicator1, indicator2)
        similarity_factors['source_similarity'] = source_sim
        
        # Enrichment similarity
        enrich_sim = self._calculate_enrichment_similarity(indicator1, indicator2)
        similarity_factors['enrichment_similarity'] = enrich_sim
        
        # Temporal similarity
        temporal_sim = self._calculate_temporal_similarity(indicator1, indicator2)
        similarity_factors['temporal_similarity'] = temporal_sim
        
        # Calculate overall confidence
        confidence_score = (
            tag_sim * self.tag_weight +
            source_sim * self.source_weight +
            enrich_sim * self.enrichment_weight +
            temporal_sim * self.temporal_weight
        )
        
        if confidence_score >= self.min_confidence:
            confidence_level = self._score_to_confidence_level(confidence_score)
            
            return DuplicateMatch(
                indicator1_id=indicator1.id,
                indicator2_id=indicator2.id,
                match_type=DuplicateMatchType.CONTEXTUAL_SIMILAR,
                confidence_score=confidence_score,
                confidence_level=confidence_level,
                similarity_factors=similarity_factors,
                evidence={
                    'tags1': indicator1.tags,
                    'tags2': indicator2.tags,
                    'source1': getattr(indicator1.source_metadata, 'source_name', 'unknown'),
                    'source2': getattr(indicator2.source_metadata, 'source_name', 'unknown')
                },
                match_reason=f"Contextual similarity: {confidence_score:.2f}"
            )
        
        return None
    
    def _calculate_tag_similarity(self, tags1: List[str], tags2: List[str]) -> float:
        """Calculate tag similarity using Jaccard coefficient."""
        if not tags1 and not tags2:
            return 1.0
        if not tags1 or not tags2:
            return 0.0
        
        set1 = set(tag.lower() for tag in tags1)
        set2 = set(tag.lower() for tag in tags2)
        
        intersection = len(set1 & set2)
        union = len(set1 | set2)
        
        return intersection / union if union > 0 else 0.0
    
    def _calculate_source_similarity(self, indicator1: NormalizedIndicator, 
                                   indicator2: NormalizedIndicator) -> float:
        """Calculate source similarity."""
        try:
            source1 = indicator1.source_metadata.source_name
            source2 = indicator2.source_metadata.source_name
            
            if source1 == source2:
                return 1.0
            
            # Check for source hierarchy or relationships
            # For now, simple string similarity
            return difflib.SequenceMatcher(None, source1.lower(), source2.lower()).ratio()
            
        except Exception:
            return 0.0
    
    def _calculate_enrichment_similarity(self, indicator1: NormalizedIndicator, 
                                       indicator2: NormalizedIndicator) -> float:
        """Calculate enrichment context similarity."""
        try:
            enrich1 = indicator1.context.get('enrichment', {})
            enrich2 = indicator2.context.get('enrichment', {})
            
            if not enrich1 and not enrich2:
                return 1.0
            if not enrich1 or not enrich2:
                return 0.0
            
            similarities = []
            
            # Reputation similarity
            rep1 = enrich1.get('reputation', {})
            rep2 = enrich2.get('reputation', {})
            
            if rep1 and rep2:
                rep_sim = self._calculate_reputation_similarity(rep1, rep2)
                similarities.append(rep_sim)
            
            # Geolocation similarity
            geo1 = enrich1.get('geolocation', {})
            geo2 = enrich2.get('geolocation', {})
            
            if geo1 and geo2:
                geo_sim = self._calculate_geo_similarity(geo1, geo2)
                similarities.append(geo_sim)
            
            return sum(similarities) / len(similarities) if similarities else 0.0
            
        except Exception:
            return 0.0
    
    def _calculate_reputation_similarity(self, rep1: Dict, rep2: Dict) -> float:
        """Calculate reputation similarity."""
        # Compare reputation scores and categories
        score1 = rep1.get('reputation_score', 0)
        score2 = rep2.get('reputation_score', 0)
        
        # Normalize scores to 0-1 range
        norm_score1 = (score1 + 100) / 200  # Assuming -100 to 100 range
        norm_score2 = (score2 + 100) / 200
        
        score_similarity = 1.0 - abs(norm_score1 - norm_score2)
        
        # Check category similarity
        cat1 = rep1.get('category', '')
        cat2 = rep2.get('category', '')
        
        cat_similarity = 1.0 if cat1 == cat2 else 0.5 if cat1 and cat2 else 0.0
        
        return (score_similarity + cat_similarity) / 2
    
    def _calculate_geo_similarity(self, geo1: Dict, geo2: Dict) -> float:
        """Calculate geolocation similarity."""
        # Compare countries
        country1 = geo1.get('country', '')
        country2 = geo2.get('country', '')
        
        if country1 and country2:
            return 1.0 if country1 == country2 else 0.3
        
        return 0.0
    
    def _calculate_temporal_similarity(self, indicator1: NormalizedIndicator, 
                                     indicator2: NormalizedIndicator) -> float:
        """Calculate temporal similarity."""
        try:
            # Compare creation times
            time1 = indicator1.created
            time2 = indicator2.created
            
            if isinstance(time1, str):
                time1 = datetime.fromisoformat(time1.replace('Z', '+00:00'))
            if isinstance(time2, str):
                time2 = datetime.fromisoformat(time2.replace('Z', '+00:00'))
            
            time_diff = abs((time1 - time2).total_seconds())
            
            # Similarity decreases with time difference
            # Full similarity if within 1 hour, decreasing to 0 over 30 days
            max_diff = 30 * 24 * 3600  # 30 days in seconds
            similarity = max(0, 1.0 - (time_diff / max_diff))
            
            return similarity
            
        except Exception:
            return 0.0
    
    def _score_to_confidence_level(self, score: float) -> DuplicateConfidence:
        """Convert confidence score to confidence level."""
        if score >= 0.95:
            return DuplicateConfidence.CERTAIN
        elif score >= 0.8:
            return DuplicateConfidence.HIGH
        elif score >= 0.6:
            return DuplicateConfidence.MODERATE
        elif score >= 0.4:
            return DuplicateConfidence.LOW
        else:
            return DuplicateConfidence.WEAK


class DeduplicationEngine:
    """Main deduplication engine that orchestrates all matching algorithms."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize deduplication engine."""
        self.config = config or {}
        
        # Initialize matchers
        self.exact_matcher = ExactValueMatcher(self.config.get('exact_matcher', {}))
        self.semantic_matcher = SemanticEquivalenceMatcher(self.config.get('semantic_matcher', {}))
        self.contextual_matcher = ContextualSimilarityMatcher(self.config.get('contextual_matcher', {}))
        
        # Deduplication settings
        self.enable_exact_matching = self.config.get('enable_exact_matching', True)
        self.enable_semantic_matching = self.config.get('enable_semantic_matching', True)
        self.enable_contextual_matching = self.config.get('enable_contextual_matching', False)
        
        logger.info("Deduplication engine initialized")
    
    def find_duplicates(self, indicators: List[NormalizedIndicator]) -> List[DuplicateMatch]:
        """Find all duplicate matches in the provided indicators."""
        logger.info(f"Starting deduplication analysis for {len(indicators)} indicators")
        
        all_matches = []
        
        # Run exact matching
        if self.enable_exact_matching:
            logger.info("Running exact value matching...")
            exact_matches = self.exact_matcher.find_matches(indicators)
            all_matches.extend(exact_matches)
        
        # Run semantic matching
        if self.enable_semantic_matching:
            logger.info("Running semantic equivalence matching...")
            semantic_matches = self.semantic_matcher.find_matches(indicators)
            all_matches.extend(semantic_matches)
        
        # Run contextual matching (can be expensive for large datasets)
        if self.enable_contextual_matching and len(indicators) <= 1000:
            logger.info("Running contextual similarity matching...")
            contextual_matches = self.contextual_matcher.find_matches(indicators)
            all_matches.extend(contextual_matches)
        elif self.enable_contextual_matching:
            logger.warning(f"Skipping contextual matching for large dataset ({len(indicators)} indicators)")
        
        # Deduplicate matches themselves
        unique_matches = self._deduplicate_matches(all_matches)
        
        logger.info(f"Deduplication complete: found {len(unique_matches)} unique duplicate matches")
        
        return unique_matches
    
    def _deduplicate_matches(self, matches: List[DuplicateMatch]) -> List[DuplicateMatch]:
        """Remove duplicate matches and keep the highest confidence ones."""
        # Group by indicator pair
        match_groups = defaultdict(list)
        
        for match in matches:
            # Create consistent key regardless of indicator order
            key = tuple(sorted([match.indicator1_id, match.indicator2_id]))
            match_groups[key].append(match)
        
        # Keep best match for each pair
        unique_matches = []
        for pair_matches in match_groups.values():
            if len(pair_matches) == 1:
                unique_matches.append(pair_matches[0])
            else:
                # Keep match with highest confidence
                best_match = max(pair_matches, key=lambda m: m.confidence_score)
                unique_matches.append(best_match)
        
        return unique_matches
    
    def create_duplicate_groups(self, matches: List[DuplicateMatch]) -> List[Set[str]]:
        """Create groups of duplicate indicators from matches."""
        # Build graph of connections
        connections = defaultdict(set)
        
        for match in matches:
            connections[match.indicator1_id].add(match.indicator2_id)
            connections[match.indicator2_id].add(match.indicator1_id)
        
        # Find connected components
        visited = set()
        groups = []
        
        for indicator_id in connections:
            if indicator_id not in visited:
                group = self._find_connected_component(indicator_id, connections, visited)
                if len(group) > 1:
                    groups.append(group)
        
        logger.info(f"Created {len(groups)} duplicate groups")
        return groups
    
    def _find_connected_component(self, start_id: str, connections: Dict[str, Set[str]], 
                                visited: Set[str]) -> Set[str]:
        """Find all indicators connected to the start indicator."""
        component = set()
        stack = [start_id]
        
        while stack:
            current_id = stack.pop()
            if current_id in visited:
                continue
                
            visited.add(current_id)
            component.add(current_id)
            
            # Add connected indicators to stack
            for connected_id in connections[current_id]:
                if connected_id not in visited:
                    stack.append(connected_id)
        
        return component