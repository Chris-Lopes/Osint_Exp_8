"""
Correlation algorithms for threat intelligence indicator analysis.

This module implements various correlation algorithms to identify relationships
between indicators based on temporal proximity, network relationships,
shared attributes, and enrichment data.
"""

import logging
import math
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass
from enum import Enum
import ipaddress
import re

try:
    from ..normalizers.schema import NormalizedIndicator, IndicatorType
except ImportError:
    from normalizers.schema import NormalizedIndicator, IndicatorType

logger = logging.getLogger(__name__)


class CorrelationType(Enum):
    """Types of correlations between indicators."""
    TEMPORAL = "temporal"
    NETWORK = "network"
    ATTRIBUTE = "attribute"
    ENRICHMENT = "enrichment"
    BEHAVIORAL = "behavioral"
    CAMPAIGN = "campaign"


class CorrelationStrength(Enum):
    """Strength levels for correlations."""
    WEAK = "weak"
    MODERATE = "moderate"
    STRONG = "strong"
    VERY_STRONG = "very_strong"


@dataclass
class CorrelationResult:
    """Result of a correlation analysis."""
    indicator1_id: str
    indicator2_id: str
    correlation_type: CorrelationType
    strength: CorrelationStrength
    score: float  # 0.0 to 1.0
    confidence: float  # 0.0 to 1.0
    evidence: Dict[str, Any]
    timestamp: datetime
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            'indicator1_id': self.indicator1_id,
            'indicator2_id': self.indicator2_id,
            'correlation_type': self.correlation_type.value,
            'strength': self.strength.value,
            'score': self.score,
            'confidence': self.confidence,
            'evidence': self.evidence,
            'timestamp': self.timestamp.isoformat()
        }


class TemporalCorrelationAnalyzer:
    """Analyzes temporal correlations between indicators."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize temporal correlation analyzer."""
        self.config = config or {}
        
        # Time windows for correlation
        self.short_window = timedelta(hours=self.config.get('short_window_hours', 1))
        self.medium_window = timedelta(hours=self.config.get('medium_window_hours', 24))
        self.long_window = timedelta(days=self.config.get('long_window_days', 7))
        
        # Scoring thresholds
        self.very_strong_threshold = self.config.get('very_strong_threshold', 0.9)
        self.strong_threshold = self.config.get('strong_threshold', 0.7)
        self.moderate_threshold = self.config.get('moderate_threshold', 0.4)
    
    def analyze_temporal_correlation(self, indicator1: NormalizedIndicator, 
                                   indicator2: NormalizedIndicator) -> Optional[CorrelationResult]:
        """Analyze temporal correlation between two indicators."""
        try:
            # Parse timestamps - handle both string and datetime objects
            time1 = self._parse_timestamp(indicator1.created)
            time2 = self._parse_timestamp(indicator2.created)
            
            # Calculate time difference
            time_diff = abs(time1 - time2)
            
            # Determine correlation strength based on time proximity
            if time_diff <= self.short_window:
                score = 0.95
                strength = CorrelationStrength.VERY_STRONG
                evidence = {
                    'time_difference_minutes': time_diff.total_seconds() / 60,
                    'window': 'short',
                    'simultaneous_activity': True
                }
            elif time_diff <= self.medium_window:
                # Linear decay within medium window
                score = 0.7 * (1 - (time_diff.total_seconds() / self.medium_window.total_seconds()))
                strength = CorrelationStrength.STRONG if score > self.strong_threshold else CorrelationStrength.MODERATE
                evidence = {
                    'time_difference_hours': time_diff.total_seconds() / 3600,
                    'window': 'medium',
                    'related_activity': True
                }
            elif time_diff <= self.long_window:
                # Weaker correlation within long window
                score = 0.4 * (1 - (time_diff.total_seconds() / self.long_window.total_seconds()))
                strength = CorrelationStrength.MODERATE if score > self.moderate_threshold else CorrelationStrength.WEAK
                evidence = {
                    'time_difference_days': time_diff.days,
                    'window': 'long',
                    'campaign_timeframe': True
                }
            else:
                return None  # No temporal correlation
            
            # Boost score for same source
            if indicator1.source_metadata.source_name == indicator2.source_metadata.source_name:
                score *= 1.2
                evidence['same_source'] = True
            
            # Ensure score doesn't exceed 1.0
            score = min(score, 1.0)
            
            # Calculate confidence based on data quality
            confidence = self._calculate_temporal_confidence(indicator1, indicator2, time_diff)
            
            return CorrelationResult(
                indicator1_id=indicator1.id,
                indicator2_id=indicator2.id,
                correlation_type=CorrelationType.TEMPORAL,
                strength=strength,
                score=score,
                confidence=confidence,
                evidence=evidence,
                timestamp=datetime.utcnow()
            )
            
        except Exception as e:
            logger.error(f"Temporal correlation error: {e}")
            return None
    
    def _parse_timestamp(self, timestamp) -> datetime:
        """Parse timestamp from various formats."""
        if isinstance(timestamp, datetime):
            return timestamp
        elif isinstance(timestamp, str):
            # Handle different string formats
            try:
                # Try ISO format first
                return datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            except ValueError:
                # Try other common formats
                try:
                    return datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S.%f')
                except ValueError:
                    return datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
        else:
            # Fallback to current time
            logger.warning(f"Unknown timestamp format: {type(timestamp)}, using current time")
            return datetime.utcnow()
    
    def _calculate_temporal_confidence(self, indicator1: NormalizedIndicator, 
                                     indicator2: NormalizedIndicator, 
                                     time_diff: timedelta) -> float:
        """Calculate confidence in temporal correlation."""
        confidence = 0.8  # Base confidence
        
        # Higher confidence for precise timestamps
        time1 = self._parse_timestamp(indicator1.created)
        time2 = self._parse_timestamp(indicator2.created)
        
        # Check if timestamps have microsecond precision
        if time1.microsecond > 0 or time2.microsecond > 0:
            confidence += 0.1
        
        # Higher confidence for closer time proximity
        if time_diff <= self.short_window:
            confidence += 0.1
        
        # Lower confidence for very old indicators
        now = datetime.utcnow()
        
        age1 = now - time1
        age2 = now - time2
        
        if age1.days > 30 or age2.days > 30:
            confidence -= 0.1
        
        return min(max(confidence, 0.0), 1.0)


class NetworkCorrelationAnalyzer:
    """Analyzes network-based correlations between indicators."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize network correlation analyzer."""
        self.config = config or {}
    
    def analyze_network_correlation(self, indicator1: NormalizedIndicator, 
                                  indicator2: NormalizedIndicator) -> Optional[CorrelationResult]:
        """Analyze network correlation between two indicators."""
        try:
            # IP-based correlations
            if self._are_ip_indicators(indicator1, indicator2):
                return self._analyze_ip_correlation(indicator1, indicator2)
            
            # Domain-based correlations
            if self._are_domain_indicators(indicator1, indicator2):
                return self._analyze_domain_correlation(indicator1, indicator2)
            
            # Mixed IP/Domain correlations
            if self._is_mixed_network_pair(indicator1, indicator2):
                return self._analyze_mixed_network_correlation(indicator1, indicator2)
            
            return None
            
        except Exception as e:
            logger.error(f"Network correlation error: {e}")
            return None
    
    def _are_ip_indicators(self, indicator1: NormalizedIndicator, 
                          indicator2: NormalizedIndicator) -> bool:
        """Check if both indicators are IP addresses."""
        ip_types = {IndicatorType.IP, IndicatorType.IPV4, IndicatorType.IPV6}
        return (indicator1.indicator_type in ip_types and 
                indicator2.indicator_type in ip_types)
    
    def _are_domain_indicators(self, indicator1: NormalizedIndicator, 
                             indicator2: NormalizedIndicator) -> bool:
        """Check if both indicators are domains."""
        domain_types = {IndicatorType.DOMAIN}
        return (indicator1.indicator_type in domain_types and 
                indicator2.indicator_type in domain_types)
    
    def _is_mixed_network_pair(self, indicator1: NormalizedIndicator, 
                              indicator2: NormalizedIndicator) -> bool:
        """Check if indicators are mixed network types (IP + domain)."""
        ip_types = {IndicatorType.IP, IndicatorType.IPV4, IndicatorType.IPV6}
        domain_types = {IndicatorType.DOMAIN}
        
        return ((indicator1.indicator_type in ip_types and indicator2.indicator_type in domain_types) or
                (indicator1.indicator_type in domain_types and indicator2.indicator_type in ip_types))
    
    def _analyze_ip_correlation(self, indicator1: NormalizedIndicator, 
                               indicator2: NormalizedIndicator) -> Optional[CorrelationResult]:
        """Analyze correlation between IP addresses."""
        try:
            ip1 = ipaddress.ip_address(indicator1.value)
            ip2 = ipaddress.ip_address(indicator2.value)
            
            # Same IP
            if ip1 == ip2:
                return CorrelationResult(
                    indicator1_id=indicator1.id,
                    indicator2_id=indicator2.id,
                    correlation_type=CorrelationType.NETWORK,
                    strength=CorrelationStrength.VERY_STRONG,
                    score=1.0,
                    confidence=0.95,
                    evidence={'relationship': 'identical_ip', 'ip_address': str(ip1)},
                    timestamp=datetime.utcnow()
                )
            
            # Same subnet analysis
            subnet_correlation = self._analyze_subnet_correlation(ip1, ip2)
            if subnet_correlation:
                return CorrelationResult(
                    indicator1_id=indicator1.id,
                    indicator2_id=indicator2.id,
                    correlation_type=CorrelationType.NETWORK,
                    strength=subnet_correlation['strength'],
                    score=subnet_correlation['score'],
                    confidence=subnet_correlation['confidence'],
                    evidence=subnet_correlation['evidence'],
                    timestamp=datetime.utcnow()
                )
            
            # ASN correlation from enrichment data
            asn_correlation = self._analyze_asn_correlation(indicator1, indicator2)
            if asn_correlation:
                return asn_correlation
            
            return None
            
        except ValueError:
            logger.warning(f"Invalid IP addresses for correlation: {indicator1.value}, {indicator2.value}")
            return None
    
    def _analyze_subnet_correlation(self, ip1: ipaddress.ip_address, 
                                   ip2: ipaddress.ip_address) -> Optional[Dict[str, Any]]:
        """Analyze subnet-based correlation between IPs."""
        if ip1.version != ip2.version:
            return None
        
        # Check various subnet sizes
        subnet_checks = [
            ('/24', 24, 0.8, CorrelationStrength.STRONG),
            ('/20', 20, 0.6, CorrelationStrength.MODERATE), 
            ('/16', 16, 0.4, CorrelationStrength.WEAK)
        ]
        
        for subnet_name, prefix_len, score, strength in subnet_checks:
            try:
                # Create network with the specified prefix length
                if ip1.version == 4:
                    network1 = ipaddress.IPv4Network(f"{ip1}/{prefix_len}", strict=False)
                    network2 = ipaddress.IPv4Network(f"{ip2}/{prefix_len}", strict=False)
                else:
                    network1 = ipaddress.IPv6Network(f"{ip1}/{prefix_len}", strict=False)
                    network2 = ipaddress.IPv6Network(f"{ip2}/{prefix_len}", strict=False)
                
                if network1 == network2:
                    return {
                        'score': score,
                        'strength': strength,
                        'confidence': 0.7,
                        'evidence': {
                            'relationship': 'same_subnet',
                            'subnet': str(network1),
                            'prefix_length': prefix_len
                        }
                    }
            except Exception:
                continue
        
        return None
    
    def _analyze_asn_correlation(self, indicator1: NormalizedIndicator, 
                                indicator2: NormalizedIndicator) -> Optional[CorrelationResult]:
        """Analyze ASN-based correlation using enrichment data."""
        try:
            # Get ASN information from enrichment context
            enrich1 = indicator1.context.get('enrichment', {})
            enrich2 = indicator2.context.get('enrichment', {})
            
            asn1_data = enrich1.get('asn', {})
            asn2_data = enrich2.get('asn', {})
            
            asn1 = asn1_data.get('asn_number')
            asn2 = asn2_data.get('asn_number')
            
            if asn1 and asn2 and asn1 == asn2:
                return CorrelationResult(
                    indicator1_id=indicator1.id,
                    indicator2_id=indicator2.id,
                    correlation_type=CorrelationType.NETWORK,
                    strength=CorrelationStrength.MODERATE,
                    score=0.6,
                    confidence=0.8,
                    evidence={
                        'relationship': 'same_asn',
                        'asn_number': asn1,
                        'network_owner': asn1_data.get('network_owner', 'Unknown')
                    },
                    timestamp=datetime.utcnow()
                )
            
            return None
            
        except Exception as e:
            logger.error(f"ASN correlation error: {e}")
            return None
    
    def _analyze_domain_correlation(self, indicator1: NormalizedIndicator, 
                                   indicator2: NormalizedIndicator) -> Optional[CorrelationResult]:
        """Analyze correlation between domains."""
        domain1 = indicator1.value.lower()
        domain2 = indicator2.value.lower()
        
        # Exact match
        if domain1 == domain2:
            return CorrelationResult(
                indicator1_id=indicator1.id,
                indicator2_id=indicator2.id,
                correlation_type=CorrelationType.NETWORK,
                strength=CorrelationStrength.VERY_STRONG,
                score=1.0,
                confidence=0.95,
                evidence={'relationship': 'identical_domain'},
                timestamp=datetime.utcnow()
            )
        
        # Subdomain analysis
        subdomain_correlation = self._analyze_subdomain_correlation(domain1, domain2)
        if subdomain_correlation:
            return CorrelationResult(
                indicator1_id=indicator1.id,
                indicator2_id=indicator2.id,
                correlation_type=CorrelationType.NETWORK,
                strength=subdomain_correlation['strength'],
                score=subdomain_correlation['score'],
                confidence=subdomain_correlation['confidence'],
                evidence=subdomain_correlation['evidence'],
                timestamp=datetime.utcnow()
            )
        
        return None
    
    def _analyze_subdomain_correlation(self, domain1: str, domain2: str) -> Optional[Dict[str, Any]]:
        """Analyze subdomain relationships."""
        # Extract root domains
        parts1 = domain1.split('.')
        parts2 = domain2.split('.')
        
        if len(parts1) < 2 or len(parts2) < 2:
            return None
        
        # Same root domain (e.g., sub1.example.com vs sub2.example.com)
        root1 = '.'.join(parts1[-2:])
        root2 = '.'.join(parts2[-2:])
        
        if root1 == root2:
            return {
                'score': 0.7,
                'strength': CorrelationStrength.STRONG,
                'confidence': 0.85,
                'evidence': {
                    'relationship': 'same_root_domain',
                    'root_domain': root1,
                    'domain1_subdomains': '.'.join(parts1[:-2]) if len(parts1) > 2 else '',
                    'domain2_subdomains': '.'.join(parts2[:-2]) if len(parts2) > 2 else ''
                }
            }
        
        # Parent-child relationship
        if domain1.endswith('.' + domain2) or domain2.endswith('.' + domain1):
            return {
                'score': 0.8,
                'strength': CorrelationStrength.STRONG,
                'confidence': 0.9,
                'evidence': {
                    'relationship': 'parent_child_domain',
                    'parent': domain2 if domain1.endswith('.' + domain2) else domain1,
                    'child': domain1 if domain1.endswith('.' + domain2) else domain2
                }
            }
        
        return None
    
    def _analyze_mixed_network_correlation(self, indicator1: NormalizedIndicator, 
                                         indicator2: NormalizedIndicator) -> Optional[CorrelationResult]:
        """Analyze correlation between IP and domain indicators."""
        # Use enrichment data to find DNS resolution connections
        try:
            # Determine which is IP and which is domain
            ip_indicator = indicator1 if indicator1.indicator_type in {IndicatorType.IP, IndicatorType.IPV4, IndicatorType.IPV6} else indicator2
            domain_indicator = indicator2 if ip_indicator == indicator1 else indicator1
            
            # Check DNS enrichment data
            domain_enrichment = domain_indicator.context.get('enrichment', {}).get('dns', {})
            dns_records = domain_enrichment.get('dns_records', {})
            
            # Check A and AAAA records
            a_records = dns_records.get('A', {}).get('records', [])
            aaaa_records = dns_records.get('AAAA', {}).get('records', [])
            
            all_ips = a_records + aaaa_records
            
            if ip_indicator.value in all_ips:
                return CorrelationResult(
                    indicator1_id=indicator1.id,
                    indicator2_id=indicator2.id,
                    correlation_type=CorrelationType.NETWORK,
                    strength=CorrelationStrength.VERY_STRONG,
                    score=0.9,
                    confidence=0.9,
                    evidence={
                        'relationship': 'dns_resolution',
                        'domain': domain_indicator.value,
                        'resolved_ip': ip_indicator.value,
                        'record_type': 'A' if ip_indicator.value in a_records else 'AAAA'
                    },
                    timestamp=datetime.utcnow()
                )
            
            return None
            
        except Exception as e:
            logger.error(f"Mixed network correlation error: {e}")
            return None


class AttributeCorrelationAnalyzer:
    """Analyzes attribute-based correlations between indicators."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize attribute correlation analyzer."""
        self.config = config or {}
    
    def analyze_attribute_correlation(self, indicator1: NormalizedIndicator, 
                                    indicator2: NormalizedIndicator) -> Optional[CorrelationResult]:
        """Analyze attribute correlation between two indicators."""
        try:
            correlations = []
            
            # Source correlation
            source_corr = self._analyze_source_correlation(indicator1, indicator2)
            if source_corr:
                correlations.append(source_corr)
            
            # Confidence correlation
            confidence_corr = self._analyze_confidence_correlation(indicator1, indicator2)
            if confidence_corr:
                correlations.append(confidence_corr)
            
            # Tags/Labels correlation
            tags_corr = self._analyze_tags_correlation(indicator1, indicator2)
            if tags_corr:
                correlations.append(tags_corr)
            
            # Pattern correlation (for file hashes, URLs, etc.)
            pattern_corr = self._analyze_pattern_correlation(indicator1, indicator2)
            if pattern_corr:
                correlations.append(pattern_corr)
            
            # If we have correlations, return the strongest one
            if correlations:
                best_correlation = max(correlations, key=lambda x: x['score'])
                
                return CorrelationResult(
                    indicator1_id=indicator1.id,
                    indicator2_id=indicator2.id,
                    correlation_type=CorrelationType.ATTRIBUTE,
                    strength=best_correlation['strength'],
                    score=best_correlation['score'],
                    confidence=best_correlation['confidence'],
                    evidence=best_correlation['evidence'],
                    timestamp=datetime.utcnow()
                )
            
            return None
            
        except Exception as e:
            logger.error(f"Attribute correlation error: {e}")
            return None
    
    def _analyze_source_correlation(self, indicator1: NormalizedIndicator, 
                                   indicator2: NormalizedIndicator) -> Optional[Dict[str, Any]]:
        """Analyze correlation based on source."""
        if indicator1.source_metadata.source_name == indicator2.source_metadata.source_name:
            return {
                'score': 0.6,
                'strength': CorrelationStrength.MODERATE,
                'confidence': 0.8,
                'evidence': {
                    'attribute_type': 'source',
                    'shared_source': indicator1.source_metadata.source_name,
                    'relationship': 'same_source'
                }
            }
        return None
    
    def _analyze_confidence_correlation(self, indicator1: NormalizedIndicator, 
                                      indicator2: NormalizedIndicator) -> Optional[Dict[str, Any]]:
        """Analyze correlation based on confidence levels."""
        conf_diff = abs(indicator1.confidence - indicator2.confidence)
        
        # High confidence indicators with similar confidence levels
        if indicator1.confidence >= 80 and indicator2.confidence >= 80 and conf_diff <= 10:
            return {
                'score': 0.4,
                'strength': CorrelationStrength.WEAK,
                'confidence': 0.6,
                'evidence': {
                    'attribute_type': 'confidence',
                    'confidence1': indicator1.confidence,
                    'confidence2': indicator2.confidence,
                    'confidence_difference': conf_diff,
                    'relationship': 'similar_high_confidence'
                }
            }
        
        return None
    
    def _analyze_tags_correlation(self, indicator1: NormalizedIndicator, 
                                 indicator2: NormalizedIndicator) -> Optional[Dict[str, Any]]:
        """Analyze correlation based on tags/labels."""
        # Extract tags from context
        tags1 = set(indicator1.context.get('tags', []))
        tags2 = set(indicator2.context.get('tags', []))
        
        if tags1 and tags2:
            common_tags = tags1.intersection(tags2)
            if common_tags:
                jaccard_similarity = len(common_tags) / len(tags1.union(tags2))
                
                if jaccard_similarity >= 0.5:
                    strength = CorrelationStrength.STRONG if jaccard_similarity >= 0.7 else CorrelationStrength.MODERATE
                    
                    return {
                        'score': min(jaccard_similarity * 0.8, 0.7),
                        'strength': strength,
                        'confidence': 0.7,
                        'evidence': {
                            'attribute_type': 'tags',
                            'common_tags': list(common_tags),
                            'jaccard_similarity': jaccard_similarity,
                            'relationship': 'shared_tags'
                        }
                    }
        
        return None
    
    def _analyze_pattern_correlation(self, indicator1: NormalizedIndicator, 
                                   indicator2: NormalizedIndicator) -> Optional[Dict[str, Any]]:
        """Analyze correlation based on value patterns."""
        # URL path correlation
        if indicator1.indicator_type == IndicatorType.URL and indicator2.indicator_type == IndicatorType.URL:
            return self._analyze_url_pattern_correlation(indicator1.value, indicator2.value)
        
        # File hash family correlation  
        if (indicator1.indicator_type in {IndicatorType.MD5, IndicatorType.SHA1, IndicatorType.SHA256} and
            indicator2.indicator_type in {IndicatorType.MD5, IndicatorType.SHA1, IndicatorType.SHA256}):
            return self._analyze_hash_pattern_correlation(indicator1, indicator2)
        
        return None
    
    def _analyze_url_pattern_correlation(self, url1: str, url2: str) -> Optional[Dict[str, Any]]:
        """Analyze URL pattern correlation."""
        try:
            from urllib.parse import urlparse
            
            parsed1 = urlparse(url1)
            parsed2 = urlparse(url2)
            
            # Same domain and similar path structure
            if parsed1.netloc == parsed2.netloc:
                path_similarity = self._calculate_path_similarity(parsed1.path, parsed2.path)
                
                if path_similarity >= 0.6:
                    return {
                        'score': min(path_similarity * 0.6, 0.6),
                        'strength': CorrelationStrength.MODERATE,
                        'confidence': 0.7,
                        'evidence': {
                            'attribute_type': 'url_pattern',
                            'same_domain': parsed1.netloc,
                            'path_similarity': path_similarity,
                            'relationship': 'similar_url_structure'
                        }
                    }
            
            return None
            
        except Exception:
            return None
    
    def _calculate_path_similarity(self, path1: str, path2: str) -> float:
        """Calculate similarity between URL paths."""
        if not path1 and not path2:
            return 1.0
        
        if not path1 or not path2:
            return 0.0
        
        # Simple Jaccard similarity on path segments
        segments1 = set(path1.strip('/').split('/'))
        segments2 = set(path2.strip('/').split('/'))
        
        if not segments1 and not segments2:
            return 1.0
        
        intersection = segments1.intersection(segments2)
        union = segments1.union(segments2)
        
        return len(intersection) / len(union) if union else 0.0
    
    def _analyze_hash_pattern_correlation(self, indicator1: NormalizedIndicator, 
                                        indicator2: NormalizedIndicator) -> Optional[Dict[str, Any]]:
        """Analyze file hash pattern correlation."""
        # If same file is represented with different hash types
        context1 = indicator1.context
        context2 = indicator2.context
        
        # Check if they have related file information
        filename1 = context1.get('filename')
        filename2 = context2.get('filename')
        
        if filename1 and filename2 and filename1 == filename2:
            return {
                'score': 0.8,
                'strength': CorrelationStrength.STRONG,
                'confidence': 0.9,
                'evidence': {
                    'attribute_type': 'file_hash',
                    'same_filename': filename1,
                    'hash_type1': indicator1.indicator_type.value,
                    'hash_type2': indicator2.indicator_type.value,
                    'relationship': 'same_file_different_hashes'
                }
            }
        
        return None


class EnrichmentCorrelationAnalyzer:
    """Analyzes correlations based on enrichment data."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize enrichment correlation analyzer."""
        self.config = config or {}
    
    def analyze_enrichment_correlation(self, indicator1: NormalizedIndicator, 
                                     indicator2: NormalizedIndicator) -> Optional[CorrelationResult]:
        """Analyze correlation based on enrichment data."""
        try:
            correlations = []
            
            # Geolocation correlation
            geo_corr = self._analyze_geolocation_correlation(indicator1, indicator2)
            if geo_corr:
                correlations.append(geo_corr)
            
            # Reputation correlation
            rep_corr = self._analyze_reputation_correlation(indicator1, indicator2)
            if rep_corr:
                correlations.append(rep_corr)
            
            # ASN correlation (already handled in NetworkCorrelationAnalyzer)
            
            # Return the strongest correlation
            if correlations:
                best_correlation = max(correlations, key=lambda x: x['score'])
                
                return CorrelationResult(
                    indicator1_id=indicator1.id,
                    indicator2_id=indicator2.id,
                    correlation_type=CorrelationType.ENRICHMENT,
                    strength=best_correlation['strength'],
                    score=best_correlation['score'],
                    confidence=best_correlation['confidence'],
                    evidence=best_correlation['evidence'],
                    timestamp=datetime.utcnow()
                )
            
            return None
            
        except Exception as e:
            logger.error(f"Enrichment correlation error: {e}")
            return None
    
    def _analyze_geolocation_correlation(self, indicator1: NormalizedIndicator, 
                                       indicator2: NormalizedIndicator) -> Optional[Dict[str, Any]]:
        """Analyze geolocation-based correlation."""
        try:
            enrich1 = indicator1.context.get('enrichment', {}).get('geolocation', {})
            enrich2 = indicator2.context.get('enrichment', {}).get('geolocation', {})
            
            if not enrich1 or not enrich2:
                return None
            
            country1 = enrich1.get('country')
            country2 = enrich2.get('country')
            city1 = enrich1.get('city')
            city2 = enrich2.get('city')
            
            # Same city - strong correlation
            if city1 and city2 and city1 == city2:
                return {
                    'score': 0.7,
                    'strength': CorrelationStrength.STRONG,
                    'confidence': 0.8,
                    'evidence': {
                        'enrichment_type': 'geolocation',
                        'same_city': city1,
                        'country': country1,
                        'relationship': 'same_geolocation'
                    }
                }
            
            # Same country - moderate correlation
            if country1 and country2 and country1 == country2:
                return {
                    'score': 0.4,
                    'strength': CorrelationStrength.MODERATE,
                    'confidence': 0.6,
                    'evidence': {
                        'enrichment_type': 'geolocation',
                        'same_country': country1,
                        'city1': city1,
                        'city2': city2,
                        'relationship': 'same_country'
                    }
                }
            
            return None
            
        except Exception as e:
            logger.error(f"Geolocation correlation error: {e}")
            return None
    
    def _analyze_reputation_correlation(self, indicator1: NormalizedIndicator, 
                                      indicator2: NormalizedIndicator) -> Optional[Dict[str, Any]]:
        """Analyze reputation-based correlation."""
        try:
            rep1 = indicator1.context.get('enrichment', {}).get('reputation', {})
            rep2 = indicator2.context.get('enrichment', {}).get('reputation', {})
            
            if not rep1 or not rep2:
                return None
            
            score1 = rep1.get('reputation_score', 0)
            score2 = rep2.get('reputation_score', 0)
            category1 = rep1.get('category', '')
            category2 = rep2.get('category', '')
            
            # Both have negative reputation - correlation based on threat level
            if score1 < 0 and score2 < 0:
                score_similarity = 1 - abs(score1 - score2) / 100  # Normalize to 0-1
                
                if score_similarity >= 0.7:
                    return {
                        'score': min(score_similarity * 0.6, 0.6),
                        'strength': CorrelationStrength.MODERATE,
                        'confidence': 0.7,
                        'evidence': {
                            'enrichment_type': 'reputation',
                            'reputation_score1': score1,
                            'reputation_score2': score2,
                            'category1': category1,
                            'category2': category2,
                            'score_similarity': score_similarity,
                            'relationship': 'similar_negative_reputation'
                        }
                    }
            
            return None
            
        except Exception as e:
            logger.error(f"Reputation correlation error: {e}")
            return None


class CorrelationEngine:
    """Main correlation engine that orchestrates all correlation analyses."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize correlation engine."""
        self.config = config or {}
        
        # Initialize analyzers
        self.temporal_analyzer = TemporalCorrelationAnalyzer(self.config.get('temporal', {}))
        self.network_analyzer = NetworkCorrelationAnalyzer(self.config.get('network', {}))
        self.attribute_analyzer = AttributeCorrelationAnalyzer(self.config.get('attribute', {}))
        self.enrichment_analyzer = EnrichmentCorrelationAnalyzer(self.config.get('enrichment', {}))
        
        logger.info("Correlation engine initialized")
    
    def analyze_correlations(self, indicator1: NormalizedIndicator, 
                           indicator2: NormalizedIndicator) -> List[CorrelationResult]:
        """Analyze all types of correlations between two indicators."""
        correlations = []
        
        # Skip self-correlation
        if indicator1.id == indicator2.id:
            return correlations
        
        # Temporal correlation
        temporal_result = self.temporal_analyzer.analyze_temporal_correlation(indicator1, indicator2)
        if temporal_result:
            correlations.append(temporal_result)
        
        # Network correlation  
        network_result = self.network_analyzer.analyze_network_correlation(indicator1, indicator2)
        if network_result:
            correlations.append(network_result)
        
        # Attribute correlation
        attribute_result = self.attribute_analyzer.analyze_attribute_correlation(indicator1, indicator2)
        if attribute_result:
            correlations.append(attribute_result)
        
        # Enrichment correlation
        enrichment_result = self.enrichment_analyzer.analyze_enrichment_correlation(indicator1, indicator2)
        if enrichment_result:
            correlations.append(enrichment_result)
        
        return correlations
    
    def batch_correlation_analysis(self, indicators: List[NormalizedIndicator]) -> List[CorrelationResult]:
        """Perform correlation analysis on a batch of indicators."""
        all_correlations = []
        
        logger.info(f"Starting batch correlation analysis for {len(indicators)} indicators")
        
        # Compare each pair of indicators
        for i in range(len(indicators)):
            for j in range(i + 1, len(indicators)):
                correlations = self.analyze_correlations(indicators[i], indicators[j])
                all_correlations.extend(correlations)
        
        logger.info(f"Found {len(all_correlations)} correlations")
        return all_correlations
    
    def find_correlation_clusters(self, correlations: List[CorrelationResult], 
                                min_correlation_score: float = 0.5) -> List[Set[str]]:
        """Find clusters of correlated indicators."""
        # Build graph of correlations
        correlation_graph = {}
        
        for corr in correlations:
            if corr.score >= min_correlation_score:
                # Add edges in both directions
                if corr.indicator1_id not in correlation_graph:
                    correlation_graph[corr.indicator1_id] = set()
                if corr.indicator2_id not in correlation_graph:
                    correlation_graph[corr.indicator2_id] = set()
                
                correlation_graph[corr.indicator1_id].add(corr.indicator2_id)
                correlation_graph[corr.indicator2_id].add(corr.indicator1_id)
        
        # Find connected components (clusters)
        visited = set()
        clusters = []
        
        def dfs(node, cluster):
            if node in visited:
                return
            visited.add(node)
            cluster.add(node)
            
            for neighbor in correlation_graph.get(node, []):
                dfs(neighbor, cluster)
        
        for node in correlation_graph:
            if node not in visited:
                cluster = set()
                dfs(node, cluster)
                if len(cluster) > 1:  # Only include clusters with multiple indicators
                    clusters.append(cluster)
        
        logger.info(f"Found {len(clusters)} correlation clusters")
        return clusters