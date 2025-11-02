"""
VirusTotal API collector for file hashes, IPs, URLs, and domains.

This collector interfaces with VirusTotal's API v3 to gather threat intelligence
about malicious files, suspicious IPs, malicious URLs, and dangerous domains.
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, Iterator, Optional

from .base import RestApiCollector

logger = logging.getLogger(__name__)


class VirusTotalCollector(RestApiCollector):
    """Collector for VirusTotal threat intelligence."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize VirusTotal collector."""
        super().__init__(
            source_name="virustotal_intel",
            base_url="https://www.virustotal.com/api/v3",
            config=config
        )
        
        # VirusTotal-specific rate limiting (4 requests per minute for free accounts)
        vt_rate_limit = self.source_config.get('rate_limit_per_minute', 4)
        self.delay_between_requests = 60.0 / vt_rate_limit if vt_rate_limit > 0 else 15.0
    
    def collect(self, date: Optional[str] = None) -> str:
        """
        Collect VirusTotal threat intelligence data.
        
        Args:
            date: Date string in YYYY-MM-DD format
            
        Returns:
            Path to output file
        """
        output_file = self._get_output_file(date)
        
        if not self.is_available():
            logger.error(f"VirusTotal collector not available - check API key")
            return str(output_file)
        
        logger.info(f"Starting VirusTotal collection for {date or 'today'}")
        
        indicators = self._collect_recent_indicators()
        count = self._write_indicators(indicators, output_file)
        
        logger.info(f"VirusTotal collection complete: {count} indicators")
        return str(output_file)
    
    def is_available(self) -> bool:
        """Check if VirusTotal API is available."""
        if not self.api_key:
            return False
        
        try:
            # Test API with a simple quota check
            url = f"{self.base_url}/users/{self.api_key.split('-')[0] if '-' in self.api_key else 'current'}/overall_quotas"
            response = self._make_request(url)
            return response is not None
        except Exception:
            return False
    
    def _collect_recent_indicators(self) -> Iterator[Dict[str, Any]]:
        """Collect recent malicious indicators from VirusTotal."""
        
        # Collect recent malicious files
        yield from self._collect_recent_files()
        
        # Collect recent malicious URLs
        yield from self._collect_recent_urls()
        
        # Collect recent malicious domains
        yield from self._collect_recent_domains()
        
        # Collect recent malicious IPs
        yield from self._collect_recent_ips()
    
    def _collect_recent_files(self) -> Iterator[Dict[str, Any]]:
        """Collect recent malicious file hashes."""
        logger.info("Collecting recent malicious files from VirusTotal")
        
        # Use VirusTotal Intelligence search for recent malware
        # Note: This requires VirusTotal Premium/Enterprise
        search_queries = [
            "type:peexe positives:5+ fs:2024-01-01+",  # Recent PE files with 5+ detections
            "type:pdf positives:3+ fs:2024-01-01+",   # Recent malicious PDFs
            "type:docx positives:3+ fs:2024-01-01+",  # Recent malicious Office docs
        ]
        
        for query in search_queries:
            try:
                url = f"{self.base_url}/intelligence/search"
                params = {
                    'query': query,
                    'limit': 100  # Limit results per query
                }
                
                response = self._make_request(url, params=params)
                if not response or 'data' not in response:
                    continue
                
                for item in response['data']:
                    if 'attributes' in item:
                        yield self._normalize_file_indicator(item)
                        
            except Exception as e:
                logger.error(f"Error collecting files with query '{query}': {e}")
    
    def _collect_recent_urls(self) -> Iterator[Dict[str, Any]]:
        """Collect recent malicious URLs."""
        logger.info("Collecting recent malicious URLs from VirusTotal")
        
        # Use URL intelligence search
        search_queries = [
            "positives:3+ ls:7d",  # URLs with 3+ detections in last 7 days
        ]
        
        for query in search_queries:
            try:
                url = f"{self.base_url}/intelligence/search"
                params = {
                    'query': query,
                    'descriptors_only': 'false',
                    'limit': 50
                }
                
                response = self._make_request(url, params=params)
                if not response or 'data' not in response:
                    continue
                
                for item in response['data']:
                    if item.get('type') == 'url' and 'attributes' in item:
                        yield self._normalize_url_indicator(item)
                        
            except Exception as e:
                logger.error(f"Error collecting URLs with query '{query}': {e}")
    
    def _collect_recent_domains(self) -> Iterator[Dict[str, Any]]:
        """Collect recent malicious domains."""
        logger.info("Collecting recent malicious domains from VirusTotal")
        
        # Use domain intelligence search
        search_queries = [
            "positives:2+ ls:7d",  # Domains with 2+ detections in last 7 days
        ]
        
        for query in search_queries:
            try:
                url = f"{self.base_url}/intelligence/search"
                params = {
                    'query': query,
                    'descriptors_only': 'false',
                    'limit': 50
                }
                
                response = self._make_request(url, params=params)
                if not response or 'data' not in response:
                    continue
                
                for item in response['data']:
                    if item.get('type') == 'domain' and 'attributes' in item:
                        yield self._normalize_domain_indicator(item)
                        
            except Exception as e:
                logger.error(f"Error collecting domains with query '{query}': {e}")
    
    def _collect_recent_ips(self) -> Iterator[Dict[str, Any]]:
        """Collect recent malicious IP addresses."""
        logger.info("Collecting recent malicious IPs from VirusTotal")
        
        # Use IP intelligence search
        search_queries = [
            "positives:2+ ls:7d",  # IPs with 2+ detections in last 7 days
        ]
        
        for query in search_queries:
            try:
                url = f"{self.base_url}/intelligence/search"
                params = {
                    'query': query,
                    'descriptors_only': 'false', 
                    'limit': 50
                }
                
                response = self._make_request(url, params=params)
                if not response or 'data' not in response:
                    continue
                
                for item in response['data']:
                    if item.get('type') == 'ip_address' and 'attributes' in item:
                        yield self._normalize_ip_indicator(item)
                        
            except Exception as e:
                logger.error(f"Error collecting IPs with query '{query}': {e}")
    
    def _make_request(self, url: str, **kwargs) -> Optional[Dict[str, Any]]:
        """Make authenticated request to VirusTotal API."""
        headers = self.headers.copy()
        headers['x-apikey'] = self.api_key
        
        try:
            import time
            time.sleep(self.delay_between_requests)  # Rate limiting
            
            from ..utils.http import get
            response = get(url, headers=headers, **kwargs)
            return response
        except Exception as e:
            logger.error(f"VirusTotal API request failed: {e}")
            return None
    
    def _normalize_file_indicator(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize VirusTotal file data to common format."""
        attrs = item.get('attributes', {})
        stats = attrs.get('last_analysis_stats', {})
        
        return {
            'type': 'file_hash',
            'value': item.get('id', ''),
            'context': {
                'md5': attrs.get('md5'),
                'sha1': attrs.get('sha1'), 
                'sha256': attrs.get('sha256'),
                'file_type': attrs.get('type_description'),
                'file_size': attrs.get('size'),
                'detection_ratio': f"{stats.get('malicious', 0)}/{sum(stats.values())}",
                'first_seen': attrs.get('first_submission_date'),
                'last_seen': attrs.get('last_analysis_date'),
                'names': attrs.get('names', [])
            },
            'confidence': min(stats.get('malicious', 0) * 10, 100),  # Scale to 0-100
            'severity': 'high' if stats.get('malicious', 0) > 10 else 'medium',
            'source_url': f"https://www.virustotal.com/gui/file/{item.get('id', '')}",
            'tags': ['malware', 'file_hash']
        }
    
    def _normalize_url_indicator(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize VirusTotal URL data to common format."""
        attrs = item.get('attributes', {})
        stats = attrs.get('last_analysis_stats', {})
        
        return {
            'type': 'url',
            'value': attrs.get('url', ''),
            'context': {
                'detection_ratio': f"{stats.get('malicious', 0)}/{sum(stats.values())}",
                'first_seen': attrs.get('first_submission_date'),
                'last_seen': attrs.get('last_analysis_date'),
                'final_url': attrs.get('last_final_url'),
                'title': attrs.get('title')
            },
            'confidence': min(stats.get('malicious', 0) * 15, 100),
            'severity': 'high' if stats.get('malicious', 0) > 5 else 'medium',
            'source_url': f"https://www.virustotal.com/gui/url/{item.get('id', '')}/detection",
            'tags': ['malicious_url', 'phishing']
        }
    
    def _normalize_domain_indicator(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize VirusTotal domain data to common format."""
        attrs = item.get('attributes', {})
        stats = attrs.get('last_analysis_stats', {})
        
        return {
            'type': 'domain',
            'value': item.get('id', ''),
            'context': {
                'detection_ratio': f"{stats.get('malicious', 0)}/{sum(stats.values())}",
                'registrar': attrs.get('registrar'),
                'creation_date': attrs.get('creation_date'),
                'last_update_date': attrs.get('last_update_date'),
                'categories': attrs.get('categories', {}),
                'popularity_rank': attrs.get('popularity_ranks', {})
            },
            'confidence': min(stats.get('malicious', 0) * 20, 100),
            'severity': 'high' if stats.get('malicious', 0) > 3 else 'medium',
            'source_url': f"https://www.virustotal.com/gui/domain/{item.get('id', '')}",
            'tags': ['malicious_domain', 'c2']
        }
    
    def _normalize_ip_indicator(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize VirusTotal IP data to common format."""
        attrs = item.get('attributes', {})
        stats = attrs.get('last_analysis_stats', {})
        
        return {
            'type': 'ip',
            'value': item.get('id', ''),
            'context': {
                'detection_ratio': f"{stats.get('malicious', 0)}/{sum(stats.values())}",
                'country': attrs.get('country'),
                'asn': attrs.get('asn'),
                'as_owner': attrs.get('as_owner'),
                'network': attrs.get('network')
            },
            'confidence': min(stats.get('malicious', 0) * 20, 100),
            'severity': 'high' if stats.get('malicious', 0) > 3 else 'medium', 
            'source_url': f"https://www.virustotal.com/gui/ip-address/{item.get('id', '')}",
            'tags': ['malicious_ip', 'c2']
        }