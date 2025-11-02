"""
AlienVault OTX (Open Threat Exchange) collector.

This collector interfaces with AlienVault's OTX API to gather threat intelligence
including malicious IPs, domains, URLs, file hashes, and other IOCs.
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, Iterator, List, Optional
from urllib.parse import urljoin

from .base import RestApiCollector

logger = logging.getLogger(__name__)


class OTXCollector(RestApiCollector):
    """Collector for AlienVault OTX threat intelligence."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize OTX collector."""
        super().__init__(
            source_name="otx_indicators",
            base_url="https://otx.alienvault.com/api/v1",
            config=config
        )
    
    def collect(self, date: Optional[str] = None) -> str:
        """
        Collect OTX threat intelligence data.
        
        Args:
            date: Date string in YYYY-MM-DD format
            
        Returns:
            Path to output file
        """
        output_file = self._get_output_file(date)
        
        if not self.is_available():
            logger.error("OTX collector not available - check API key")
            return str(output_file)
        
        logger.info(f"Starting OTX collection for {date or 'today'}")
        
        indicators = self._collect_recent_pulses()
        count = self._write_indicators(indicators, output_file)
        
        logger.info(f"OTX collection complete: {count} indicators")
        return str(output_file)
    
    def is_available(self) -> bool:
        """Check if OTX API is available."""
        if not self.api_key:
            return False
        
        try:
            # Test API with user info
            url = f"{self.base_url}/user/me"
            response = self._make_request(url)
            return response is not None
        except Exception:
            return False
    
    def _collect_recent_pulses(self) -> Iterator[Dict[str, Any]]:
        """Collect indicators from recent OTX pulses."""
        logger.info("Collecting recent pulses from OTX")
        
        try:
            # Get recent pulses (last 7 days)
            since_date = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S")
            
            url = f"{self.base_url}/pulses/subscribed"
            params = {
                'modified_since': since_date,
                'limit': 100
            }
            
            response = self._make_request(url, params=params)
            if not response or 'results' not in response:
                logger.warning("No recent pulses found in OTX")
                return
            
            for pulse in response['results']:
                yield from self._extract_indicators_from_pulse(pulse)
                
        except Exception as e:
            logger.error(f"Error collecting OTX pulses: {e}")
    
    def _extract_indicators_from_pulse(self, pulse: Dict[str, Any]) -> Iterator[Dict[str, Any]]:
        """Extract indicators from an OTX pulse."""
        try:
            pulse_id = pulse.get('id')
            pulse_name = pulse.get('name', '')
            pulse_description = pulse.get('description', '')
            malware_families = pulse.get('malware_families', [])
            attack_ids = pulse.get('attack_ids', [])
            
            # Get detailed pulse information including indicators
            detail_url = f"{self.base_url}/pulses/{pulse_id}"
            detail_response = self._make_request(detail_url)
            
            if not detail_response or 'indicators' not in detail_response:
                return
            
            for indicator_data in detail_response['indicators']:
                indicator = self._normalize_otx_indicator(
                    indicator_data, pulse_name, pulse_description, 
                    malware_families, attack_ids
                )
                if indicator:
                    yield indicator
                    
        except Exception as e:
            logger.error(f"Error extracting indicators from pulse {pulse.get('id', '')}: {e}")
    
    def _normalize_otx_indicator(self, indicator_data: Dict[str, Any], 
                               pulse_name: str, pulse_description: str,
                               malware_families: List[str], 
                               attack_ids: List[str]) -> Optional[Dict[str, Any]]:
        """
        Normalize OTX indicator to common format.
        
        Args:
            indicator_data: Raw indicator data from OTX
            pulse_name: Name of the pulse containing this indicator
            pulse_description: Description of the pulse
            malware_families: Associated malware families
            attack_ids: Associated ATT&CK technique IDs
            
        Returns:
            Normalized indicator or None if invalid
        """
        try:
            indicator_value = indicator_data.get('indicator', '').strip()
            indicator_type = indicator_data.get('type', '').strip().lower()
            
            if not indicator_value or not indicator_type:
                return None
            
            # Map OTX types to our standard types
            type_mapping = {
                'ipv4': 'ip',
                'ipv6': 'ip', 
                'domain': 'domain',
                'hostname': 'domain',
                'url': 'url',
                'uri': 'url',
                'md5': 'file_hash',
                'sha1': 'file_hash',
                'sha256': 'file_hash',
                'email': 'email',
                'filepath': 'file_path',
                'mutex': 'mutex',
                'cvv': 'cve'
            }
            
            normalized_type = type_mapping.get(indicator_type, indicator_type)
            
            # Calculate confidence based on available metadata
            confidence = 70  # Base confidence for OTX
            if malware_families:
                confidence += 15
            if attack_ids:
                confidence += 10
            if indicator_data.get('is_active'):
                confidence += 5
            
            # Determine severity
            severity = 'high'
            if any(family in ['ransomware', 'banker', 'stealer'] for family in malware_families):
                severity = 'critical'
            elif not malware_families and not attack_ids:
                severity = 'medium'
            
            # Build tags
            tags = ['otx', normalized_type]
            tags.extend([family.lower().replace(' ', '_') for family in malware_families])
            if attack_ids:
                tags.extend([f"mitre_{attack_id.lower()}" for attack_id in attack_ids])
            
            return {
                'type': normalized_type,
                'value': indicator_value,
                'context': {
                    'pulse_name': pulse_name,
                    'pulse_description': pulse_description[:500],  # Truncate long descriptions
                    'malware_families': malware_families,
                    'attack_ids': attack_ids,
                    'is_active': indicator_data.get('is_active'),
                    'role': indicator_data.get('role'),
                    'access_type': indicator_data.get('access_type'),
                    'access_reason': indicator_data.get('access_reason')
                },
                'confidence': min(confidence, 100),
                'severity': severity,
                'source_url': f"https://otx.alienvault.com/indicator/{indicator_type}/{indicator_value}",
                'tags': tags
            }
            
        except Exception as e:
            logger.error(f"Error normalizing OTX indicator: {e}")
            return None
    
    def _make_request(self, url: str, **kwargs) -> Optional[Dict[str, Any]]:
        """Make authenticated request to OTX API."""
        headers = self.headers.copy()
        headers['X-OTX-API-KEY'] = self.api_key
        
        try:
            import time
            time.sleep(self.delay_between_requests)  # Rate limiting
            
            from ..utils.http import get
            response = get(url, headers=headers, **kwargs)
            return response.json() if response else None
        except Exception as e:
            logger.error(f"OTX API request failed: {e}")
            return None


class ShodanCollector(RestApiCollector):
    """Collector for Shodan threat intelligence."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize Shodan collector."""
        super().__init__(
            source_name="shodan_honeypot",
            base_url="https://api.shodan.io",
            config=config
        )
    
    def collect(self, date: Optional[str] = None) -> str:
        """
        Collect Shodan threat intelligence data.
        
        Args:
            date: Date string in YYYY-MM-DD format
            
        Returns:
            Path to output file
        """
        output_file = self._get_output_file(date)
        
        if not self.is_available():
            logger.error("Shodan collector not available - check API key")
            return str(output_file)
        
        logger.info(f"Starting Shodan collection for {date or 'today'}")
        
        indicators = self._collect_malicious_hosts()
        count = self._write_indicators(indicators, output_file)
        
        logger.info(f"Shodan collection complete: {count} indicators")
        return str(output_file)
    
    def is_available(self) -> bool:
        """Check if Shodan API is available."""
        if not self.api_key:
            return False
        
        try:
            # Test API with account info
            url = f"{self.base_url}/account/profile?key={self.api_key}"
            response = self._make_request(url)
            return response is not None
        except Exception:
            return False
    
    def _collect_malicious_hosts(self) -> Iterator[Dict[str, Any]]:
        """Collect malicious hosts from Shodan using threat-focused queries."""
        logger.info("Collecting malicious hosts from Shodan")
        
        # Define threat-focused search queries
        threat_queries = [
            'category:malware',
            'vuln:*',
            'tag:honeypot',
            'tag:compromised',
            'has_screenshot:true port:3389',  # Exposed RDP
            'port:22 SSH-2.0-libssh',        # Potentially malicious SSH
            'http.title:"hacked"',            # Defaced websites
            '"botnet" port:80'                # Botnet C&C servers
        ]
        
        for query in threat_queries:
            try:
                url = f"{self.base_url}/shodan/host/search"
                params = {
                    'key': self.api_key,
                    'query': query,
                    'limit': 20  # Limit results per query
                }
                
                response = self._make_request(url, params=params)
                if not response or 'matches' not in response:
                    continue
                
                for host in response['matches']:
                    indicator = self._normalize_shodan_indicator(host, query)
                    if indicator:
                        yield indicator
                        
            except Exception as e:
                logger.error(f"Error collecting Shodan data for query '{query}': {e}")
    
    def _normalize_shodan_indicator(self, host: Dict[str, Any], 
                                  query: str) -> Optional[Dict[str, Any]]:
        """
        Normalize Shodan host data to common format.
        
        Args:
            host: Shodan host data
            query: The search query that found this host
            
        Returns:
            Normalized indicator or None if invalid
        """
        try:
            ip_str = host.get('ip_str', '').strip()
            if not ip_str:
                return None
            
            # Extract key metadata
            port = host.get('port')
            org = host.get('org', '')
            isp = host.get('isp', '')
            country = host.get('location', {}).get('country_name', '')
            city = host.get('location', {}).get('city', '')
            vulns = host.get('vulns', [])
            tags = host.get('tags', [])
            
            # Calculate confidence based on available threat indicators
            confidence = 60  # Base confidence
            if vulns:
                confidence += len(vulns) * 5  # 5 points per vulnerability
            if 'malware' in tags or 'compromised' in tags:
                confidence += 20
            if 'honeypot' in tags:
                confidence += 15
            
            # Determine severity
            severity = 'medium'
            if vulns:
                high_severity_vulns = ['ms17-010', 'wannacry', 'heartbleed']
                if any(vuln.lower() in high_severity_vulns for vuln in vulns):
                    severity = 'critical'
                elif len(vulns) > 3:
                    severity = 'high'
            if 'malware' in tags or 'botnet' in query.lower():
                severity = 'high'
            
            # Build context tags
            context_tags = ['shodan', 'exposed_service']
            context_tags.extend(tags)
            if vulns:
                context_tags.append('vulnerable')
            if port:
                context_tags.append(f'port_{port}')
            
            return {
                'type': 'ip',
                'value': ip_str,
                'context': {
                    'port': port,
                    'org': org,
                    'isp': isp,
                    'country': country,
                    'city': city,
                    'vulns': vulns,
                    'tags': tags,
                    'query': query,
                    'last_update': host.get('timestamp'),
                    'banner': host.get('data', '')[:200],  # Truncated banner
                    'product': host.get('product'),
                    'version': host.get('version')
                },
                'confidence': min(confidence, 100),
                'severity': severity,
                'source_url': f"https://www.shodan.io/host/{ip_str}",
                'tags': context_tags
            }
            
        except Exception as e:
            logger.error(f"Error normalizing Shodan indicator: {e}")
            return None
    
    def _make_request(self, url: str, **kwargs) -> Optional[Dict[str, Any]]:
        """Make authenticated request to Shodan API."""
        try:
            import time
            time.sleep(self.delay_between_requests)  # Rate limiting
            
            from ..utils.http import get
            response = get(url, headers=self.headers, **kwargs)
            return response.json() if response else None
        except Exception as e:
            logger.error(f"Shodan API request failed: {e}")
            return None