"""
URLhaus collector for malicious URLs and malware distribution sites.

URLhaus is a project from abuse.ch that shares malicious URLs used for malware
distribution. It provides CSV feeds and an API for real-time threat intelligence.
"""

import csv
import io
import logging
from datetime import datetime
from typing import Any, Dict, Iterator, Optional

from .base import CsvCollector

logger = logging.getLogger(__name__)


class URLhausCollector(CsvCollector):
    """Collector for URLhaus malicious URL feed."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize URLhaus collector."""
        super().__init__(
            source_name="urlhaus_recent",
            feed_url="https://urlhaus.abuse.ch/downloads/csv_recent/",
            config=config
        )
    
    def is_available(self) -> bool:
        """Check if URLhaus feed is available."""
        # URLhaus is a public feed, so just check if we have a valid URL
        return bool(self.feed_url and self.feed_url.startswith('https://'))
    
    def collect(self, date: Optional[str] = None) -> str:
        """
        Collect URLhaus threat intelligence data.
        
        Args:
            date: Date string in YYYY-MM-DD format
            
        Returns:
            Path to output file
        """
        output_file = self._get_output_file(date)
        
        if not self.is_available():
            logger.error("URLhaus feed not available")
            return str(output_file)
        
        logger.info(f"Starting URLhaus collection for {date or 'today'}")
        
        indicators = self._collect_malicious_urls()
        count = self._write_indicators(indicators, output_file)
        
        logger.info(f"URLhaus collection complete: {count} indicators")
        return str(output_file)
    
    def _collect_malicious_urls(self) -> Iterator[Dict[str, Any]]:
        """Collect malicious URLs from URLhaus CSV feed."""
        try:
            from ..utils.http import get
            
            # Get the CSV feed
            response = get(self.feed_url, headers=self.headers)
            if not response:
                logger.error("Failed to fetch URLhaus CSV feed")
                return
            
            # Parse CSV content
            csv_content = response.text if hasattr(response, 'text') else str(response)
            lines = csv_content.split('\n')
            
            # Find the header line and extract field names
            fieldnames = None
            data_lines = []
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                elif line.startswith('#'):
                    # Check if this is the header line
                    if 'id,dateadded,url' in line:
                        # Extract field names from header comment
                        header_part = line[1:].strip()  # Remove the #
                        fieldnames = [field.strip() for field in header_part.split(',')]
                else:
                    # Data line
                    data_lines.append(line)
            
            if not fieldnames:
                # Fallback fieldnames if header not found
                fieldnames = ['id', 'dateadded', 'url', 'url_status', 'last_online', 'threat', 'tags', 'urlhaus_link', 'reporter']
            
            # Parse CSV with correct fieldnames
            csv_reader = csv.DictReader(data_lines, fieldnames=fieldnames)
            
            for row in csv_reader:
                indicator = self._normalize_url_indicator(row)
                if indicator:
                    yield indicator
                    
        except Exception as e:
            logger.error(f"Error collecting URLhaus data: {e}")
    
    def _normalize_url_indicator(self, row: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Normalize URLhaus CSV row to common indicator format.
        
        Args:
            row: CSV row dictionary
            
        Returns:
            Normalized indicator or None if invalid
        """
        try:
            # Extract key fields from URLhaus CSV
            url = row.get('url', '').strip()
            if not url:
                return None
            
            # Calculate confidence based on status and threat
            status = row.get('url_status', '').lower()
            threat = row.get('threat', '').lower()
            
            confidence = 70  # Base confidence for URLhaus
            if status == 'online':
                confidence += 20
            if threat in ['malware_download', 'botnet_cc']:
                confidence += 10
            
            # Determine severity
            severity = 'high' if threat in ['malware_download', 'botnet_cc'] else 'medium'
            
            # Build tags
            tags = ['malicious_url', 'malware_distribution']
            if threat:
                tags.append(threat.replace('_', '-'))
            
            return {
                'type': 'url',
                'value': url,
                'context': {
                    'date_added': row.get('dateadded'),
                    'url_status': status,
                    'threat_type': threat,
                    'tags': row.get('tags', '').split(',') if row.get('tags') else [],
                    'urlhaus_link': row.get('urlhaus_link'),
                    'reporter': row.get('reporter')
                },
                'confidence': min(confidence, 100),
                'severity': severity,
                'source_url': row.get('urlhaus_link', ''),
                'tags': tags
            }
            
        except Exception as e:
            logger.error(f"Error normalizing URLhaus indicator: {e}")
            return None


class MalwareBazaarCollector(CsvCollector):
    """Collector for MalwareBazaar malware samples."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize MalwareBazaar collector.""" 
        super().__init__(
            source_name="malwarebazaar_recent",
            feed_url="https://bazaar.abuse.ch/export/csv/recent/",
            config=config
        )
    
    def is_available(self) -> bool:
        """Check if MalwareBazaar feed is available."""
        # MalwareBazaar is a public feed, so just check if we have a valid URL
        return bool(self.feed_url and self.feed_url.startswith('https://'))
    
    def collect(self, date: Optional[str] = None) -> str:
        """
        Collect MalwareBazaar threat intelligence data.
        
        Args:
            date: Date string in YYYY-MM-DD format
            
        Returns:
            Path to output file
        """
        output_file = self._get_output_file(date)
        
        if not self.is_available():
            logger.error("MalwareBazaar feed not available")
            return str(output_file)
        
        logger.info(f"Starting MalwareBazaar collection for {date or 'today'}")
        
        indicators = self._collect_malware_samples()
        count = self._write_indicators(indicators, output_file)
        
        logger.info(f"MalwareBazaar collection complete: {count} indicators")
        return str(output_file)
    
    def _collect_malware_samples(self) -> Iterator[Dict[str, Any]]:
        """Collect malware samples from MalwareBazaar CSV feed."""
        try:
            from ..utils.http import get
            
            # Get the CSV feed
            response = get(self.feed_url, headers=self.headers)
            if not response:
                logger.error("Failed to fetch MalwareBazaar CSV feed")
                return
            
            # Parse CSV content
            csv_content = response.text if hasattr(response, 'text') else str(response)
            lines = csv_content.split('\n')
            
            # Find the header line and extract field names
            fieldnames = None
            data_lines = []
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                elif line.startswith('#'):
                    # Check if this is the header line
                    if 'first_seen_utc' in line and 'sha256_hash' in line:
                        # Extract field names from header comment
                        header_part = line[1:].strip()  # Remove the #
                        # Parse quoted field names
                        import re
                        fieldnames = re.findall(r'"([^"]*)"', header_part)
                else:
                    # Data line
                    data_lines.append(line)
            
            if not fieldnames:
                # Fallback fieldnames if header not found
                fieldnames = ['first_seen_utc', 'sha256_hash', 'md5_hash', 'sha1_hash', 'reporter', 'file_name', 'file_type_guess', 'mime_type', 'signature', 'clamav', 'vtpercent', 'imphash', 'ssdeep', 'tlsh']
            
            # Parse CSV with correct fieldnames
            csv_reader = csv.DictReader(data_lines, fieldnames=fieldnames)
            
            for row in csv_reader:
                indicator = self._normalize_sample_indicator(row)
                if indicator:
                    yield indicator
                    
        except Exception as e:
            logger.error(f"Error collecting MalwareBazaar data: {e}")
    
    def _normalize_sample_indicator(self, row: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Normalize MalwareBazaar CSV row to common indicator format.
        
        Args:
            row: CSV row dictionary
            
        Returns:
            Normalized indicator or None if invalid
        """
        try:
            # Extract key fields
            sha256_hash = row.get('sha256_hash', '').strip()
            if not sha256_hash:
                return None
            
            # Build indicator
            malware_family = row.get('signature', '')
            file_type = row.get('file_type', '')
            
            # Calculate confidence based on signature and file type
            confidence = 85  # High confidence for MalwareBazaar samples
            
            # Determine severity based on malware family
            high_severity_families = [
                'ransomware', 'banking', 'stealer', 'backdoor', 'trojan'
            ]
            severity = 'high' if any(family in malware_family.lower() 
                                   for family in high_severity_families) else 'medium'
            
            # Build tags
            tags = ['malware', 'file_hash']
            if malware_family:
                tags.append(malware_family.lower().replace(' ', '_'))
            if file_type:
                tags.append(file_type.lower())
            
            return {
                'type': 'file_hash',
                'value': sha256_hash,
                'context': {
                    'md5_hash': row.get('md5_hash'),
                    'sha1_hash': row.get('sha1_hash'),
                    'sha256_hash': sha256_hash,
                    'file_size': row.get('file_size'),
                    'file_type': file_type,
                    'mime_type': row.get('mime_type'),
                    'signature': malware_family,
                    'first_seen': row.get('first_seen'),
                    'last_seen': row.get('last_seen'),
                    'ssdeep': row.get('ssdeep'),
                    'tlsh': row.get('tlsh')
                },
                'confidence': confidence,
                'severity': severity,
                'source_url': f"https://bazaar.abuse.ch/sample/{sha256_hash}/",
                'tags': tags
            }
            
        except Exception as e:
            logger.error(f"Error normalizing MalwareBazaar indicator: {e}")
            return None


class ThreatFoxCollector(CsvCollector):
    """Collector for ThreatFox IOCs (Indicators of Compromise)."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize ThreatFox collector."""
        super().__init__(
            source_name="threatfox",
            feed_url="https://threatfox.abuse.ch/export/csv/recent/",
            config=config
        )
    
    def is_available(self) -> bool:
        """Check if ThreatFox feed is available."""
        # ThreatFox is a public feed, so just check if we have a valid URL
        return bool(self.feed_url and self.feed_url.startswith('https://'))
    
    def collect(self, date: Optional[str] = None) -> str:
        """
        Collect ThreatFox threat intelligence data.
        
        Args:
            date: Date string in YYYY-MM-DD format
            
        Returns:
            Path to output file
        """
        output_file = self._get_output_file(date)
        
        if not self.is_available():
            logger.error("ThreatFox feed not available")
            return str(output_file)
        
        logger.info(f"Starting ThreatFox collection for {date or 'today'}")
        
        indicators = self._collect_iocs()
        count = self._write_indicators(indicators, output_file)
        
        logger.info(f"ThreatFox collection complete: {count} indicators")
        return str(output_file)
    
    def _collect_iocs(self) -> Iterator[Dict[str, Any]]:
        """Collect IOCs from ThreatFox CSV feed."""
        try:
            from ..utils.http import get
            
            # Get the CSV feed
            response = get(self.feed_url, headers=self.headers)
            if not response:
                logger.error("Failed to fetch ThreatFox CSV feed")
                return
            
            # Parse CSV content
            csv_content = response.text if hasattr(response, 'text') else str(response)
            lines = csv_content.split('\n')
            
            # Find the header line and extract field names
            fieldnames = None
            data_lines = []
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                elif line.startswith('#'):
                    # Check if this is the header line
                    if 'first_seen_utc' in line and 'ioc_id' in line:
                        # Extract field names from header comment
                        header_part = line[1:].strip()  # Remove the #
                        # Parse quoted field names
                        import re
                        fieldnames = re.findall(r'"([^"]*)"', header_part)
                else:
                    # Data line
                    data_lines.append(line)
            
            if not fieldnames:
                # Fallback fieldnames if header not found
                fieldnames = ['first_seen_utc', 'ioc_id', 'ioc_value', 'ioc_type', 'threat_type', 'fk_malware', 'malware_alias', 'malware_printable', 'last_seen_utc', 'confidence_level', 'reference', 'tags', 'anonymous', 'reporter']
            
            # Parse CSV with correct fieldnames
            csv_reader = csv.DictReader(data_lines, fieldnames=fieldnames)
            
            for row in csv_reader:
                indicator = self._normalize_ioc_indicator(row)
                if indicator:
                    yield indicator
                    
        except Exception as e:
            logger.error(f"Error collecting ThreatFox data: {e}")
    
    def _normalize_ioc_indicator(self, row: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Normalize ThreatFox CSV row to common indicator format.
        
        Args:
            row: CSV row dictionary
            
        Returns:
            Normalized indicator or None if invalid
        """
        try:
            # Extract key fields
            ioc_value = row.get('ioc_value', '').strip()
            ioc_type = row.get('ioc_type', '').strip().lower()
            
            if not ioc_value or not ioc_type:
                return None
            
            # Map ThreatFox IOC types to our types
            type_mapping = {
                'ip:port': 'ip',
                'domain': 'domain',
                'url': 'url',
                'md5_hash': 'file_hash',
                'sha1_hash': 'file_hash',
                'sha256_hash': 'file_hash',
                'email': 'email'
            }
            
            indicator_type = type_mapping.get(ioc_type, ioc_type)
            
            # Extract metadata
            malware_family = row.get('malware', '')
            confidence_level = row.get('confidence_level', '50')
            
            # Convert confidence level to integer
            try:
                confidence = int(confidence_level)
            except (ValueError, TypeError):
                confidence = 50
            
            # Determine severity
            severity = 'high' if confidence > 75 else 'medium' if confidence > 50 else 'low'
            
            # Build tags
            tags = ['ioc', ioc_type.replace(':', '_')]
            if malware_family:
                tags.append(malware_family.lower().replace(' ', '_'))
            
            return {
                'type': indicator_type,
                'value': ioc_value,
                'context': {
                    'ioc_type': ioc_type,
                    'malware_family': malware_family,
                    'malware_alias': row.get('malware_alias'),
                    'confidence_level': confidence,
                    'first_seen': row.get('first_seen'),
                    'last_seen': row.get('last_seen'),
                    'reference': row.get('reference'),
                    'reporter': row.get('reporter')
                },
                'confidence': confidence,
                'severity': severity,
                'source_url': f"https://threatfox.abuse.ch/ioc/{row.get('id', '')}/",
                'tags': tags
            }
            
        except Exception as e:
            logger.error(f"Error normalizing ThreatFox indicator: {e}")
            return None