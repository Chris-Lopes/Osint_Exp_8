"""
Base collector class for threat intelligence sources.

This module provides the abstract base class that all threat intelligence
collectors should inherit from, ensuring consistent behavior across sources.
"""

import asyncio
import json
import logging
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from ..utils.env import load, getenv
from ..utils.http import get

logger = logging.getLogger(__name__)


class BaseCollector(ABC):
    """Abstract base class for threat intelligence collectors."""
    
    def __init__(self, source_name: str, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the collector.
        
        Args:
            source_name: Name of the threat intelligence source
            config: Optional configuration override
        """
        self.source_name = source_name
        self.config = config or load()
        
        # Get source configuration - handle both list and dict formats
        sources_config = self.config.get('sources', [])
        if isinstance(sources_config, list):
            # Convert list format to dict format for easier access
            sources_dict = {source['key']: source for source in sources_config}
            self.source_config = sources_dict.get(source_name, {})
        else:
            self.source_config = sources_config.get(source_name, {})
        
        # Set up rate limiting
        self.rate_limit = self.source_config.get('rate_limit_per_minute', 60)
        self.delay_between_requests = 60.0 / self.rate_limit if self.rate_limit > 0 else 0
        
        # Set up authentication
        auth_env_key = self.source_config.get('auth_env_key', f"API_KEY_{source_name.upper()}")
        self.api_key = getenv(auth_env_key)
        self.headers = self._build_headers()
        
        # Set up output directory
        self.output_dir = Path("data/raw") / source_name
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Initialized collector for {source_name}")
    
    def _build_headers(self) -> Dict[str, str]:
        """Build HTTP headers for API requests."""
        headers = {
            'User-Agent': getenv('GENERIC_USER_AGENT', 'Threat-Aggregation-Lab/1.0')
        }
        
        # Add authentication if available
        if self.api_key:
            auth_header = self.source_config.get('auth_header', 'X-API-Key')
            headers[auth_header] = self.api_key
        
        return headers
    
    @abstractmethod
    def collect(self, date: Optional[str] = None) -> str:
        """
        Collect threat intelligence data for the specified date.
        
        Args:
            date: Date string in YYYY-MM-DD format, defaults to today
            
        Returns:
            Path to the output file containing collected data
        """
        pass
    
    @abstractmethod
    def is_available(self) -> bool:
        """
        Check if the source is available and properly configured.
        
        Returns:
            True if source is available, False otherwise
        """
        pass
    
    def _get_output_file(self, date: Optional[str] = None) -> Path:
        """Get the output file path for the given date."""
        if date is None:
            date = datetime.now().strftime("%Y-%m-%d")
        return self.output_dir / f"{date}.jsonl"
    
    def _write_indicators(self, indicators: Iterator[Dict[str, Any]], 
                         output_file: Path) -> int:
        """
        Write indicators to JSONL file.
        
        Args:
            indicators: Iterator of indicator dictionaries
            output_file: Path to output file
            
        Returns:
            Number of indicators written
        """
        count = 0
        with open(output_file, 'w') as f:
            for indicator in indicators:
                # Add metadata
                indicator['_source'] = self.source_name
                indicator['_collected_at'] = datetime.now().isoformat()
                
                f.write(json.dumps(indicator) + '\n')
                count += 1
        
        logger.info(f"Wrote {count} indicators to {output_file}")
        return count
    
    async def _rate_limited_request(self, url: str, **kwargs) -> Optional[Dict[str, Any]]:
        """
        Make a rate-limited HTTP request.
        
        Args:
            url: URL to request
            **kwargs: Additional arguments for the request
            
        Returns:
            Response JSON or None if failed
        """
        # Apply rate limiting
        if self.delay_between_requests > 0:
            await asyncio.sleep(self.delay_between_requests)
        
        try:
            response = get(url, headers=self.headers, **kwargs)
            if response and 'json' in str(type(response)).lower():
                return response
            elif response:
                return response.json() if hasattr(response, 'json') else response
        except Exception as e:
            logger.error(f"Request failed for {url}: {e}")
            return None
        
        return None


class RestApiCollector(BaseCollector):
    """Base class for REST API-based collectors."""
    
    def __init__(self, source_name: str, base_url: str, config: Optional[Dict[str, Any]] = None):
        """
        Initialize REST API collector.
        
        Args:
            source_name: Name of the source
            base_url: Base URL for the API
            config: Optional configuration override
        """
        super().__init__(source_name, config)
        self.base_url = base_url.rstrip('/')
    
    def is_available(self) -> bool:
        """Check if the API is available."""
        try:
            # Try to make a simple request to check availability
            test_url = f"{self.base_url}/version" if "version" in self.source_config.get('endpoints', {}) else self.base_url
            response = get(test_url, headers=self.headers, timeout=10)
            return response is not None
        except Exception:
            return False


class CsvCollector(BaseCollector):
    """Base class for CSV/feed-based collectors."""
    
    def __init__(self, source_name: str, feed_url: str, config: Optional[Dict[str, Any]] = None):
        """
        Initialize CSV collector.
        
        Args:
            source_name: Name of the source
            feed_url: URL of the CSV/feed
            config: Optional configuration override
        """
        super().__init__(source_name, config)
        self.feed_url = feed_url
    
    def is_available(self) -> bool:
        """Check if the feed is available."""
        try:
            response = get(self.feed_url, headers=self.headers, timeout=10)
            return response is not None
        except Exception:
            return False
    
    def _parse_csv_line(self, line: str) -> Optional[Dict[str, Any]]:
        """
        Parse a single CSV line into an indicator.
        
        Args:
            line: CSV line to parse
            
        Returns:
            Parsed indicator or None if invalid
        """
        # Override in subclasses for source-specific parsing
        return None


class TaxiiCollector(BaseCollector):
    """Base class for TAXII-based collectors."""
    
    def __init__(self, source_name: str, discovery_url: str, 
                 config: Optional[Dict[str, Any]] = None):
        """
        Initialize TAXII collector.
        
        Args:
            source_name: Name of the source
            discovery_url: TAXII discovery URL
            config: Optional configuration override
        """
        super().__init__(source_name, config)
        self.discovery_url = discovery_url
        self.collections = []
    
    def is_available(self) -> bool:
        """Check if TAXII server is available."""
        try:
            response = get(self.discovery_url, headers=self.headers, timeout=10)
            return response is not None
        except Exception:
            return False
    
    def _discover_collections(self) -> List[Dict[str, Any]]:
        """Discover available TAXII collections."""
        # Implement TAXII discovery protocol
        # This would be expanded based on TAXII version (1.x vs 2.x)
        return []