"""
IP Geolocation enrichment service.

This module provides IP geolocation functionality using MaxMind GeoIP databases
and other geolocation APIs to enrich IP indicators with geographical context.
"""

import json
import logging
import requests
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Optional, Any, List
from ipaddress import ip_address, AddressValueError
import geoip2.database
import geoip2.errors

logger = logging.getLogger(__name__)


class GeolocationResult:
    """Result object for geolocation lookup."""
    
    def __init__(self, ip: str, success: bool = False):
        self.ip = ip
        self.success = success
        self.country = None
        self.country_code = None
        self.region = None
        self.region_code = None
        self.city = None
        self.postal_code = None
        self.latitude = None
        self.longitude = None
        self.timezone = None
        self.isp = None
        self.org = None
        self.asn = None
        self.asn_org = None
        self.is_anonymous_proxy = False
        self.is_satellite_provider = False
        self.accuracy_radius = None
        self.source = None
        self.error = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            'ip': self.ip,
            'success': self.success,
            'country': self.country,
            'country_code': self.country_code,
            'region': self.region,
            'region_code': self.region_code,
            'city': self.city,
            'postal_code': self.postal_code,
            'latitude': self.latitude,
            'longitude': self.longitude,
            'timezone': self.timezone,
            'isp': self.isp,
            'org': self.org,
            'asn': self.asn,
            'asn_org': self.asn_org,
            'is_anonymous_proxy': self.is_anonymous_proxy,
            'is_satellite_provider': self.is_satellite_provider,
            'accuracy_radius': self.accuracy_radius,
            'source': self.source,
            'error': self.error
        }


class MaxMindGeolocationService:
    """MaxMind GeoIP database geolocation service."""
    
    def __init__(self, city_db_path: Optional[str] = None, 
                 isp_db_path: Optional[str] = None):
        """
        Initialize MaxMind geolocation service.
        
        Args:
            city_db_path: Path to MaxMind GeoLite2-City.mmdb database
            isp_db_path: Path to MaxMind GeoLite2-ISP.mmdb database
        """
        self.city_db_path = city_db_path
        self.isp_db_path = isp_db_path
        self.city_reader = None
        self.isp_reader = None
        
        # Try to initialize databases
        self._init_databases()
    
    def _init_databases(self):
        """Initialize MaxMind database readers."""
        if self.city_db_path and Path(self.city_db_path).exists():
            try:
                self.city_reader = geoip2.database.Reader(self.city_db_path)
                logger.info(f"Initialized MaxMind City database: {self.city_db_path}")
            except Exception as e:
                logger.warning(f"Failed to initialize City database: {e}")
        
        if self.isp_db_path and Path(self.isp_db_path).exists():
            try:
                self.isp_reader = geoip2.database.Reader(self.isp_db_path)
                logger.info(f"Initialized MaxMind ISP database: {self.isp_db_path}")
            except Exception as e:
                logger.warning(f"Failed to initialize ISP database: {e}")
    
    def lookup(self, ip: str) -> GeolocationResult:
        """
        Perform geolocation lookup using MaxMind databases.
        
        Args:
            ip: IP address to lookup
            
        Returns:
            GeolocationResult object
        """
        result = GeolocationResult(ip)
        result.source = "maxmind"
        
        try:
            # Validate IP address
            ip_obj = ip_address(ip)
            
            # Skip private/local addresses
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast:
                result.error = "Private/local IP address"
                return result
            
            # City/Location lookup
            if self.city_reader:
                try:
                    city_response = self.city_reader.city(ip)
                    
                    result.country = city_response.country.name
                    result.country_code = city_response.country.iso_code
                    result.region = city_response.subdivisions.most_specific.name
                    result.region_code = city_response.subdivisions.most_specific.iso_code
                    result.city = city_response.city.name
                    result.postal_code = city_response.postal.code
                    result.latitude = float(city_response.location.latitude) if city_response.location.latitude else None
                    result.longitude = float(city_response.location.longitude) if city_response.location.longitude else None
                    result.timezone = city_response.location.time_zone
                    result.accuracy_radius = city_response.location.accuracy_radius
                    
                    # Traits
                    result.is_anonymous_proxy = city_response.traits.is_anonymous_proxy
                    result.is_satellite_provider = city_response.traits.is_satellite_provider
                    
                except geoip2.errors.AddressNotFoundError:
                    logger.debug(f"Address not found in City database: {ip}")
                except Exception as e:
                    logger.warning(f"City lookup error for {ip}: {e}")
            
            # ISP/ASN lookup
            if self.isp_reader:
                try:
                    isp_response = self.isp_reader.isp(ip)
                    
                    result.isp = isp_response.isp
                    result.org = isp_response.organization
                    result.asn = isp_response.autonomous_system_number
                    result.asn_org = isp_response.autonomous_system_organization
                    
                except geoip2.errors.AddressNotFoundError:
                    logger.debug(f"Address not found in ISP database: {ip}")
                except Exception as e:
                    logger.warning(f"ISP lookup error for {ip}: {e}")
            
            # Mark as successful if we got any data
            if any([result.country, result.city, result.isp, result.asn]):
                result.success = True
            else:
                result.error = "No geolocation data found"
                
        except AddressValueError:
            result.error = "Invalid IP address format"
        except Exception as e:
            result.error = f"Lookup error: {e}"
            logger.error(f"MaxMind geolocation error for {ip}: {e}")
        
        return result
    
    def close(self):
        """Close database readers."""
        if self.city_reader:
            self.city_reader.close()
        if self.isp_reader:
            self.isp_reader.close()


class IPAPIGeolocationService:
    """IP-API.com geolocation service (free tier)."""
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize IP-API geolocation service.
        
        Args:
            api_key: Optional API key for premium features
        """
        self.api_key = api_key
        self.base_url = "http://ip-api.com/json"
        self.requests_per_minute = 45  # Free tier limit
        self.last_request_time = datetime.min
        
    def lookup(self, ip: str) -> GeolocationResult:
        """
        Perform geolocation lookup using IP-API.com.
        
        Args:
            ip: IP address to lookup
            
        Returns:
            GeolocationResult object
        """
        result = GeolocationResult(ip)
        result.source = "ip-api"
        
        try:
            # Validate IP address
            ip_obj = ip_address(ip)
            
            # Skip private/local addresses
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast:
                result.error = "Private/local IP address"
                return result
            
            # Rate limiting
            self._enforce_rate_limit()
            
            # Make API request
            params = {
                'fields': 'status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query'
            }
            
            response = requests.get(f"{self.base_url}/{ip}", params=params, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            
            if data.get('status') == 'success':
                result.country = data.get('country')
                result.country_code = data.get('countryCode')
                result.region = data.get('regionName')
                result.region_code = data.get('region')
                result.city = data.get('city')
                result.postal_code = data.get('zip')
                result.latitude = data.get('lat')
                result.longitude = data.get('lon')
                result.timezone = data.get('timezone')
                result.isp = data.get('isp')
                result.org = data.get('org')
                
                # Parse ASN from 'as' field (format: "AS15169 Google LLC")
                as_field = data.get('as', '')
                if as_field:
                    try:
                        if as_field.startswith('AS'):
                            parts = as_field[2:].split(' ', 1)
                            result.asn = int(parts[0])
                            result.asn_org = parts[1] if len(parts) > 1 else None
                    except (ValueError, IndexError):
                        pass
                
                result.success = True
            else:
                result.error = data.get('message', 'Lookup failed')
                
        except AddressValueError:
            result.error = "Invalid IP address format"
        except requests.RequestException as e:
            result.error = f"API request failed: {e}"
            logger.error(f"IP-API request error for {ip}: {e}")
        except Exception as e:
            result.error = f"Lookup error: {e}"
            logger.error(f"IP-API geolocation error for {ip}: {e}")
        
        return result
    
    def _enforce_rate_limit(self):
        """Enforce rate limiting for free tier."""
        now = datetime.now()
        time_since_last = (now - self.last_request_time).total_seconds()
        
        # Ensure at least 1.5 seconds between requests (40 per minute)
        if time_since_last < 1.5:
            import time
            time.sleep(1.5 - time_since_last)
        
        self.last_request_time = datetime.now()


class GeolocationService:
    """Main geolocation service that combines multiple providers."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize geolocation service with multiple providers.
        
        Args:
            config: Configuration dictionary for providers
        """
        self.config = config or {}
        self.providers = []
        
        # Initialize MaxMind service
        maxmind_config = self.config.get('maxmind', {})
        if maxmind_config.get('enabled', True):
            city_db = maxmind_config.get('city_db_path', 'data/geoip/GeoLite2-City.mmdb')
            isp_db = maxmind_config.get('isp_db_path', 'data/geoip/GeoLite2-ISP.mmdb')
            
            maxmind_service = MaxMindGeolocationService(city_db, isp_db)
            if maxmind_service.city_reader or maxmind_service.isp_reader:
                self.providers.append(maxmind_service)
                logger.info("MaxMind geolocation service initialized")
        
        # Initialize IP-API service as fallback
        ipapi_config = self.config.get('ipapi', {})
        if ipapi_config.get('enabled', True):
            api_key = ipapi_config.get('api_key')
            ipapi_service = IPAPIGeolocationService(api_key)
            self.providers.append(ipapi_service)
            logger.info("IP-API geolocation service initialized")
        
        logger.info(f"Initialized {len(self.providers)} geolocation providers")
    
    def lookup(self, ip: str) -> GeolocationResult:
        """
        Perform geolocation lookup using available providers.
        
        Args:
            ip: IP address to lookup
            
        Returns:
            GeolocationResult object
        """
        last_error = None
        
        for provider in self.providers:
            try:
                result = provider.lookup(ip)
                
                if result.success:
                    logger.debug(f"Geolocation successful for {ip} using {result.source}")
                    return result
                else:
                    last_error = result.error
                    
            except Exception as e:
                last_error = str(e)
                logger.warning(f"Geolocation provider failed for {ip}: {e}")
        
        # Return failure result
        result = GeolocationResult(ip)
        result.error = last_error or "All geolocation providers failed"
        return result
    
    def lookup_batch(self, ips: List[str]) -> Dict[str, GeolocationResult]:
        """
        Perform batch geolocation lookups.
        
        Args:
            ips: List of IP addresses to lookup
            
        Returns:
            Dictionary mapping IP addresses to GeolocationResult objects
        """
        results = {}
        
        for ip in ips:
            try:
                results[ip] = self.lookup(ip)
            except Exception as e:
                result = GeolocationResult(ip)
                result.error = str(e)
                results[ip] = result
                logger.error(f"Batch geolocation error for {ip}: {e}")
        
        return results
    
    def close(self):
        """Close all provider connections."""
        for provider in self.providers:
            if hasattr(provider, 'close'):
                provider.close()