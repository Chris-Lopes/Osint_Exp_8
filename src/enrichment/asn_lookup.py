"""
ASN (Autonomous System Number) lookup and enrichment service.

This module provides ASN lookup functionality to enrich IP indicators
with network ownership and routing information.
"""

import json
import logging
import requests
from datetime import datetime
from typing import Dict, List, Optional, Any
from ipaddress import ip_address, ip_network, AddressValueError
import socket

logger = logging.getLogger(__name__)


class ASNResult:
    """Result object for ASN lookup operations."""
    
    def __init__(self, ip: str):
        self.ip = ip
        self.success = False
        self.asn = None
        self.asn_name = None
        self.asn_org = None
        self.asn_country = None
        self.network = None
        self.network_name = None
        self.allocated_date = None
        self.registry = None  # ARIN, RIPE, APNIC, etc.
        self.source = None
        self.response_time = None
        self.error = None
        self.timestamp = datetime.utcnow()
        
        # Additional network information
        self.bgp_prefix = None
        self.route_description = None
        self.abuse_contacts = []
        self.technical_contacts = []
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            'ip': self.ip,
            'success': self.success,
            'asn': self.asn,
            'asn_name': self.asn_name,
            'asn_org': self.asn_org,
            'asn_country': self.asn_country,
            'network': self.network,
            'network_name': self.network_name,
            'allocated_date': self.allocated_date,
            'registry': self.registry,
            'bgp_prefix': self.bgp_prefix,
            'route_description': self.route_description,
            'abuse_contacts': self.abuse_contacts,
            'technical_contacts': self.technical_contacts,
            'source': self.source,
            'response_time': self.response_time,
            'error': self.error,
            'timestamp': self.timestamp.isoformat()
        }


class IPAPIASNService:
    """ASN lookup using IP-API.com service."""
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize IP-API ASN service.
        
        Args:
            api_key: Optional API key for premium features
        """
        self.api_key = api_key
        self.base_url = "http://ip-api.com/json"
        
    def lookup(self, ip: str) -> ASNResult:
        """
        Perform ASN lookup using IP-API.com.
        
        Args:
            ip: IP address to lookup
            
        Returns:
            ASNResult object
        """
        result = ASNResult(ip)
        result.source = "ip-api"
        
        try:
            # Validate IP address
            ip_obj = ip_address(ip)
            
            # Skip private/local addresses
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast:
                result.error = "Private/local IP address"
                return result
            
            # Make API request
            import time
            start_time = time.time()
            
            params = {
                'fields': 'status,message,as,asname,org,country,query'
            }
            
            response = requests.get(f"{self.base_url}/{ip}", params=params, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            result.response_time = time.time() - start_time
            
            if data.get('status') == 'success':
                # Parse ASN from 'as' field (format: "AS15169 Google LLC")
                as_field = data.get('as', '')
                if as_field:
                    try:
                        if as_field.startswith('AS'):
                            asn_str = as_field[2:].split(' ')[0]
                            result.asn = int(asn_str)
                            
                            # Extract organization name from AS field
                            space_index = as_field.find(' ')
                            if space_index > 0:
                                result.asn_org = as_field[space_index + 1:]
                    except (ValueError, IndexError):
                        logger.warning(f"Could not parse ASN from: {as_field}")
                
                result.asn_name = data.get('asname')
                result.asn_country = data.get('country')
                
                # Use org field as fallback for ASN org
                if not result.asn_org:
                    result.asn_org = data.get('org')
                
                result.success = True
            else:
                result.error = data.get('message', 'Lookup failed')
                
        except AddressValueError:
            result.error = "Invalid IP address format"
        except requests.RequestException as e:
            result.error = f"API request failed: {e}"
            logger.error(f"IP-API ASN request error for {ip}: {e}")
        except Exception as e:
            result.error = f"Lookup error: {e}"
            logger.error(f"IP-API ASN error for {ip}: {e}")
        
        return result


class IPInfoASNService:
    """ASN lookup using IPInfo.io service."""
    
    def __init__(self, api_token: Optional[str] = None):
        """
        Initialize IPInfo ASN service.
        
        Args:
            api_token: Optional API token for higher limits
        """
        self.api_token = api_token
        self.base_url = "https://ipinfo.io"
        
    def lookup(self, ip: str) -> ASNResult:
        """
        Perform ASN lookup using IPInfo.io.
        
        Args:
            ip: IP address to lookup
            
        Returns:
            ASNResult object
        """
        result = ASNResult(ip)
        result.source = "ipinfo"
        
        try:
            # Validate IP address
            ip_obj = ip_address(ip)
            
            # Skip private/local addresses
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast:
                result.error = "Private/local IP address"
                return result
            
            # Prepare request
            import time
            start_time = time.time()
            
            headers = {}
            if self.api_token:
                headers['Authorization'] = f'Bearer {self.api_token}'
            
            # Make API request
            response = requests.get(
                f"{self.base_url}/{ip}/json", 
                headers=headers, 
                timeout=10
            )
            response.raise_for_status()
            
            data = response.json()
            result.response_time = time.time() - start_time
            
            # Extract ASN information
            org_field = data.get('org', '')
            if org_field:
                # Format: "AS15169 Google LLC"
                try:
                    if org_field.startswith('AS'):
                        parts = org_field[2:].split(' ', 1)
                        result.asn = int(parts[0])
                        result.asn_org = parts[1] if len(parts) > 1 else None
                except (ValueError, IndexError):
                    result.asn_org = org_field
            
            # Other fields
            result.asn_country = data.get('country')
            result.network = data.get('ip')  # Sometimes returns CIDR
            
            if result.asn or result.asn_org:
                result.success = True
            else:
                result.error = "No ASN data found"
                
        except AddressValueError:
            result.error = "Invalid IP address format"
        except requests.RequestException as e:
            result.error = f"API request failed: {e}"
            logger.error(f"IPInfo ASN request error for {ip}: {e}")
        except Exception as e:
            result.error = f"Lookup error: {e}"
            logger.error(f"IPInfo ASN error for {ip}: {e}")
        
        return result


class HackerTargetASNService:
    """ASN lookup using HackerTarget.com service (free)."""
    
    def __init__(self):
        """Initialize HackerTarget ASN service."""
        self.base_url = "https://api.hackertarget.com"
        
    def lookup(self, ip: str) -> ASNResult:
        """
        Perform ASN lookup using HackerTarget.com.
        
        Args:
            ip: IP address to lookup
            
        Returns:
            ASNResult object
        """
        result = ASNResult(ip)
        result.source = "hackertarget"
        
        try:
            # Validate IP address
            ip_obj = ip_address(ip)
            
            # Skip private/local addresses
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast:
                result.error = "Private/local IP address"
                return result
            
            # Make API request
            import time
            start_time = time.time()
            
            response = requests.get(
                f"{self.base_url}/aslookup/?q={ip}", 
                timeout=10
            )
            response.raise_for_status()
            
            result.response_time = time.time() - start_time
            
            # Parse response text (format: "AS15169,8.8.8.8/32,GOOGLE,US")
            text = response.text.strip()
            
            if text and not text.startswith('error'):
                parts = text.split(',')
                if len(parts) >= 3:
                    # Parse ASN (format: "AS15169")
                    asn_str = parts[0].strip()
                    if asn_str.startswith('AS'):
                        try:
                            result.asn = int(asn_str[2:])
                        except ValueError:
                            pass
                    
                    # Parse network (format: "8.8.8.8/32")
                    if len(parts) > 1:
                        result.network = parts[1].strip()
                    
                    # Parse organization name
                    if len(parts) > 2:
                        result.asn_org = parts[2].strip()
                        result.asn_name = result.asn_org
                    
                    # Parse country
                    if len(parts) > 3:
                        result.asn_country = parts[3].strip()
                    
                    result.success = True
                else:
                    result.error = f"Unexpected response format: {text}"
            else:
                result.error = text if text else "No data returned"
                
        except AddressValueError:
            result.error = "Invalid IP address format"
        except requests.RequestException as e:
            result.error = f"API request failed: {e}"
            logger.error(f"HackerTarget ASN request error for {ip}: {e}")
        except Exception as e:
            result.error = f"Lookup error: {e}"
            logger.error(f"HackerTarget ASN error for {ip}: {e}")
        
        return result


class ASNLookupService:
    """Main ASN lookup service combining multiple providers."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize ASN lookup service with multiple providers.
        
        Args:
            config: Configuration dictionary for providers
        """
        self.config = config or {}
        self.providers = []
        
        # Initialize HackerTarget service (free, no API key needed)
        hackertarget_config = self.config.get('hackertarget', {})
        if hackertarget_config.get('enabled', True):
            self.providers.append(HackerTargetASNService())
            logger.info("HackerTarget ASN service initialized")
        
        # Initialize IP-API service
        ipapi_config = self.config.get('ipapi', {})
        if ipapi_config.get('enabled', True):
            api_key = ipapi_config.get('api_key')
            self.providers.append(IPAPIASNService(api_key))
            logger.info("IP-API ASN service initialized")
        
        # Initialize IPInfo service
        ipinfo_config = self.config.get('ipinfo', {})
        if ipinfo_config.get('enabled', False):  # Disabled by default
            api_token = ipinfo_config.get('api_token')
            if api_token:
                self.providers.append(IPInfoASNService(api_token))
                logger.info("IPInfo ASN service initialized")
        
        logger.info(f"Initialized {len(self.providers)} ASN lookup providers")
    
    def lookup(self, ip: str) -> ASNResult:
        """
        Perform ASN lookup using available providers.
        
        Args:
            ip: IP address to lookup
            
        Returns:
            ASNResult object
        """
        last_error = None
        
        for provider in self.providers:
            try:
                result = provider.lookup(ip)
                
                if result.success:
                    logger.debug(f"ASN lookup successful for {ip} using {result.source}")
                    return result
                else:
                    last_error = result.error
                    
            except Exception as e:
                last_error = str(e)
                logger.warning(f"ASN provider failed for {ip}: {e}")
        
        # Return failure result
        result = ASNResult(ip)
        result.error = last_error or "All ASN lookup providers failed"
        return result
    
    def lookup_batch(self, ips: List[str]) -> Dict[str, ASNResult]:
        """
        Perform batch ASN lookups.
        
        Args:
            ips: List of IP addresses to lookup
            
        Returns:
            Dictionary mapping IP addresses to ASNResult objects
        """
        results = {}
        
        for ip in ips:
            try:
                results[ip] = self.lookup(ip)
                
                # Add small delay to avoid rate limiting
                import time
                time.sleep(0.1)
                
            except Exception as e:
                result = ASNResult(ip)
                result.error = str(e)
                results[ip] = result
                logger.error(f"Batch ASN lookup error for {ip}: {e}")
        
        return results
    
    def enrich_network_context(self, ip: str) -> Dict[str, Any]:
        """
        Enrich IP with comprehensive ASN and network context.
        
        Args:
            ip: IP address to enrich
            
        Returns:
            Dictionary with network context information
        """
        context = {
            'ip': ip,
            'asn_lookup_success': False,
            'asn_data': None
        }
        
        try:
            asn_result = self.lookup(ip)
            
            context['asn_lookup_success'] = asn_result.success
            context['asn_data'] = asn_result.to_dict()
            
            if asn_result.success:
                # Add derived information
                context['has_asn'] = asn_result.asn is not None
                context['network_owner'] = asn_result.asn_org
                context['network_country'] = asn_result.asn_country
                context['asn_number'] = asn_result.asn
                
                # Categorize by common providers
                if asn_result.asn_org:
                    org_lower = asn_result.asn_org.lower()
                    
                    if any(cloud in org_lower for cloud in ['amazon', 'aws', 'microsoft', 'azure', 'google', 'gcp']):
                        context['network_category'] = 'cloud_provider'
                    elif any(cdn in org_lower for cdn in ['cloudflare', 'akamai', 'fastly', 'maxcdn']):
                        context['network_category'] = 'cdn'
                    elif any(hosting in org_lower for hosting in ['hosting', 'datacenter', 'server']):
                        context['network_category'] = 'hosting'
                    elif any(isp in org_lower for isp in ['telecom', 'internet', 'broadband', 'isp']):
                        context['network_category'] = 'isp'
                    else:
                        context['network_category'] = 'other'
                
        except Exception as e:
            context['asn_error'] = str(e)
            logger.error(f"ASN enrichment error for {ip}: {e}")
        
        return context