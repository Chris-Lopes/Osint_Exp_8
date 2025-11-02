"""
DNS resolution and domain enrichment service.

This module provides DNS resolution, reverse DNS lookups, and domain
reputation checking to enrich IP and domain indicators.
"""

import dns.resolver
import dns.reversename
import logging
import socket
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Any
from ipaddress import ip_address, AddressValueError
import requests
import time

logger = logging.getLogger(__name__)


class DNSResult:
    """Result object for DNS lookup operations."""
    
    def __init__(self, query: str, query_type: str = "A"):
        self.query = query
        self.query_type = query_type
        self.success = False
        self.records = []
        self.reverse_dns = None
        self.nameservers = []
        self.mx_records = []
        self.txt_records = []
        self.cname = None
        self.ttl = None
        self.response_time = None
        self.error = None
        self.timestamp = datetime.utcnow()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            'query': self.query,
            'query_type': self.query_type,
            'success': self.success,
            'records': self.records,
            'reverse_dns': self.reverse_dns,
            'nameservers': self.nameservers,
            'mx_records': self.mx_records,
            'txt_records': self.txt_records,
            'cname': self.cname,
            'ttl': self.ttl,
            'response_time': self.response_time,
            'error': self.error,
            'timestamp': self.timestamp.isoformat()
        }


class DomainReputationResult:
    """Result object for domain reputation checks."""
    
    def __init__(self, domain: str):
        self.domain = domain
        self.success = False
        self.reputation_score = None  # 0-100, higher is better
        self.category = None
        self.is_malicious = False
        self.is_suspicious = False
        self.is_phishing = False
        self.is_malware = False
        self.blocklist_matches = []
        self.reputation_sources = []
        self.age_days = None
        self.registrar = None
        self.error = None
        self.timestamp = datetime.utcnow()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            'domain': self.domain,
            'success': self.success,
            'reputation_score': self.reputation_score,
            'category': self.category,
            'is_malicious': self.is_malicious,
            'is_suspicious': self.is_suspicious,
            'is_phishing': self.is_phishing,
            'is_malware': self.is_malware,
            'blocklist_matches': self.blocklist_matches,
            'reputation_sources': self.reputation_sources,
            'age_days': self.age_days,
            'registrar': self.registrar,
            'error': self.error,
            'timestamp': self.timestamp.isoformat()
        }


class DNSResolverService:
    """Core DNS resolution service."""
    
    def __init__(self, nameservers: Optional[List[str]] = None, timeout: float = 5.0):
        """
        Initialize DNS resolver service.
        
        Args:
            nameservers: Custom nameservers to use
            timeout: Query timeout in seconds
        """
        self.resolver = dns.resolver.Resolver()
        self.timeout = timeout
        
        if nameservers:
            self.resolver.nameservers = nameservers
        
        # Configure resolver
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout * 2
        
        logger.info(f"DNS resolver initialized with nameservers: {self.resolver.nameservers}")
    
    def resolve_domain(self, domain: str, record_type: str = "A") -> DNSResult:
        """
        Resolve domain to get DNS records.
        
        Args:
            domain: Domain name to resolve
            record_type: DNS record type (A, AAAA, MX, TXT, etc.)
            
        Returns:
            DNSResult object
        """
        result = DNSResult(domain, record_type)
        start_time = time.time()
        
        try:
            # Perform DNS query
            answers = self.resolver.resolve(domain, record_type)
            
            # Extract records
            for rdata in answers:
                if record_type == "A" or record_type == "AAAA":
                    result.records.append(str(rdata))
                elif record_type == "MX":
                    result.mx_records.append({
                        'priority': rdata.preference,
                        'host': str(rdata.exchange)
                    })
                elif record_type == "TXT":
                    result.txt_records.append(str(rdata))
                elif record_type == "CNAME":
                    result.cname = str(rdata)
                else:
                    result.records.append(str(rdata))
            
            result.ttl = answers.rrset.ttl
            result.success = True
            
        except dns.resolver.NXDOMAIN:
            result.error = "Domain does not exist"
        except dns.resolver.NoAnswer:
            result.error = f"No {record_type} records found"
        except dns.resolver.Timeout:
            result.error = "DNS query timeout"
        except Exception as e:
            result.error = f"DNS resolution error: {e}"
            logger.error(f"DNS resolution error for {domain}: {e}")
        
        result.response_time = time.time() - start_time
        return result
    
    def reverse_dns_lookup(self, ip: str) -> DNSResult:
        """
        Perform reverse DNS lookup for an IP address.
        
        Args:
            ip: IP address to lookup
            
        Returns:
            DNSResult object
        """
        result = DNSResult(ip, "PTR")
        start_time = time.time()
        
        try:
            # Validate IP address
            ip_obj = ip_address(ip)
            
            # Create reverse DNS query
            reverse_name = dns.reversename.from_address(ip)
            
            # Perform reverse lookup
            answers = self.resolver.resolve(reverse_name, "PTR")
            
            # Extract hostnames
            hostnames = [str(rdata) for rdata in answers]
            result.reverse_dns = hostnames[0] if hostnames else None
            result.records = hostnames
            result.success = True
            
        except AddressValueError:
            result.error = "Invalid IP address"
        except dns.resolver.NXDOMAIN:
            result.error = "No reverse DNS record found"
        except dns.resolver.NoAnswer:
            result.error = "No PTR records found"
        except dns.resolver.Timeout:
            result.error = "DNS query timeout"
        except Exception as e:
            result.error = f"Reverse DNS error: {e}"
            logger.error(f"Reverse DNS error for {ip}: {e}")
        
        result.response_time = time.time() - start_time
        return result
    
    def get_nameservers(self, domain: str) -> DNSResult:
        """
        Get nameservers for a domain.
        
        Args:
            domain: Domain name
            
        Returns:
            DNSResult object with nameserver information
        """
        result = DNSResult(domain, "NS")
        start_time = time.time()
        
        try:
            answers = self.resolver.resolve(domain, "NS")
            result.nameservers = [str(rdata) for rdata in answers]
            result.success = True
            
        except Exception as e:
            result.error = f"Nameserver lookup error: {e}"
            logger.error(f"Nameserver lookup error for {domain}: {e}")
        
        result.response_time = time.time() - start_time
        return result
    
    def comprehensive_lookup(self, domain: str) -> Dict[str, DNSResult]:
        """
        Perform comprehensive DNS lookup with multiple record types.
        
        Args:
            domain: Domain name to lookup
            
        Returns:
            Dictionary of record types to DNSResult objects
        """
        record_types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME"]
        results = {}
        
        for record_type in record_types:
            try:
                results[record_type] = self.resolve_domain(domain, record_type)
            except Exception as e:
                result = DNSResult(domain, record_type)
                result.error = str(e)
                results[record_type] = result
                logger.warning(f"Failed to lookup {record_type} for {domain}: {e}")
        
        return results


class DomainReputationService:
    """Domain reputation checking service."""
    
    def __init__(self):
        """Initialize domain reputation service."""
        # Common malware/phishing domain patterns
        self.suspicious_patterns = [
            'bit.ly', 'tinyurl', 'ow.ly', 'goo.gl',  # URL shorteners
            'freenom', '000webhostapp',  # Free hosting
            'duckdns', 'no-ip',  # Dynamic DNS
        ]
        
        # Known bad TLDs (higher risk)
        self.suspicious_tlds = {
            '.tk', '.ml', '.ga', '.cf',  # Free TLDs
            '.cc', '.pw', '.top', '.click'  # Often abused TLDs
        }
        
        logger.info("Domain reputation service initialized")
    
    def check_reputation(self, domain: str) -> DomainReputationResult:
        """
        Check domain reputation using various indicators.
        
        Args:
            domain: Domain name to check
            
        Returns:
            DomainReputationResult object
        """
        result = DomainReputationResult(domain)
        
        try:
            # Initialize reputation score
            reputation_score = 50  # Neutral starting point
            reputation_factors = []
            
            # Check for suspicious patterns
            domain_lower = domain.lower()
            
            # Check TLD reputation
            for suspicious_tld in self.suspicious_tlds:
                if domain_lower.endswith(suspicious_tld):
                    reputation_score -= 20
                    reputation_factors.append(f"Suspicious TLD: {suspicious_tld}")
                    result.is_suspicious = True
                    break
            
            # Check for suspicious patterns
            for pattern in self.suspicious_patterns:
                if pattern in domain_lower:
                    reputation_score -= 15
                    reputation_factors.append(f"Suspicious pattern: {pattern}")
                    result.is_suspicious = True
            
            # Check domain length (very short or very long can be suspicious)
            if len(domain) < 4:
                reputation_score -= 10
                reputation_factors.append("Very short domain name")
            elif len(domain) > 50:
                reputation_score -= 10
                reputation_factors.append("Very long domain name")
            
            # Check for excessive subdomains
            subdomain_count = domain.count('.')
            if subdomain_count > 3:
                reputation_score -= 5
                reputation_factors.append(f"Many subdomains: {subdomain_count}")
            
            # Check for numbers in domain (can indicate DGA)
            digit_count = sum(c.isdigit() for c in domain)
            if digit_count > len(domain) * 0.3:  # More than 30% digits
                reputation_score -= 15
                reputation_factors.append("High digit ratio")
                result.is_suspicious = True
            
            # Check for homograph attacks (mixed scripts)
            try:
                # Simple check for non-ASCII characters
                if not domain.isascii():
                    reputation_score -= 20
                    reputation_factors.append("Non-ASCII characters (possible homograph)")
                    result.is_suspicious = True
            except:
                pass
            
            # Normalize score
            reputation_score = max(0, min(100, reputation_score))
            
            # Set classification based on score
            if reputation_score < 30:
                result.is_malicious = True
                result.category = "malicious"
            elif reputation_score < 50:
                result.is_suspicious = True
                result.category = "suspicious"
            elif reputation_score > 80:
                result.category = "trusted"
            else:
                result.category = "neutral"
            
            result.reputation_score = reputation_score
            result.reputation_sources = reputation_factors
            result.success = True
            
        except Exception as e:
            result.error = f"Reputation check error: {e}"
            logger.error(f"Domain reputation error for {domain}: {e}")
        
        return result
    
    def check_blocklists(self, domain: str) -> List[str]:
        """
        Check domain against known blocklists.
        
        Args:
            domain: Domain to check
            
        Returns:
            List of blocklist names that contain the domain
        """
        # This is a placeholder - in production, you would check against
        # actual blocklist APIs or databases
        blocklist_matches = []
        
        # Simple pattern-based checks
        domain_lower = domain.lower()
        
        # Check against known bad patterns
        bad_patterns = [
            'phishing', 'malware', 'virus', 'trojan', 'ransomware',
            'scam', 'fraud', 'spam', 'botnet', 'c2', 'c&c'
        ]
        
        for pattern in bad_patterns:
            if pattern in domain_lower:
                blocklist_matches.append(f"pattern:{pattern}")
        
        return blocklist_matches


class DNSEnrichmentService:
    """Main DNS enrichment service combining resolution and reputation."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize DNS enrichment service.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        
        # Initialize DNS resolver
        resolver_config = self.config.get('resolver', {})
        nameservers = resolver_config.get('nameservers')
        timeout = resolver_config.get('timeout', 5.0)
        
        self.dns_resolver = DNSResolverService(nameservers, timeout)
        
        # Initialize reputation service
        self.reputation_service = DomainReputationService()
        
        logger.info("DNS enrichment service initialized")
    
    def enrich_ip(self, ip: str) -> Dict[str, Any]:
        """
        Enrich IP address with DNS information.
        
        Args:
            ip: IP address to enrich
            
        Returns:
            Dictionary with enrichment results
        """
        enrichment_data = {
            'ip': ip,
            'reverse_dns': None,
            'hostnames': [],
            'dns_response_time': None,
            'dns_success': False
        }
        
        try:
            # Perform reverse DNS lookup
            reverse_result = self.dns_resolver.reverse_dns_lookup(ip)
            
            enrichment_data['dns_response_time'] = reverse_result.response_time
            enrichment_data['dns_success'] = reverse_result.success
            
            if reverse_result.success:
                enrichment_data['reverse_dns'] = reverse_result.reverse_dns
                enrichment_data['hostnames'] = reverse_result.records
                
                # If we got hostnames, check their reputation
                if reverse_result.records:
                    hostname_reputations = {}
                    for hostname in reverse_result.records:
                        rep_result = self.reputation_service.check_reputation(hostname)
                        hostname_reputations[hostname] = rep_result.to_dict()
                    
                    enrichment_data['hostname_reputations'] = hostname_reputations
            else:
                enrichment_data['dns_error'] = reverse_result.error
                
        except Exception as e:
            enrichment_data['dns_error'] = str(e)
            logger.error(f"DNS enrichment error for IP {ip}: {e}")
        
        return enrichment_data
    
    def enrich_domain(self, domain: str) -> Dict[str, Any]:
        """
        Enrich domain with comprehensive DNS and reputation information.
        
        Args:
            domain: Domain name to enrich
            
        Returns:
            Dictionary with enrichment results
        """
        enrichment_data = {
            'domain': domain,
            'dns_records': {},
            'reputation': None,
            'dns_success': False,
            'reputation_success': False
        }
        
        try:
            # Perform comprehensive DNS lookup
            dns_results = self.dns_resolver.comprehensive_lookup(domain)
            
            # Convert results to dict format
            enrichment_data['dns_records'] = {
                record_type: result.to_dict() 
                for record_type, result in dns_results.items()
            }
            
            # Check if any DNS queries were successful
            enrichment_data['dns_success'] = any(
                result.success for result in dns_results.values()
            )
            
            # Check domain reputation
            reputation_result = self.reputation_service.check_reputation(domain)
            enrichment_data['reputation'] = reputation_result.to_dict()
            enrichment_data['reputation_success'] = reputation_result.success
            
            # Add blocklist checks
            blocklist_matches = self.reputation_service.check_blocklists(domain)
            enrichment_data['blocklist_matches'] = blocklist_matches
            
        except Exception as e:
            enrichment_data['error'] = str(e)
            logger.error(f"DNS enrichment error for domain {domain}: {e}")
        
        return enrichment_data
    
    def enrich_batch(self, items: List[Dict[str, str]]) -> Dict[str, Dict[str, Any]]:
        """
        Perform batch DNS enrichment.
        
        Args:
            items: List of items with 'type' and 'value' keys
            
        Returns:
            Dictionary mapping item values to enrichment results
        """
        results = {}
        
        for item in items:
            item_type = item.get('type', '').lower()
            item_value = item.get('value', '')
            
            try:
                if item_type in ['ip', 'ipv4', 'ipv6', 'ipv4-addr', 'ipv6-addr']:
                    results[item_value] = self.enrich_ip(item_value)
                elif item_type in ['domain', 'domain-name']:
                    results[item_value] = self.enrich_domain(item_value)
                else:
                    # Try to auto-detect type
                    try:
                        ip_address(item_value)
                        results[item_value] = self.enrich_ip(item_value)
                    except AddressValueError:
                        # Assume it's a domain
                        results[item_value] = self.enrich_domain(item_value)
                        
            except Exception as e:
                results[item_value] = {'error': str(e)}
                logger.error(f"Batch DNS enrichment error for {item_value}: {e}")
        
        return results