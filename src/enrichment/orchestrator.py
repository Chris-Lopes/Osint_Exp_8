"""
Enrichment orchestrator for coordinating threat intelligence enrichment services.

This module provides the main orchestration functionality that coordinates
geolocation, DNS, ASN, and reputation services to enrich normalized indicators.
"""

import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Iterator, Tuple
import time

from .geolocation import GeolocationService
from .dns_service import DNSEnrichmentService
from .asn_lookup import ASNLookupService
from .reputation_scoring import ReputationScoringEngine
try:
    from ..normalizers.schema import NormalizedIndicator, IndicatorType
except ImportError:
    from normalizers.schema import NormalizedIndicator, IndicatorType

logger = logging.getLogger(__name__)


class EnrichmentResult:
    """Result object for indicator enrichment."""
    
    def __init__(self, indicator: NormalizedIndicator):
        self.indicator = indicator
        self.original_indicator = indicator.dict()
        self.success = False
        
        # Enrichment data
        self.geolocation_data = None
        self.dns_data = None
        self.asn_data = None
        self.reputation_data = None
        
        # Processing metadata
        self.enrichment_sources = []
        self.enrichment_errors = []
        self.processing_time = 0.0
        self.timestamp = datetime.utcnow()
        
        # Enhanced indicator
        self.enriched_indicator = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        result = {
            'indicator_value': self.indicator.value,
            'indicator_type': self.indicator.indicator_type.value,
            'success': self.success,
            'enrichment_data': {
                'geolocation': self.geolocation_data,
                'dns': self.dns_data,
                'asn': self.asn_data,
                'reputation': self.reputation_data
            },
            'enrichment_sources': self.enrichment_sources,
            'enrichment_errors': self.enrichment_errors,
            'processing_time': self.processing_time,
            'timestamp': self.timestamp.isoformat()
        }
        
        if self.enriched_indicator:
            result['enriched_indicator'] = self.enriched_indicator
        
        return result


class EnrichmentOrchestrator:
    """Main orchestrator for threat intelligence enrichment."""
    
    def __init__(self, config_dir: str = "config"):
        """
        Initialize enrichment orchestrator.
        
        Args:
            config_dir: Configuration directory path
        """
        self.config_dir = Path(config_dir)
        self.config = self._load_config()
        
        # Initialize enrichment services
        self.geolocation_service = None
        self.dns_service = None
        self.asn_service = None
        self.reputation_engine = None
        
        self._init_services()
        
        logger.info("Enrichment orchestrator initialized")
    
    def _load_config(self) -> Dict[str, Any]:
        """Load enrichment configuration."""
        config_file = self.config_dir / "enrichment_config.yaml"
        
        # Default configuration
        default_config = {
            'services': {
                'geolocation': {
                    'enabled': True,
                    'providers': {
                        'maxmind': {
                            'enabled': True,
                            'city_db_path': 'data/geoip/GeoLite2-City.mmdb',
                            'isp_db_path': 'data/geoip/GeoLite2-ISP.mmdb'
                        },
                        'ipapi': {
                            'enabled': True,
                            'api_key': None
                        }
                    }
                },
                'dns': {
                    'enabled': True,
                    'resolver': {
                        'nameservers': None,
                        'timeout': 5.0
                    }
                },
                'asn': {
                    'enabled': True,
                    'providers': {
                        'hackertarget': {'enabled': True},
                        'ipapi': {'enabled': True, 'api_key': None},
                        'ipinfo': {'enabled': False, 'api_token': None}
                    }
                },
                'reputation': {
                    'enabled': True
                }
            },
            'processing': {
                'max_concurrent_enrichments': 4,
                'timeout_per_indicator': 30,
                'retry_failed_enrichments': True,
                'cache_results': True
            }
        }
        
        # Try to load custom config
        if config_file.exists():
            try:
                import yaml
                with open(config_file, 'r') as f:
                    custom_config = yaml.safe_load(f)
                
                # Merge configurations
                default_config.update(custom_config)
                logger.info(f"Loaded enrichment configuration from {config_file}")
                
            except Exception as e:
                logger.warning(f"Failed to load config from {config_file}: {e}")
        
        return default_config
    
    def _init_services(self):
        """Initialize enrichment services based on configuration."""
        services_config = self.config.get('services', {})
        
        # Initialize geolocation service
        geo_config = services_config.get('geolocation', {})
        if geo_config.get('enabled', True):
            try:
                self.geolocation_service = GeolocationService(geo_config.get('providers', {}))
                logger.info("Geolocation service initialized")
            except Exception as e:
                logger.error(f"Failed to initialize geolocation service: {e}")
        
        # Initialize DNS service
        dns_config = services_config.get('dns', {})
        if dns_config.get('enabled', True):
            try:
                self.dns_service = DNSEnrichmentService(dns_config)
                logger.info("DNS enrichment service initialized")
            except Exception as e:
                logger.error(f"Failed to initialize DNS service: {e}")
        
        # Initialize ASN service
        asn_config = services_config.get('asn', {})
        if asn_config.get('enabled', True):
            try:
                self.asn_service = ASNLookupService(asn_config.get('providers', {}))
                logger.info("ASN lookup service initialized")
            except Exception as e:
                logger.error(f"Failed to initialize ASN service: {e}")
        
        # Initialize reputation engine
        rep_config = services_config.get('reputation', {})
        if rep_config.get('enabled', True):
            try:
                self.reputation_engine = ReputationScoringEngine(rep_config)
                logger.info("Reputation scoring engine initialized")
            except Exception as e:
                logger.error(f"Failed to initialize reputation engine: {e}")
    
    def enrich_indicator(self, indicator: NormalizedIndicator) -> EnrichmentResult:
        """
        Enrich a single normalized indicator.
        
        Args:
            indicator: NormalizedIndicator to enrich
            
        Returns:
            EnrichmentResult object
        """
        result = EnrichmentResult(indicator)
        start_time = time.time()
        
        try:
            enrichment_data = {}
            
            # Determine which enrichments to apply based on indicator type
            enrichments_to_apply = self._get_applicable_enrichments(indicator)
            
            # Apply geolocation enrichment
            if 'geolocation' in enrichments_to_apply and self.geolocation_service:
                try:
                    geo_result = self.geolocation_service.lookup(indicator.value)
                    result.geolocation_data = geo_result.to_dict()
                    enrichment_data['geolocation'] = result.geolocation_data
                    result.enrichment_sources.append('geolocation')
                    
                    if not geo_result.success:
                        result.enrichment_errors.append(f"Geolocation: {geo_result.error}")
                        
                except Exception as e:
                    error_msg = f"Geolocation enrichment error: {e}"
                    result.enrichment_errors.append(error_msg)
                    logger.error(f"Geolocation error for {indicator.value}: {e}")
            
            # Apply DNS enrichment
            if 'dns' in enrichments_to_apply and self.dns_service:
                try:
                    if indicator.indicator_type in [IndicatorType.IPV4, IndicatorType.IPV6, IndicatorType.IP]:
                        dns_result = self.dns_service.enrich_ip(indicator.value)
                    else:
                        dns_result = self.dns_service.enrich_domain(indicator.value)
                    
                    result.dns_data = dns_result
                    enrichment_data['dns'] = result.dns_data
                    result.enrichment_sources.append('dns')
                    
                except Exception as e:
                    error_msg = f"DNS enrichment error: {e}"
                    result.enrichment_errors.append(error_msg)
                    logger.error(f"DNS error for {indicator.value}: {e}")
            
            # Apply ASN enrichment
            if 'asn' in enrichments_to_apply and self.asn_service:
                try:
                    asn_result = self.asn_service.enrich_network_context(indicator.value)
                    result.asn_data = asn_result
                    enrichment_data['asn'] = result.asn_data
                    result.enrichment_sources.append('asn')
                    
                except Exception as e:
                    error_msg = f"ASN enrichment error: {e}"
                    result.enrichment_errors.append(error_msg)
                    logger.error(f"ASN error for {indicator.value}: {e}")
            
            # Apply reputation scoring
            if 'reputation' in enrichments_to_apply and self.reputation_engine:
                try:
                    rep_result = self.reputation_engine.score_indicator(
                        indicator.value,
                        indicator.indicator_type.value,
                        enrichment_data
                    )
                    result.reputation_data = rep_result.to_dict()
                    result.enrichment_sources.append('reputation')
                    
                    if not rep_result.success:
                        result.enrichment_errors.append(f"Reputation: {rep_result.error}")
                        
                except Exception as e:
                    error_msg = f"Reputation scoring error: {e}"
                    result.enrichment_errors.append(error_msg)
                    logger.error(f"Reputation error for {indicator.value}: {e}")
            
            # Create enriched indicator
            result.enriched_indicator = self._create_enriched_indicator(
                indicator, enrichment_data
            )
            
            # Mark as successful if we got any enrichment data
            result.success = bool(result.enrichment_sources)
            
        except Exception as e:
            error_msg = f"Enrichment orchestration error: {e}"
            result.enrichment_errors.append(error_msg)
            logger.error(f"Enrichment error for {indicator.value}: {e}")
        
        result.processing_time = time.time() - start_time
        return result
    
    def _get_applicable_enrichments(self, indicator: NormalizedIndicator) -> List[str]:
        """Determine which enrichments are applicable for an indicator type."""
        enrichments = []
        
        # IP addresses can be enriched with geolocation, DNS, ASN, and reputation
        if indicator.indicator_type in [IndicatorType.IPV4, IndicatorType.IPV6, IndicatorType.IP]:
            enrichments.extend(['geolocation', 'dns', 'asn', 'reputation'])
        
        # Domains can be enriched with DNS and reputation
        elif indicator.indicator_type == IndicatorType.DOMAIN:
            enrichments.extend(['dns', 'reputation'])
        
        # URLs can be enriched with DNS (of domain part) and reputation
        elif indicator.indicator_type == IndicatorType.URL:
            enrichments.extend(['dns', 'reputation'])
        
        # File hashes get reputation scoring
        elif indicator.indicator_type in [IndicatorType.MD5, IndicatorType.SHA1, IndicatorType.SHA256]:
            enrichments.extend(['reputation'])
        
        # Email addresses get DNS (domain part) and reputation
        elif indicator.indicator_type == IndicatorType.EMAIL:
            enrichments.extend(['dns', 'reputation'])
        
        return enrichments
    
    def _create_enriched_indicator(self, original: NormalizedIndicator, 
                                 enrichment_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create enriched indicator by merging original with enrichment data."""
        enriched = original.dict()
        
        # Add enrichment data to context
        if 'enrichment' not in enriched['context']:
            enriched['context']['enrichment'] = {}
        
        enriched['context']['enrichment'].update(enrichment_data)
        
        # Update network context with geolocation and ASN data
        if enrichment_data.get('geolocation'):
            geo_data = enrichment_data['geolocation']
            if geo_data.get('success'):
                if not enriched.get('network_context'):
                    enriched['network_context'] = {}
                
                enriched['network_context'].update({
                    'country': geo_data.get('country'),
                    'city': geo_data.get('city'),
                    'latitude': geo_data.get('latitude'),
                    'longitude': geo_data.get('longitude'),
                    'isp': geo_data.get('isp'),
                    'organization': geo_data.get('org')
                })
        
        if enrichment_data.get('asn'):
            asn_data = enrichment_data['asn']
            if asn_data.get('asn_lookup_success'):
                if not enriched.get('network_context'):
                    enriched['network_context'] = {}
                
                enriched['network_context'].update({
                    'asn': asn_data.get('asn_number'),
                    'asn_org': asn_data.get('network_owner'),
                    'network_category': asn_data.get('network_category')
                })
        
        # Update confidence based on reputation score
        if enrichment_data.get('reputation'):
            rep_data = enrichment_data['reputation']
            if rep_data.get('success'):
                # Adjust confidence based on reputation
                rep_score = rep_data.get('reputation_score', 0)
                if rep_score < -50:  # High negative reputation
                    enriched['confidence'] = min(enriched['confidence'] + 20, 100)
                elif rep_score < -20:  # Medium negative reputation  
                    enriched['confidence'] = min(enriched['confidence'] + 10, 100)
        
        # Update modified timestamp
        enriched['modified'] = datetime.utcnow().isoformat()
        
        return enriched
    
    def enrich_batch(self, indicators: List[NormalizedIndicator], 
                    max_concurrent: Optional[int] = None) -> List[EnrichmentResult]:
        """
        Enrich multiple indicators concurrently.
        
        Args:
            indicators: List of NormalizedIndicator objects to enrich
            max_concurrent: Maximum number of concurrent enrichments
            
        Returns:
            List of EnrichmentResult objects
        """
        if not indicators:
            return []
        
        max_workers = max_concurrent or self.config.get('processing', {}).get('max_concurrent_enrichments', 4)
        results = []
        
        logger.info(f"Starting batch enrichment of {len(indicators)} indicators with {max_workers} workers")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all enrichment tasks
            future_to_indicator = {
                executor.submit(self.enrich_indicator, indicator): indicator
                for indicator in indicators
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_indicator):
                try:
                    result = future.result(timeout=self.config.get('processing', {}).get('timeout_per_indicator', 30))
                    results.append(result)
                    
                except Exception as e:
                    indicator = future_to_indicator[future]
                    error_result = EnrichmentResult(indicator)
                    error_result.enrichment_errors.append(f"Enrichment failed: {e}")
                    results.append(error_result)
                    logger.error(f"Batch enrichment error for {indicator.value}: {e}")
        
        logger.info(f"Batch enrichment completed: {len(results)} results")
        return results
    
    def enrich_from_file(self, input_file: Path, output_file: Path) -> Dict[str, Any]:
        """
        Enrich indicators from a normalized data file.
        
        Args:
            input_file: Path to input JSONL file with normalized indicators
            output_file: Path to output JSONL file for enriched indicators
            
        Returns:
            Processing statistics
        """
        start_time = time.time()
        
        stats = {
            'input_file': str(input_file),
            'output_file': str(output_file),
            'start_time': start_time,
            'total_indicators': 0,
            'enriched_successfully': 0,
            'enrichment_errors': 0,
            'processing_time': 0,
            'enrichment_sources_used': set()
        }
        
        try:
            # Load indicators from input file
            indicators = []
            
            with open(input_file, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        indicator_data = json.loads(line)
                        indicator = NormalizedIndicator(**indicator_data)
                        indicators.append(indicator)
                        stats['total_indicators'] += 1
                        
                    except Exception as e:
                        logger.warning(f"Failed to parse indicator at line {line_num}: {e}")
                        stats['enrichment_errors'] += 1
            
            logger.info(f"Loaded {len(indicators)} indicators from {input_file}")
            
            # Enrich indicators
            enrichment_results = self.enrich_batch(indicators)
            
            # Write enriched indicators to output file
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                for result in enrichment_results:
                    if result.success and result.enriched_indicator:
                        f.write(json.dumps(result.enriched_indicator, default=str) + '\n')
                        stats['enriched_successfully'] += 1
                        stats['enrichment_sources_used'].update(result.enrichment_sources)
                    else:
                        # Write original indicator if enrichment failed
                        f.write(json.dumps(result.original_indicator, default=str) + '\n')
                        stats['enrichment_errors'] += 1
            
            stats['processing_time'] = time.time() - start_time
            stats['enrichment_sources_used'] = list(stats['enrichment_sources_used'])
            
            logger.info(f"Enrichment complete: {stats['enriched_successfully']}/{stats['total_indicators']} "
                       f"indicators enriched in {stats['processing_time']:.1f}s")
            
        except Exception as e:
            logger.error(f"File enrichment error: {e}")
            stats['error'] = str(e)
        
        return stats
    
    def close(self):
        """Close all service connections."""
        if self.geolocation_service:
            self.geolocation_service.close()
        
        logger.info("Enrichment orchestrator closed")