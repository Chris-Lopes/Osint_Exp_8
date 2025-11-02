"""
Core normalization engine for threat intelligence indicators.

This module provides the main normalization functionality that converts
source-specific threat intelligence data into standardized STIX-like format.
"""

import json
import logging
import re
import yaml
import jinja2
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from .schema import (
    NormalizedIndicator, IndicatorType, ThreatType, SeverityLevel, TLPMarking,
    SourceMetadata, NetworkContext, FileContext, MalwareContext,
    GeographicLocation, NormalizationRule, NormalizationResult
)

logger = logging.getLogger(__name__)


class FieldMapper:
    """Handles field mapping and transformation logic."""
    
    def __init__(self):
        """Initialize field mapper with common patterns."""
        # Common field name variations
        self.field_aliases = {
            # Indicator values
            'indicator': ['value', 'ioc', 'observable', 'artifact'],
            'type': ['indicator_type', 'ioc_type', 'observable_type'],
            
            # Temporal fields
            'first_seen': ['first_observed', 'created', 'date_added', 'timestamp'],
            'last_seen': ['last_observed', 'modified', 'last_updated'],
            
            # Confidence and severity
            'confidence': ['confidence_level', 'reliability', 'score'],
            'severity': ['priority', 'risk_level', 'threat_level'],
            
            # Source information
            'source': ['provider', 'feed', 'origin'],
            'source_url': ['url', 'link', 'reference', 'permalink'],
            
            # Network context
            'asn': ['autonomous_system', 'as_number'],
            'country': ['country_name', 'geo_country'],
            'city': ['geo_city', 'location_city']
        }
    
    def find_field_value(self, data: Dict[str, Any], target_field: str) -> Any:
        """
        Find a field value using aliases and case-insensitive matching.
        
        Args:
            data: Source data dictionary
            target_field: Target field name to find
            
        Returns:
            Field value if found, None otherwise
        """
        # Direct match (case-insensitive)
        for key, value in data.items():
            if key.lower() == target_field.lower():
                return value
        
        # Alias matching
        aliases = self.field_aliases.get(target_field, [])
        for alias in aliases:
            for key, value in data.items():
                if key.lower() == alias.lower():
                    return value
        
        # Nested field search (e.g., context.country)
        if '.' in target_field:
            parts = target_field.split('.')
            current = data
            try:
                for part in parts:
                    if isinstance(current, dict):
                        current = current.get(part, current.get(part.lower()))
                    else:
                        return None
                return current
            except (KeyError, TypeError):
                pass
        
        return None
    
    def transform_value(self, value: Any, transformation: Dict[str, Any]) -> Any:
        """
        Transform a field value according to transformation rules.
        
        Args:
            value: Original value
            transformation: Transformation configuration
            
        Returns:
            Transformed value
        """
        if value is None:
            return value
        
        transform_type = transformation.get('type')
        
        if transform_type == 'lowercase':
            return str(value).lower()
        elif transform_type == 'uppercase':
            return str(value).upper()
        elif transform_type == 'strip':
            return str(value).strip()
        elif transform_type == 'regex_replace':
            pattern = transformation.get('pattern', '')
            replacement = transformation.get('replacement', '')
            return re.sub(pattern, replacement, str(value))
        elif transform_type == 'mapping':
            mapping = transformation.get('mapping', {})
            return mapping.get(str(value), value)
        elif transform_type == 'split':
            delimiter = transformation.get('delimiter', ',')
            return str(value).split(delimiter)
        elif transform_type == 'join':
            delimiter = transformation.get('delimiter', ' ')
            if isinstance(value, list):
                return delimiter.join(str(v) for v in value)
            return value
        elif transform_type == 'int':
            try:
                return int(value)
            except (ValueError, TypeError):
                return None
        elif transform_type == 'float':
            try:
                return float(value)
            except (ValueError, TypeError):
                return None
        elif transform_type == 'datetime':
            format_str = transformation.get('format', '%Y-%m-%d %H:%M:%S')
            try:
                if isinstance(value, str):
                    return datetime.strptime(value, format_str)
                elif isinstance(value, (int, float)):
                    return datetime.fromtimestamp(value)
            except (ValueError, TypeError):
                pass
        
        return value


class IndicatorNormalizer:
    """Main normalization engine for threat intelligence indicators."""
    
    def __init__(self, config_dir: str = "config"):
        """
        Initialize the normalizer.
        
        Args:
            config_dir: Directory containing normalization rules
        """
        self.config_dir = Path(config_dir)
        self.field_mapper = FieldMapper()
        self.normalization_rules = self._load_normalization_rules()
        
        # Type detection patterns
        self.type_patterns = {
            IndicatorType.IPV4: re.compile(r'^(\d{1,3}\.){3}\d{1,3}$'),
            IndicatorType.IPV6: re.compile(r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'),
            IndicatorType.DOMAIN: re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'),
            IndicatorType.URL: re.compile(r'^https?://'),
            IndicatorType.EMAIL: re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'),
            IndicatorType.MD5: re.compile(r'^[a-fA-F0-9]{32}$'),
            IndicatorType.SHA1: re.compile(r'^[a-fA-F0-9]{40}$'),
            IndicatorType.SHA256: re.compile(r'^[a-fA-F0-9]{64}$'),
        }
        
        logger.info(f"Initialized normalizer with {len(self.normalization_rules)} rules")
    
    def _load_normalization_rules(self) -> Dict[str, NormalizationRule]:
        """Load normalization rules from YAML configuration."""
        rules = {}
        
        # Load rules from YAML file
        rules_file = self.config_dir / "normalization_rules.yaml"
        if rules_file.exists():
            try:
                with open(rules_file, 'r') as f:
                    rules_data = yaml.safe_load(f)
                
                # Process each source's rules
                for source_name, source_config in rules_data.items():
                    if source_name in ['confidence_functions', 'type_mapping_functions', 'default']:
                        continue  # Skip helper sections
                    
                    if 'rules' in source_config:
                        # Convert YAML rules to NormalizationRule format
                        field_mappings = {}
                        condition_rules = []
                        
                        for rule in source_config['rules']:
                            condition = rule.get('condition', 'true')
                            mappings = rule.get('mappings', {})
                            
                            # Create field mappings
                            for field_name, mapping_expr in mappings.items():
                                if field_name not in field_mappings:
                                    field_mappings[field_name] = []
                                
                                field_mappings[field_name].append({
                                    'condition': condition,
                                    'expression': mapping_expr
                                })
                        
                        rules[source_name] = NormalizationRule(
                            source_name=source_name,
                            field_mappings=field_mappings,
                            indicator_type_mapping=source_config.get('indicator_type_mapping', {}),
                            value_transformations=source_config.get('value_transformations', {}),
                            required_fields=source_config.get('required_fields', ['value'])
                        )
                
                logger.info(f"Loaded {len(rules)} normalization rules from YAML")
            except Exception as e:
                logger.error(f"Error loading YAML normalization rules: {e}")
        
        # Add default fallback rules
        default_rules = self._create_default_rules()
        for rule in default_rules:
            if rule.source_name not in rules:
                rules[rule.source_name] = rule
        
        return rules
    
    def _evaluate_template(self, template_str: str, context: Dict[str, Any]) -> Any:
        """
        Evaluate a simple template expression against context data.
        
        Args:
            template_str: Template string (e.g., "{{ value or indicator }}")
            context: Context data for evaluation
            
        Returns:
            Evaluated result
        """
        if not isinstance(template_str, str):
            return template_str
        
        # Handle simple template expressions
        if template_str.startswith('{{') and template_str.endswith('}}'):
            expr = template_str[2:-2].strip()
            
            # Handle simple field access
            if '.' not in expr and 'or' not in expr and 'get(' not in expr:
                return context.get(expr)
            
            # Handle basic 'or' expressions  
            if ' or ' in expr:
                parts = expr.split(' or ')
                for part in parts:
                    part = part.strip()
                    if part.startswith('"') and part.endswith('"'):
                        return part[1:-1]  # Return string literal
                    value = context.get(part)
                    if value:
                        return value
                return None
            
            # Handle attribute access (e.g., attributes.get('country'))
            if '.get(' in expr:
                try:
                    # Simple evaluation for basic attribute access
                    if expr.startswith('attributes.get('):
                        attr_name = expr[expr.find("'")+1:expr.rfind("'")]
                        attributes = context.get('attributes', {})
                        return attributes.get(attr_name)
                except:
                    pass
            
            # Return the field value if it exists
            return context.get(expr.split('.')[0])
        
        return template_str
    
    def _evaluate_condition(self, condition: str, context: Dict[str, Any]) -> bool:
        """
        Evaluate a simple condition against context data.
        
        Args:
            condition: Condition string (e.g., "type == 'ip_address'")
            context: Context data for evaluation
            
        Returns:
            Boolean result
        """
        if condition == 'true':
            return True
        
        # Handle simple equality checks
        if '==' in condition:
            left, right = condition.split('==', 1)
            left = left.strip()
            right = right.strip().strip('"\'')
            
            left_value = context.get(left)
            return str(left_value) == right
        
        # Handle 'is defined' checks
        if 'is defined' in condition:
            field_name = condition.split(' is defined')[0].strip()
            return field_name in context and context[field_name] is not None
        
        # Handle 'in' checks
        if ' in ' in condition:
            left, right = condition.split(' in ', 1)
            left = left.strip()
            right = right.strip()
            
            if right.startswith('[') and right.endswith(']'):
                # Parse list 
                right_list = [item.strip().strip('"\'') for item in right[1:-1].split(',')]
                left_value = str(context.get(left, ''))
                return left_value in right_list
        
        return False
    
    def _create_default_rules(self) -> List[NormalizationRule]:
        """Create default normalization rules for common sources."""
        return [
            # Example Public (test source)
            NormalizationRule(
                source_name="example_public",
                field_mappings={
                    "value": "value",
                    "type": "indicator_type",
                    "confidence": "confidence",
                    "severity": "severity",
                    "tags": "tags"
                },
                default_values={
                    "threat_types": [ThreatType.UNKNOWN.value],
                    "tlp_marking": TLPMarking.WHITE.value
                }
            ),
            
            # VirusTotal
            NormalizationRule(
                source_name="virustotal",
                field_mappings={
                    "value": "value",
                    "type": "indicator_type", 
                    "context.detection_ratio": "detection_ratio",
                    "context.first_seen": "first_seen",
                    "context.last_seen": "last_seen",
                    "confidence": "confidence",
                    "severity": "severity"
                },
                value_transformations={
                    "first_seen": {"type": "datetime", "format": "%Y-%m-%d %H:%M:%S"},
                    "last_seen": {"type": "datetime", "format": "%Y-%m-%d %H:%M:%S"}
                },
                default_values={
                    "threat_types": [ThreatType.MALWARE.value],
                    "tlp_marking": TLPMarking.WHITE.value
                }
            ),
            
            # URLhaus
            NormalizationRule(
                source_name="urlhaus",
                field_mappings={
                    "value": "value",
                    "type": "indicator_type",
                    "context.url_status": "status",
                    "context.threat_type": "threat_type",
                    "context.date_added": "first_seen",
                    "confidence": "confidence",
                    "severity": "severity"
                },
                value_transformations={
                    "threat_type": {
                        "type": "mapping",
                        "mapping": {
                            "malware_download": ThreatType.MALWARE.value,
                            "botnet_cc": ThreatType.C2.value,
                            "phishing": ThreatType.PHISHING.value
                        }
                    }
                },
                default_values={
                    "threat_types": [ThreatType.MALWARE.value],
                    "tlp_marking": TLPMarking.WHITE.value
                }
            ),
            
            # OTX (AlienVault)
            NormalizationRule(
                source_name="otx",
                field_mappings={
                    "value": "value",
                    "type": "indicator_type",
                    "context.pulse_name": "pulse_name",
                    "context.malware_families": "malware_families",
                    "confidence": "confidence",
                    "severity": "severity"
                },
                default_values={
                    "threat_types": [ThreatType.MALWARE.value],
                    "tlp_marking": TLPMarking.WHITE.value
                }
            ),
            
            # Shodan
            NormalizationRule(
                source_name="shodan",
                field_mappings={
                    "value": "value",
                    "type": "indicator_type",
                    "context.port": "port",
                    "context.org": "organization",
                    "context.country": "country",
                    "context.city": "city",
                    "context.asn": "asn",
                    "confidence": "confidence",
                    "severity": "severity"
                },
                default_values={
                    "threat_types": [ThreatType.SUSPICIOUS.value],
                    "tlp_marking": TLPMarking.WHITE.value
                }
            )
        ]
    
    def detect_indicator_type(self, value: str) -> Optional[IndicatorType]:
        """
        Detect the type of an indicator based on its value.
        
        Args:
            value: Indicator value
            
        Returns:
            Detected indicator type or None
        """
        value = str(value).strip()
        
        for indicator_type, pattern in self.type_patterns.items():
            if pattern.match(value):
                return indicator_type
        
        return None
    
    def normalize_indicator(self, source_data: Dict[str, Any], 
                          source_name: str) -> NormalizationResult:
        """
        Normalize a single indicator from source-specific format.
        
        Args:
            source_data: Raw indicator data from source
            source_name: Name of the source
            
        Returns:
            Normalization result with normalized indicator or errors
        """
        result = NormalizationResult(
            success=False,
            source_data=source_data
        )
        
        try:
            # Get normalization rule for source
            rule = self.normalization_rules.get(source_name)
            if not rule:
                # Try default fallback rules
                rule = self.normalization_rules.get('default')
                if not rule:
                    result.errors.append(f"No normalization rule found for source: {source_name}")
                    return result
            
            # Process template-based field mappings
            mapped_data = {}
            
            # Check if we have template-based rules (new format)
            if hasattr(rule, 'field_mappings') and isinstance(rule.field_mappings, dict):
                for field_name, mapping_rules in rule.field_mappings.items():
                    if isinstance(mapping_rules, list):
                        # Process conditional rules
                        for mapping_rule in mapping_rules:
                            condition = mapping_rule.get('condition', 'true')
                            expression = mapping_rule.get('expression', '')
                            
                            # Evaluate condition (simple true/false for now)
                            if condition == 'true' or self._evaluate_condition(condition, source_data):
                                value = self._evaluate_template(expression, source_data)
                                if value is not None:
                                    mapped_data[field_name] = value
                                    break
                    else:
                        # Legacy format - direct field mapping
                        value = self.field_mapper.find_field_value(source_data, mapping_rules)
                        if value is not None:
                            mapped_data[field_name] = value
            
            # Extract basic indicator value if not already mapped
            if 'value' not in mapped_data or not mapped_data['value']:
                # Try common field names for the indicator value
                for field_name in ['value', 'indicator', 'ioc_value', 'url', 'ip_str', 'sha256_hash', 'id']:
                    if field_name in source_data:
                        mapped_data['value'] = source_data[field_name]
                        break
            
            # Validate required fields
            if 'value' not in mapped_data or not mapped_data['value']:
                result.errors.append("Missing required field: indicator value")
                return result
            
            # Auto-detect indicator type if not provided
            if 'indicator_type' not in mapped_data or not mapped_data['indicator_type']:
                detected_type = self.detect_indicator_type(mapped_data['value'])
                if detected_type:
                    mapped_data['indicator_type'] = detected_type
                else:
                    result.errors.append(f"Could not determine indicator type for value: {mapped_data['value']}")
                    return result
            
            # Ensure indicator_type is enum
            if isinstance(mapped_data['indicator_type'], str):
                try:
                    mapped_data['indicator_type'] = IndicatorType(mapped_data['indicator_type'])
                except ValueError:
                    # Try mapping common variations
                    type_mapping = {
                        'ip': IndicatorType.IP,
                        'domain': IndicatorType.DOMAIN,
                        'url': IndicatorType.URL,
                        'email': IndicatorType.EMAIL,
                        'file_hash': IndicatorType.FILE_HASH,
                        'hash': IndicatorType.FILE_HASH
                    }
                    mapped_type = type_mapping.get(mapped_data['indicator_type'].lower())
                    if mapped_type:
                        mapped_data['indicator_type'] = mapped_type
                    else:
                        result.errors.append(f"Unknown indicator type: {mapped_data['indicator_type']}")
                        return result
            
            # Build source metadata
            source_metadata = SourceMetadata(
                source_name=source_name,
                collection_method="automated",
                collected_at=datetime.utcnow(),
                source_url=self.field_mapper.find_field_value(source_data, 'source_url'),
                first_seen=self.field_mapper.find_field_value(source_data, 'first_seen'),
                last_seen=self.field_mapper.find_field_value(source_data, 'last_seen')
            )
            
            # Set default confidence if not provided
            if 'confidence' not in mapped_data:
                mapped_data['confidence'] = 70  # Default confidence
            
            # Set default values for required fields
            mapped_data.setdefault('source_metadata', source_metadata)
            mapped_data.setdefault('created', datetime.utcnow())
            mapped_data.setdefault('modified', datetime.utcnow())
            
            # Create normalized indicator
            normalized_indicator = NormalizedIndicator(**mapped_data)
            
            result.indicator = normalized_indicator
            result.success = True
            
            logger.debug(f"Successfully normalized {source_name} indicator: {mapped_data['value']}")
            
        except Exception as e:
            error_msg = f"Normalization failed: {e}"
            result.errors.append(error_msg)
            logger.error(f"Error normalizing indicator from {source_name}: {e}")
        
        return result
    
    def _build_network_context(self, source_data: Dict[str, Any], 
                              rule: NormalizationRule) -> Optional[NetworkContext]:
        """Build network context from source data."""
        network_fields = {
            'asn': self.field_mapper.find_field_value(source_data, 'asn'),
            'as_name': self.field_mapper.find_field_value(source_data, 'as_name'),
            'isp': self.field_mapper.find_field_value(source_data, 'isp'),
            'organization': self.field_mapper.find_field_value(source_data, 'organization'),
            'network': self.field_mapper.find_field_value(source_data, 'network')
        }
        
        # Build geolocation
        geo_data = {}
        for field in ['country', 'country_code', 'region', 'city', 'latitude', 'longitude']:
            value = self.field_mapper.find_field_value(source_data, field)
            if value is not None:
                geo_data[field] = value
        
        geolocation = GeographicLocation(**geo_data) if geo_data else None
        
        # Only create context if we have meaningful data
        if any(v is not None for v in network_fields.values()) or geolocation:
            return NetworkContext(
                **{k: v for k, v in network_fields.items() if v is not None},
                geolocation=geolocation
            )
        
        return None
    
    def _build_file_context(self, source_data: Dict[str, Any], 
                           rule: NormalizationRule) -> Optional[FileContext]:
        """Build file context from source data."""
        file_fields = {
            'size': self.field_mapper.find_field_value(source_data, 'file_size'),
            'mime_type': self.field_mapper.find_field_value(source_data, 'mime_type'),
            'file_type': self.field_mapper.find_field_value(source_data, 'file_type'),
            'ssdeep': self.field_mapper.find_field_value(source_data, 'ssdeep'),
            'imphash': self.field_mapper.find_field_value(source_data, 'imphash'),
            'entropy': self.field_mapper.find_field_value(source_data, 'entropy')
        }
        
        # Only create context if we have meaningful data
        if any(v is not None for v in file_fields.values()):
            return FileContext(**{k: v for k, v in file_fields.items() if v is not None})
        
        return None
    
    def _build_malware_context(self, source_data: Dict[str, Any], 
                              rule: NormalizationRule) -> Optional[MalwareContext]:
        """Build malware context from source data."""
        malware_fields = {
            'family': self.field_mapper.find_field_value(source_data, 'malware_family'),
            'variant': self.field_mapper.find_field_value(source_data, 'malware_variant'),
            'aliases': self.field_mapper.find_field_value(source_data, 'malware_aliases'),
            'capabilities': self.field_mapper.find_field_value(source_data, 'capabilities'),
            'yara_rules': self.field_mapper.find_field_value(source_data, 'yara_rules'),
            'mitre_techniques': self.field_mapper.find_field_value(source_data, 'mitre_techniques')
        }
        
        # Handle list fields
        for field in ['aliases', 'capabilities', 'yara_rules', 'mitre_techniques']:
            if malware_fields[field] and not isinstance(malware_fields[field], list):
                malware_fields[field] = [malware_fields[field]]
        
        # Only create context if we have meaningful data
        if any(v for v in malware_fields.values() if v):
            return MalwareContext(**{k: v for k, v in malware_fields.items() if v})
        
        return None