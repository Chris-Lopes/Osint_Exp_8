"""
Advanced Sigma Rule Generation Engine for ThreatSight Pipeline

Generates high-quality Sigma detection rules from enriched and scored threat intelligence.
Supports multiple detection scenarios with optimized rule patterns and flexible syntax.
"""

import yaml
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
import re
import hashlib
import logging
from pathlib import Path

class DetectionLevel(Enum):
    """Detection confidence levels for Sigma rules"""
    LOW = "low"
    MEDIUM = "medium" 
    HIGH = "high"
    CRITICAL = "critical"

class IndicatorType(Enum):
    """Types of threat indicators"""
    IP_ADDRESS = "ip"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "hash"
    EMAIL = "email"
    USER_AGENT = "user_agent"
    PROCESS = "process"
    REGISTRY = "registry"
    FILE_PATH = "file_path"

@dataclass
class SigmaRuleTemplate:
    """Template for generating Sigma rules"""
    title_pattern: str
    description_pattern: str
    logsource: Dict[str, str]
    detection_fields: Dict[str, str]
    selection_conditions: List[str]
    false_positive_filters: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

@dataclass 
class SigmaRule:
    """Generated Sigma rule structure"""
    title: str
    id: str
    description: str
    references: List[str]
    author: str
    date: str
    modified: str
    tags: List[str]
    logsource: Dict[str, str]
    detection: Dict[str, Any]
    level: str
    status: str = "experimental"
    falsepositives: List[str] = field(default_factory=list)
    
    def to_yaml(self) -> str:
        """Convert rule to YAML format"""
        rule_dict = {
            'title': self.title,
            'id': self.id,
            'description': self.description,
            'references': self.references,
            'author': self.author,
            'date': self.date,
            'modified': self.modified,
            'tags': self.tags,
            'logsource': self.logsource,
            'detection': self.detection,
            'falsepositives': self.falsepositives,
            'level': self.level,
            'status': self.status
        }
        return yaml.dump(rule_dict, default_flow_style=False, sort_keys=False)

class SigmaTemplateLibrary:
    """Library of Sigma rule templates for different scenarios"""
    
    def __init__(self):
        self.templates = self._initialize_templates()
    
    def _initialize_templates(self) -> Dict[IndicatorType, SigmaRuleTemplate]:
        """Initialize default templates for different indicator types"""
        return {
            IndicatorType.IP_ADDRESS: SigmaRuleTemplate(
                title_pattern="Malicious IP Communication - {indicator}",
                description_pattern="Detects network communication to known malicious IP address {indicator}",
                logsource={"category": "network_connection", "product": "windows"},
                detection_fields={"dst_ip": "DestinationIp", "src_ip": "SourceIp"},
                selection_conditions=["dst_ip: '{indicator}'"],
                false_positive_filters=[
                    "dst_port: [80, 443, 53]",  # Common legitimate ports
                    "process_name: 'chrome.exe'"  # Browser activity
                ],
                tags=["attack.command_and_control", "attack.t1071"]
            ),
            
            IndicatorType.DOMAIN: SigmaRuleTemplate(
                title_pattern="Malicious Domain Access - {indicator}",
                description_pattern="Detects DNS queries or HTTP requests to malicious domain {indicator}",
                logsource={"category": "dns_query", "product": "windows"},
                detection_fields={"query": "QueryName", "domain": "Domain"},
                selection_conditions=["query|endswith: '.{indicator}'"],
                false_positive_filters=[
                    "query|contains: 'update'",
                    "query|contains: 'cdn'"
                ],
                tags=["attack.command_and_control", "attack.t1071.001"]
            ),
            
            IndicatorType.URL: SigmaRuleTemplate(
                title_pattern="Malicious URL Access - {indicator}",
                description_pattern="Detects HTTP requests to malicious URL {indicator}",
                logsource={"category": "proxy", "product": "windows"},
                detection_fields={"url": "c-uri", "dest": "cs-host"},
                selection_conditions=["url|contains: '{indicator}'"],
                false_positive_filters=[
                    "cs-method: 'OPTIONS'",
                    "sc-status: [404, 403]"
                ],
                tags=["attack.initial_access", "attack.t1566"]
            ),
            
            IndicatorType.FILE_HASH: SigmaRuleTemplate(
                title_pattern="Malicious File Execution - {indicator}",
                description_pattern="Detects execution of file with malicious hash {indicator}",
                logsource={"category": "process_creation", "product": "windows"},
                detection_fields={"hash": "Hashes", "md5": "md5", "sha1": "sha1", "sha256": "sha256"},
                selection_conditions=["hash|contains: '{indicator}'"],
                false_positive_filters=[
                    "ParentImage|endswith: '\\\\explorer.exe'",
                    "CommandLine|contains: '--help'"
                ],
                tags=["attack.execution", "attack.t1059"]
            ),
            
            IndicatorType.PROCESS: SigmaRuleTemplate(
                title_pattern="Suspicious Process Execution - {indicator}",
                description_pattern="Detects execution of suspicious process {indicator}",
                logsource={"category": "process_creation", "product": "windows"},
                detection_fields={"image": "Image", "command": "CommandLine"},
                selection_conditions=["image|endswith: '{indicator}'"],
                false_positive_filters=[
                    "User|contains: 'SYSTEM'",
                    "ParentImage|endswith: '\\\\services.exe'"
                ],
                tags=["attack.execution", "attack.t1059"]
            )
        }
    
    def get_template(self, indicator_type: IndicatorType) -> SigmaRuleTemplate:
        """Get template for specific indicator type"""
        return self.templates.get(indicator_type)
    
    def add_custom_template(self, indicator_type: IndicatorType, template: SigmaRuleTemplate):
        """Add custom template"""
        self.templates[indicator_type] = template

class SigmaRuleOptimizer:
    """Optimizes Sigma rules for performance and accuracy"""
    
    def __init__(self):
        self.optimization_rules = self._load_optimization_rules()
    
    def _load_optimization_rules(self) -> Dict[str, Any]:
        """Load optimization rules and patterns"""
        return {
            'field_mappings': {
                'windows_process': {
                    'Image': ['process_name', 'executable'],
                    'CommandLine': ['command_line', 'process_command'],
                    'ParentImage': ['parent_process', 'parent_executable']
                },
                'network': {
                    'DestinationIp': ['dst_ip', 'destination_ip'],
                    'SourceIp': ['src_ip', 'source_ip'],
                    'DestinationPort': ['dst_port', 'destination_port']
                }
            },
            'performance_patterns': {
                'avoid_wildcards_start': True,
                'prefer_endswith_over_contains': True,
                'use_specific_fields': True,
                'limit_or_conditions': 10
            },
            'accuracy_patterns': {
                'add_context_filters': True,
                'exclude_common_false_positives': True,
                'validate_field_existence': True
            }
        }
    
    def optimize_detection_logic(self, detection: Dict[str, Any], 
                                 indicator_type: IndicatorType) -> Dict[str, Any]:
        """Optimize detection logic for performance"""
        optimized = detection.copy()
        
        # Optimize field usage
        if 'selection' in optimized:
            optimized['selection'] = self._optimize_selection(
                optimized['selection'], indicator_type
            )
        
        # Add performance filters
        if 'condition' not in optimized:
            optimized['condition'] = 'selection'
        
        # Add false positive filters if beneficial
        if indicator_type in [IndicatorType.PROCESS, IndicatorType.FILE_PATH]:
            optimized = self._add_fp_filters(optimized)
        
        return optimized
    
    def _optimize_selection(self, selection: Dict[str, Any], 
                           indicator_type: IndicatorType) -> Dict[str, Any]:
        """Optimize selection criteria"""
        optimized = {}
        
        for field, value in selection.items():
            # Optimize string matching
            if isinstance(value, str) and '*' in value:
                if value.startswith('*'):
                    # Convert leading wildcard to endswith
                    optimized[f"{field}|endswith"] = value[1:]
                elif value.endswith('*'):
                    # Convert trailing wildcard to startswith
                    optimized[f"{field}|startswith"] = value[:-1]
                else:
                    optimized[field] = value
            else:
                optimized[field] = value
        
        return optimized
    
    def _add_fp_filters(self, detection: Dict[str, Any]) -> Dict[str, Any]:
        """Add false positive filters"""
        if 'filter' not in detection:
            detection['filter'] = {}
        
        # Common false positive patterns
        fp_filters = {
            'ParentImage|endswith': ['\\explorer.exe', '\\services.exe'],
            'User|contains': ['SYSTEM', 'SERVICE']
        }
        
        for field, values in fp_filters.items():
            if field not in detection['filter']:
                detection['filter'][field] = values
        
        # Update condition to exclude filters
        if 'condition' in detection:
            detection['condition'] = f"{detection['condition']} and not filter"
        
        return detection

class SigmaRuleGenerator:
    """Main Sigma rule generation engine"""
    
    def __init__(self):
        self.template_library = SigmaTemplateLibrary()
        self.optimizer = SigmaRuleOptimizer()
        self.logger = logging.getLogger(__name__)
    
    def generate_rule(self, indicator_data: Dict[str, Any]) -> Optional[SigmaRule]:
        """Generate Sigma rule from threat indicator"""
        try:
            # Extract indicator information
            indicator_type = self._determine_indicator_type(indicator_data)
            if not indicator_type:
                self.logger.warning(f"Could not determine indicator type for: {indicator_data}")
                return None
            
            # Get appropriate template
            template = self.template_library.get_template(indicator_type)
            if not template:
                self.logger.warning(f"No template found for indicator type: {indicator_type}")
                return None
            
            # Generate rule components
            indicator_value = indicator_data.get('value', '')
            rule_id = self._generate_rule_id(indicator_value, indicator_type)
            
            # Create detection logic
            detection = self._create_detection_logic(template, indicator_value, indicator_data)
            
            # Optimize detection
            detection = self.optimizer.optimize_detection_logic(detection, indicator_type)
            
            # Determine severity level
            level = self._calculate_detection_level(indicator_data)
            
            # Build Sigma rule
            rule = SigmaRule(
                title=template.title_pattern.format(indicator=indicator_value),
                id=rule_id,
                description=template.description_pattern.format(indicator=indicator_value),
                references=self._extract_references(indicator_data),
                author="ThreatSight Pipeline",
                date=datetime.now().strftime("%Y/%m/%d"),
                modified=datetime.now().strftime("%Y/%m/%d"),
                tags=template.tags + self._extract_tags(indicator_data),
                logsource=template.logsource,
                detection=detection,
                level=level.value,
                falsepositives=template.false_positive_filters
            )
            
            return rule
            
        except Exception as e:
            self.logger.error(f"Error generating Sigma rule: {str(e)}")
            return None
    
    def _determine_indicator_type(self, indicator_data: Dict[str, Any]) -> Optional[IndicatorType]:
        """Determine the type of indicator"""
        value = indicator_data.get('value', '').lower()
        
        # IP Address pattern
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', value):
            return IndicatorType.IP_ADDRESS
        
        # Domain pattern
        if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$', value):
            return IndicatorType.DOMAIN
        
        # URL pattern
        if value.startswith(('http://', 'https://', 'ftp://')):
            return IndicatorType.URL
        
        # Hash patterns
        if re.match(r'^[a-fA-F0-9]{32}$', value):  # MD5
            return IndicatorType.FILE_HASH
        if re.match(r'^[a-fA-F0-9]{40}$', value):  # SHA1
            return IndicatorType.FILE_HASH
        if re.match(r'^[a-fA-F0-9]{64}$', value):  # SHA256
            return IndicatorType.FILE_HASH
        
        # Email pattern
        if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', value):
            return IndicatorType.EMAIL
        
        # Process/executable pattern
        if value.endswith('.exe') or '\\' in value:
            return IndicatorType.PROCESS
        
        return None
    
    def _create_detection_logic(self, template: SigmaRuleTemplate, 
                               indicator: str, indicator_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create detection logic from template"""
        detection = {
            'selection': {},
            'condition': 'selection'
        }
        
        # Apply selection conditions from template
        for condition in template.selection_conditions:
            field, operator, value = self._parse_condition(condition, indicator)
            if operator:
                detection['selection'][f"{field}|{operator}"] = value
            else:
                detection['selection'][field] = value
        
        # Add contextual filters based on threat data
        context_filters = self._create_context_filters(indicator_data)
        if context_filters:
            detection['context'] = context_filters
            detection['condition'] = 'selection and context'
        
        return detection
    
    def _parse_condition(self, condition: str, indicator: str) -> tuple:
        """Parse template condition into field, operator, value"""
        if ':' not in condition:
            return condition, None, indicator
        
        field_part, value_part = condition.split(':', 1)
        value_part = value_part.strip().strip("'\"")
        
        # Handle operators in field name
        if '|' in field_part:
            field, operator = field_part.split('|', 1)
            return field.strip(), operator.strip(), value_part.format(indicator=indicator)
        
        return field_part.strip(), None, value_part.format(indicator=indicator)
    
    def _create_context_filters(self, indicator_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create contextual filters based on threat intelligence"""
        filters = {}
        
        # Add threat family context
        if 'threat_family' in indicator_data:
            family = indicator_data['threat_family']
            if family in ['apt', 'targeted']:
                filters['ProcessName|contains'] = ['powershell', 'cmd', 'rundll32']
        
        # Add campaign context
        if 'campaign' in indicator_data:
            campaign = indicator_data['campaign']
            filters['Tags'] = [f"campaign.{campaign}"]
        
        # Add temporal context
        if 'first_seen' in indicator_data:
            first_seen = datetime.fromisoformat(indicator_data['first_seen'])
            if datetime.now() - first_seen < timedelta(days=7):
                filters['EventTime'] = f">={first_seen.isoformat()}"
        
        return filters
    
    def _calculate_detection_level(self, indicator_data: Dict[str, Any]) -> DetectionLevel:
        """Calculate appropriate detection level"""
        score = indicator_data.get('threat_score', 0)
        confidence = indicator_data.get('confidence_score', 0)
        
        # Combine threat score and confidence
        combined_score = (score * 0.7) + (confidence * 0.3)
        
        if combined_score >= 90:
            return DetectionLevel.CRITICAL
        elif combined_score >= 70:
            return DetectionLevel.HIGH
        elif combined_score >= 50:
            return DetectionLevel.MEDIUM
        else:
            return DetectionLevel.LOW
    
    def _extract_references(self, indicator_data: Dict[str, Any]) -> List[str]:
        """Extract references from threat data"""
        references = []
        
        if 'sources' in indicator_data:
            for source in indicator_data['sources']:
                if 'url' in source:
                    references.append(source['url'])
        
        if 'reports' in indicator_data:
            for report in indicator_data['reports']:
                if 'url' in report:
                    references.append(report['url'])
        
        return references
    
    def _extract_tags(self, indicator_data: Dict[str, Any]) -> List[str]:
        """Extract MITRE ATT&CK and other tags"""
        tags = []
        
        # Add MITRE techniques
        if 'mitre_techniques' in indicator_data:
            for technique in indicator_data['mitre_techniques']:
                tags.append(f"attack.{technique.lower()}")
        
        # Add threat actor tags
        if 'threat_actor' in indicator_data:
            actor = indicator_data['threat_actor'].replace(' ', '_').lower()
            tags.append(f"actor.{actor}")
        
        # Add malware family tags
        if 'malware_family' in indicator_data:
            family = indicator_data['malware_family'].replace(' ', '_').lower()
            tags.append(f"malware.{family}")
        
        return tags
    
    def _generate_rule_id(self, indicator: str, indicator_type: IndicatorType) -> str:
        """Generate unique rule ID"""
        content = f"{indicator}:{indicator_type.value}:{datetime.now().isoformat()}"
        return hashlib.sha256(content.encode()).hexdigest()[:8]

class SigmaBatchGenerator:
    """Batch processing for multiple Sigma rules"""
    
    def __init__(self):
        self.generator = SigmaRuleGenerator()
        self.logger = logging.getLogger(__name__)
    
    def generate_batch_rules(self, indicators: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate Sigma rules for batch of indicators"""
        results = {
            'generated_rules': [],
            'failed_indicators': [],
            'statistics': {
                'total_processed': len(indicators),
                'successful': 0,
                'failed': 0,
                'by_type': {},
                'by_level': {}
            }
        }
        
        for indicator_data in indicators:
            try:
                rule = self.generator.generate_rule(indicator_data)
                
                if rule:
                    results['generated_rules'].append(rule)
                    results['statistics']['successful'] += 1
                    
                    # Update type statistics
                    indicator_type = self.generator._determine_indicator_type(indicator_data)
                    if indicator_type:
                        type_name = indicator_type.value
                        results['statistics']['by_type'][type_name] = \
                            results['statistics']['by_type'].get(type_name, 0) + 1
                    
                    # Update level statistics
                    level = rule.level
                    results['statistics']['by_level'][level] = \
                        results['statistics']['by_level'].get(level, 0) + 1
                else:
                    results['failed_indicators'].append({
                        'indicator': indicator_data.get('value', 'unknown'),
                        'reason': 'Rule generation failed'
                    })
                    results['statistics']['failed'] += 1
                    
            except Exception as e:
                results['failed_indicators'].append({
                    'indicator': indicator_data.get('value', 'unknown'),
                    'reason': str(e)
                })
                results['statistics']['failed'] += 1
                self.logger.error(f"Failed to process indicator {indicator_data}: {str(e)}")
        
        return results
    
    def export_rules_to_files(self, rules: List[SigmaRule], 
                             output_dir: str = "sigma_rules") -> Dict[str, str]:
        """Export generated rules to individual YAML files"""
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        exported_files = {}
        
        for rule in rules:
            # Create filename from rule title
            filename = re.sub(r'[^a-zA-Z0-9\-_]', '_', rule.title.lower())
            filename = f"{filename}_{rule.id[:8]}.yml"
            
            file_path = output_path / filename
            
            try:
                with open(file_path, 'w') as f:
                    f.write(rule.to_yaml())
                
                exported_files[rule.id] = str(file_path)
                
            except Exception as e:
                self.logger.error(f"Failed to export rule {rule.id}: {str(e)}")
        
        return exported_files

# Example usage and testing
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Load real indicators for testing
    import json
    from pathlib import Path
    
    def load_real_indicators_for_sigma(limit=5):
        """Load real indicators for Sigma rule generation testing."""
        enriched_dir = Path('data/enriched')
        
        if not enriched_dir.exists():
            # Fallback to hardcoded examples if no real data
            return [
                {
                    'value': '192.168.1.100',
                    'threat_score': 85,
                    'confidence_score': 90,
                    'threat_family': 'apt',
                    'mitre_techniques': ['T1071.001'],
                    'sources': [{'url': 'https://example.com/threat-report'}]
                },
                {
                    'value': 'malicious-domain.com',
                    'threat_score': 75,
                    'confidence_score': 80,
                    'threat_actor': 'APT28',
                    'malware_family': 'Emotet'
                }
            ]
        
        indicators = []
        for source_dir in enriched_dir.iterdir():
            if source_dir.is_dir():
                for jsonl_file in source_dir.glob('*.jsonl'):
                    try:
                        with open(jsonl_file, 'r') as f:
                            for line_num, line in enumerate(f, 1):
                                if len(indicators) >= limit:
                                    break
                                line = line.strip()
                                if not line:
                                    continue
                                try:
                                    data = json.loads(line)
                                    # Convert to format expected by Sigma generator
                                    indicator = {
                                        'value': data.get('value'),
                                        'threat_score': data.get('confidence', 50),
                                        'confidence_score': data.get('confidence', 50),
                                        'threat_family': 'unknown',
                                        'sources': [{'url': 'real-data'}]
                                    }
                                    indicators.append(indicator)
                                except json.JSONDecodeError:
                                    continue
                    except Exception:
                        continue
        
        if not indicators:
            # Fallback to hardcoded examples
            return [
                {
                    'value': '192.168.1.100',
                    'threat_score': 85,
                    'confidence_score': 90,
                    'threat_family': 'apt',
                    'mitre_techniques': ['T1071.001'],
                    'sources': [{'url': 'https://example.com/threat-report'}]
                },
                {
                    'value': 'malicious-domain.com',
                    'threat_score': 75,
                    'confidence_score': 80,
                    'threat_actor': 'APT28',
                    'malware_family': 'Emotet'
                }
            ]
        
        return indicators
    
    # Sample threat indicator data
    sample_indicators = load_real_indicators_for_sigma()
    
    # Generate rules
    batch_generator = SigmaBatchGenerator()
    results = batch_generator.generate_batch_rules(sample_indicators)
    
    print(f"Generated {results['statistics']['successful']} rules")
    print(f"Failed to generate {results['statistics']['failed']} rules")
    
    # Export to files
    if results['generated_rules']:
        exported = batch_generator.export_rules_to_files(results['generated_rules'])
        print(f"Exported {len(exported)} rule files")