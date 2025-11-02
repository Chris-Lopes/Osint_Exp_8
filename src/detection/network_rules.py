"""
Network Detection Rules Generator for ThreatSight Pipeline

Generates Suricata/Snort rules for network-based threat detection.
Supports protocol-specific rule generation, traffic pattern analysis, and payload inspection.
"""

import json
import re
import ipaddress
from typing import Dict, List, Any, Optional, Set, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import logging
from urllib.parse import urlparse
import base64

class RuleAction(Enum):
    """Suricata/Snort rule actions"""
    ALERT = "alert"
    PASS = "pass"
    DROP = "drop"
    REJECT = "reject"
    LOG = "log"

class Protocol(Enum):
    """Supported network protocols"""
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    HTTP = "http"
    DNS = "dns"
    TLS = "tls"
    SMTP = "smtp"
    FTP = "ftp"
    SSH = "ssh"

class Direction(Enum):
    """Traffic direction"""
    TO_SERVER = "->"
    TO_CLIENT = "<-"
    BIDIRECTIONAL = "<>"

@dataclass
class NetworkRule:
    """Network detection rule structure"""
    action: RuleAction
    protocol: Protocol
    src_addr: str
    src_port: str
    direction: Direction
    dst_addr: str
    dst_port: str
    msg: str
    options: Dict[str, Any] = field(default_factory=dict)
    sid: Optional[int] = None
    rev: int = 1
    classtype: Optional[str] = None
    reference: List[str] = field(default_factory=list)
    metadata: Dict[str, str] = field(default_factory=dict)
    
    def to_suricata_format(self) -> str:
        """Convert rule to Suricata format"""
        parts = [
            self.action.value,
            self.protocol.value,
            self.src_addr,
            self.src_port,
            self.direction.value,
            self.dst_addr,
            self.dst_port
        ]
        
        # Build options string
        options = [f'msg:"{self.msg}"']
        
        # Add SID if present
        if self.sid:
            options.append(f"sid:{self.sid}")
        
        # Add revision
        options.append(f"rev:{self.rev}")
        
        # Add classtype
        if self.classtype:
            options.append(f"classtype:{self.classtype}")
        
        # Add references
        for ref in self.reference:
            options.append(f"reference:{ref}")
        
        # Add metadata
        if self.metadata:
            metadata_items = []
            for key, value in self.metadata.items():
                metadata_items.extend([key, value])
            if metadata_items:
                options.append(f"metadata:{','.join(metadata_items)}")
        
        # Add custom options
        for option, value in self.options.items():
            if value is True:
                options.append(option)
            elif value is not False:
                options.append(f"{option}:{value}")
        
        options_str = "; ".join(options) + ";"
        rule_str = " ".join(parts) + f" ({options_str})"
        
        return rule_str

class RuleTemplate:
    """Template for generating network rules"""
    
    def __init__(self, name: str, protocol: Protocol, pattern: str):
        self.name = name
        self.protocol = protocol
        self.pattern = pattern
        self.options = {}
        self.classtype = None
        self.priority = 3

class NetworkRuleTemplateLibrary:
    """Library of network rule templates"""
    
    def __init__(self):
        self.templates = self._initialize_templates()
    
    def _initialize_templates(self) -> Dict[str, RuleTemplate]:
        """Initialize default rule templates"""
        templates = {}
        
        # Malicious IP communication
        malicious_ip = RuleTemplate("malicious_ip", Protocol.TCP, "ip_reputation")
        malicious_ip.classtype = "trojan-activity"
        malicious_ip.priority = 1
        templates["malicious_ip"] = malicious_ip
        
        # Malicious domain DNS query
        malicious_dns = RuleTemplate("malicious_dns", Protocol.DNS, "dns_query")
        malicious_dns.classtype = "trojan-activity"
        malicious_dns.priority = 2
        malicious_dns.options = {"dns.query": True}
        templates["malicious_dns"] = malicious_dns
        
        # HTTP malicious URL
        malicious_http = RuleTemplate("malicious_http", Protocol.HTTP, "http_uri")
        malicious_http.classtype = "web-application-attack"
        malicious_http.priority = 2
        malicious_http.options = {"http.uri": True}
        templates["malicious_http"] = malicious_http
        
        # TLS malicious certificate
        malicious_tls = RuleTemplate("malicious_tls", Protocol.TLS, "tls_cert")
        malicious_tls.classtype = "trojan-activity"
        malicious_tls.priority = 2
        malicious_tls.options = {"tls.cert_subject": True}
        templates["malicious_tls"] = malicious_tls
        
        # SMTP malicious attachment
        malicious_smtp = RuleTemplate("malicious_smtp", Protocol.SMTP, "smtp_attachment")
        malicious_smtp.classtype = "trojan-activity"
        malicious_smtp.priority = 1
        malicious_smtp.options = {"file.name": True, "file.hash": True}
        templates["malicious_smtp"] = malicious_smtp
        
        # Suspicious user agent
        suspicious_ua = RuleTemplate("suspicious_ua", Protocol.HTTP, "user_agent")
        suspicious_ua.classtype = "web-application-attack"
        suspicious_ua.priority = 3
        suspicious_ua.options = {"http.user_agent": True}
        templates["suspicious_ua"] = suspicious_ua
        
        # C2 communication patterns
        c2_beacon = RuleTemplate("c2_beacon", Protocol.HTTP, "c2_beacon")
        c2_beacon.classtype = "trojan-activity"
        c2_beacon.priority = 1
        c2_beacon.options = {"http.method": "POST", "http.stat_code": "200"}
        templates["c2_beacon"] = c2_beacon
        
        return templates
    
    def get_template(self, template_name: str) -> Optional[RuleTemplate]:
        """Get template by name"""
        return self.templates.get(template_name)
    
    def get_template_for_indicator(self, indicator_type: str, protocol: str = None) -> Optional[RuleTemplate]:
        """Get appropriate template for indicator type"""
        mapping = {
            'ip': 'malicious_ip',
            'domain': 'malicious_dns',
            'url': 'malicious_http',
            'user_agent': 'suspicious_ua',
            'c2': 'c2_beacon'
        }
        
        template_name = mapping.get(indicator_type.lower())
        if template_name:
            return self.templates.get(template_name)
        
        return None

class PayloadAnalyzer:
    """Analyzes network payloads for suspicious patterns"""
    
    def __init__(self):
        self.suspicious_patterns = self._load_suspicious_patterns()
        self.encoding_patterns = self._load_encoding_patterns()
    
    def _load_suspicious_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Load suspicious payload patterns"""
        return {
            'base64_executable': {
                'pattern': r'(?:TVqQAAMAAAAEAAAA|TVpQAAIAAAAEAA8A|TVqAAAEAAAAEABAA)',
                'description': 'Base64 encoded PE executable',
                'severity': 'high'
            },
            'powershell_download': {
                'pattern': r'(?:DownloadString|DownloadFile|WebClient|Invoke-WebRequest)',
                'description': 'PowerShell download activity',
                'severity': 'medium'
            },
            'suspicious_cmdline': {
                'pattern': r'(?:cmd\.exe|powershell\.exe|wscript\.exe).*?(?:-enc|-e|-w hidden)',
                'description': 'Suspicious command line execution',
                'severity': 'high'
            },
            'sql_injection': {
                'pattern': r'(?:union.*?select|or.*?1=1|drop.*?table|exec.*?xp_)',
                'description': 'SQL injection attempt',
                'severity': 'high'
            },
            'xss_attempt': {
                'pattern': r'<script.*?>.*?</script>|javascript:|onload=|onerror=',
                'description': 'Cross-site scripting attempt',
                'severity': 'medium'
            }
        }
    
    def _load_encoding_patterns(self) -> Dict[str, str]:
        """Load patterns for different encodings"""
        return {
            'base64': r'[A-Za-z0-9+/]{40,}={0,2}',
            'hex': r'(?:0x)?[0-9a-fA-F]{20,}',
            'url_encoded': r'%[0-9a-fA-F]{2}',
            'unicode': r'\\\\u[0-9a-fA-F]{4}'
        }
    
    def analyze_payload(self, payload: str) -> Dict[str, Any]:
        """Analyze payload for suspicious patterns"""
        results = {
            'suspicious_patterns': [],
            'encodings_detected': [],
            'severity': 'low',
            'confidence': 0.0
        }
        
        # Check for suspicious patterns
        for pattern_name, pattern_info in self.suspicious_patterns.items():
            if re.search(pattern_info['pattern'], payload, re.IGNORECASE):
                results['suspicious_patterns'].append({
                    'name': pattern_name,
                    'description': pattern_info['description'],
                    'severity': pattern_info['severity']
                })
        
        # Check for encodings
        for encoding_name, encoding_pattern in self.encoding_patterns.items():
            if re.search(encoding_pattern, payload):
                results['encodings_detected'].append(encoding_name)
        
        # Calculate overall severity and confidence
        severities = [p['severity'] for p in results['suspicious_patterns']]
        if 'high' in severities:
            results['severity'] = 'high'
            results['confidence'] = 0.8
        elif 'medium' in severities:
            results['severity'] = 'medium'
            results['confidence'] = 0.6
        elif results['suspicious_patterns']:
            results['severity'] = 'low'
            results['confidence'] = 0.4
        
        # Boost confidence if multiple encodings detected
        if len(results['encodings_detected']) > 1:
            results['confidence'] = min(results['confidence'] + 0.2, 1.0)
        
        return results

class NetworkRuleGenerator:
    """Main network rule generation engine"""
    
    def __init__(self):
        self.template_library = NetworkRuleTemplateLibrary()
        self.payload_analyzer = PayloadAnalyzer()
        self.logger = logging.getLogger(__name__)
        self.sid_counter = 1000000  # Start SID from 1M
    
    def generate_rule_from_indicator(self, indicator_data: Dict[str, Any]) -> Optional[NetworkRule]:
        """Generate network rule from threat indicator"""
        try:
            indicator_value = indicator_data.get('value', '')
            indicator_type = self._determine_indicator_type(indicator_data)
            
            if not indicator_type:
                self.logger.warning(f"Could not determine indicator type: {indicator_value}")
                return None
            
            # Get appropriate template
            template = self.template_library.get_template_for_indicator(indicator_type)
            if not template:
                self.logger.warning(f"No template found for indicator type: {indicator_type}")
                return None
            
            # Generate rule based on indicator type
            if indicator_type == 'ip':
                return self._generate_ip_rule(indicator_data, template)
            elif indicator_type == 'domain':
                return self._generate_dns_rule(indicator_data, template)
            elif indicator_type == 'url':
                return self._generate_http_rule(indicator_data, template)
            elif indicator_type == 'user_agent':
                return self._generate_user_agent_rule(indicator_data, template)
            else:
                return self._generate_generic_rule(indicator_data, template)
                
        except Exception as e:
            self.logger.error(f"Error generating network rule: {str(e)}")
            return None
    
    def _determine_indicator_type(self, indicator_data: Dict[str, Any]) -> Optional[str]:
        """Determine the type of network indicator"""
        value = indicator_data.get('value', '').lower()
        
        # IP Address
        try:
            ipaddress.ip_address(value)
            return 'ip'
        except ValueError:
            pass
        
        # Domain
        if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?(\\.[a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?)*$', value):
            return 'domain'
        
        # URL
        if value.startswith(('http://', 'https://', 'ftp://')):
            return 'url'
        
        # User Agent
        if 'user-agent' in indicator_data.get('type', '').lower():
            return 'user_agent'
        
        # C2 beacon pattern
        if 'c2' in indicator_data.get('category', '').lower():
            return 'c2'
        
        return None
    
    def _generate_ip_rule(self, indicator_data: Dict[str, Any], template: RuleTemplate) -> NetworkRule:
        """Generate rule for malicious IP"""
        ip_value = indicator_data['value']
        
        # Create rule for both inbound and outbound traffic
        rule = NetworkRule(
            action=RuleAction.ALERT,
            protocol=Protocol.TCP,
            src_addr="any",
            src_port="any",
            direction=Direction.BIDIRECTIONAL,
            dst_addr=ip_value,
            dst_port="any",
            msg=f"ET MALWARE Communication to Known Malicious IP {ip_value}",
            sid=self._get_next_sid(),
            classtype=template.classtype or "trojan-activity"
        )
        
        # Add threat intelligence metadata
        rule.metadata = self._extract_metadata(indicator_data)
        rule.reference = self._extract_references(indicator_data)
        
        # Add flow tracking
        rule.options["flow"] = "established,to_server"
        
        return rule
    
    def _generate_dns_rule(self, indicator_data: Dict[str, Any], template: RuleTemplate) -> NetworkRule:
        """Generate rule for malicious DNS query"""
        domain_value = indicator_data['value']
        
        rule = NetworkRule(
            action=RuleAction.ALERT,
            protocol=Protocol.DNS,
            src_addr="any",
            src_port="any",
            direction=Direction.TO_SERVER,
            dst_addr="any",
            dst_port="53",
            msg=f"ET MALWARE DNS Query for Malicious Domain {domain_value}",
            sid=self._get_next_sid(),
            classtype=template.classtype or "trojan-activity"
        )
        
        # DNS-specific options
        rule.options["dns.query"] = True
        rule.options["content"] = f'"{domain_value}"'
        rule.options["nocase"] = True
        
        rule.metadata = self._extract_metadata(indicator_data)
        rule.reference = self._extract_references(indicator_data)
        
        return rule
    
    def _generate_http_rule(self, indicator_data: Dict[str, Any], template: RuleTemplate) -> NetworkRule:
        """Generate rule for malicious HTTP URL"""
        url_value = indicator_data['value']
        parsed_url = urlparse(url_value)
        
        rule = NetworkRule(
            action=RuleAction.ALERT,
            protocol=Protocol.HTTP,
            src_addr="any",
            src_port="any",
            direction=Direction.TO_SERVER,
            dst_addr="any",
            dst_port="[80,443,8080,8443]",
            msg=f"ET MALWARE HTTP Request to Malicious URL {parsed_url.netloc}",
            sid=self._get_next_sid(),
            classtype=template.classtype or "web-application-attack"
        )
        
        # HTTP-specific options
        rule.options["http.uri"] = True
        rule.options["content"] = f'"{parsed_url.path}"'
        rule.options["http.host"] = f'"{parsed_url.netloc}"'
        rule.options["nocase"] = True
        
        # Add payload analysis if available
        if 'payload' in indicator_data:
            payload_analysis = self.payload_analyzer.analyze_payload(indicator_data['payload'])
            if payload_analysis['suspicious_patterns']:
                rule.options["pcre"] = self._build_pcre_from_analysis(payload_analysis)
        
        rule.metadata = self._extract_metadata(indicator_data)
        rule.reference = self._extract_references(indicator_data)
        
        return rule
    
    def _generate_user_agent_rule(self, indicator_data: Dict[str, Any], template: RuleTemplate) -> NetworkRule:
        """Generate rule for suspicious User-Agent"""
        ua_value = indicator_data['value']
        
        rule = NetworkRule(
            action=RuleAction.ALERT,
            protocol=Protocol.HTTP,
            src_addr="any",
            src_port="any",
            direction=Direction.TO_SERVER,
            dst_addr="any",
            dst_port="[80,443,8080,8443]",
            msg=f"ET MALWARE Suspicious User-Agent String Detected",
            sid=self._get_next_sid(),
            classtype=template.classtype or "web-application-attack"
        )
        
        # User-Agent specific options
        rule.options["http.user_agent"] = True
        rule.options["content"] = f'"{ua_value}"'
        rule.options["nocase"] = True
        
        rule.metadata = self._extract_metadata(indicator_data)
        rule.reference = self._extract_references(indicator_data)
        
        return rule
    
    def _generate_generic_rule(self, indicator_data: Dict[str, Any], template: RuleTemplate) -> NetworkRule:
        """Generate generic rule for unknown indicator types"""
        indicator_value = indicator_data['value']
        
        rule = NetworkRule(
            action=RuleAction.ALERT,
            protocol=Protocol.TCP,
            src_addr="any",
            src_port="any",
            direction=Direction.BIDIRECTIONAL,
            dst_addr="any",
            dst_port="any",
            msg=f"ET MALWARE Generic Threat Indicator Detected: {indicator_value[:50]}",
            sid=self._get_next_sid(),
            classtype="trojan-activity"
        )
        
        # Generic content matching
        rule.options["content"] = f'"{indicator_value}"'
        rule.options["nocase"] = True
        
        rule.metadata = self._extract_metadata(indicator_data)
        rule.reference = self._extract_references(indicator_data)
        
        return rule
    
    def _build_pcre_from_analysis(self, payload_analysis: Dict[str, Any]) -> str:
        """Build PCRE pattern from payload analysis"""
        patterns = []
        
        for pattern_info in payload_analysis['suspicious_patterns']:
            # Simplified pattern extraction - in reality this would be more sophisticated
            if pattern_info['name'] == 'base64_executable':
                patterns.append(r'/TVqQAAMAAAAEAAAA|TVpQAAIAAAAEAA8A/i')
            elif pattern_info['name'] == 'powershell_download':
                patterns.append(r'/DownloadString|DownloadFile|WebClient/i')
        
        if patterns:
            return f"/{('|').join(patterns)}/i"
        
        return None
    
    def _extract_metadata(self, indicator_data: Dict[str, Any]) -> Dict[str, str]:
        """Extract metadata from indicator data"""
        metadata = {
            'created_at': datetime.now().strftime('%Y-%m-%d'),
            'policy': 'Balanced'
        }
        
        if 'malware_family' in indicator_data:
            metadata['malware_family'] = indicator_data['malware_family']
        
        if 'threat_actor' in indicator_data:
            metadata['threat_actor'] = indicator_data['threat_actor']
        
        if 'campaign' in indicator_data:
            metadata['attack_target'] = indicator_data['campaign']
        
        if 'confidence_score' in indicator_data:
            confidence = indicator_data['confidence_score']
            if confidence >= 90:
                metadata['confidence'] = 'high'
            elif confidence >= 70:
                metadata['confidence'] = 'medium'
            else:
                metadata['confidence'] = 'low'
        
        return metadata
    
    def _extract_references(self, indicator_data: Dict[str, Any]) -> List[str]:
        """Extract references from indicator data"""
        references = []
        
        if 'sources' in indicator_data:
            for source in indicator_data['sources']:
                if 'url' in source:
                    # Format as Suricata reference
                    references.append(f"url,{source['url']}")
        
        if 'mitre_techniques' in indicator_data:
            for technique in indicator_data['mitre_techniques']:
                references.append(f"mitre,{technique}")
        
        return references
    
    def _get_next_sid(self) -> int:
        """Get next available SID"""
        current_sid = self.sid_counter
        self.sid_counter += 1
        return current_sid

class NetworkRuleBatchGenerator:
    """Batch processing for network rules"""
    
    def __init__(self):
        self.generator = NetworkRuleGenerator()
        self.logger = logging.getLogger(__name__)
    
    def generate_batch_rules(self, indicators: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate network rules for batch of indicators"""
        results = {
            'generated_rules': [],
            'failed_indicators': [],
            'statistics': {
                'total_processed': len(indicators),
                'successful': 0,
                'failed': 0,
                'by_protocol': {},
                'by_type': {}
            }
        }
        
        for indicator_data in indicators:
            try:
                rule = self.generator.generate_rule_from_indicator(indicator_data)
                
                if rule:
                    results['generated_rules'].append(rule)
                    results['statistics']['successful'] += 1
                    
                    # Update protocol statistics
                    protocol = rule.protocol.value
                    results['statistics']['by_protocol'][protocol] = \
                        results['statistics']['by_protocol'].get(protocol, 0) + 1
                    
                    # Update type statistics
                    indicator_type = self.generator._determine_indicator_type(indicator_data)
                    if indicator_type:
                        results['statistics']['by_type'][indicator_type] = \
                            results['statistics']['by_type'].get(indicator_type, 0) + 1
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
    
    def export_rules_to_file(self, rules: List[NetworkRule], 
                            output_path: str = "network_rules.rules") -> bool:
        """Export rules to Suricata/Snort rules file"""
        try:
            with open(output_path, 'w') as f:
                f.write("# Network Detection Rules Generated by ThreatSight Pipeline\\n")
                f.write(f"# Generated on: {datetime.now().isoformat()}\\n")
                f.write(f"# Total rules: {len(rules)}\\n")
                f.write("\\n")
                
                # Group rules by protocol
                rules_by_protocol = {}
                for rule in rules:
                    protocol = rule.protocol.value
                    if protocol not in rules_by_protocol:
                        rules_by_protocol[protocol] = []
                    rules_by_protocol[protocol].append(rule)
                
                # Write rules grouped by protocol
                for protocol, protocol_rules in rules_by_protocol.items():
                    f.write(f"# {protocol.upper()} Rules\\n")
                    for rule in protocol_rules:
                        f.write(rule.to_suricata_format() + "\\n")
                    f.write("\\n")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to export network rules: {str(e)}")
            return False

# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Load real indicators for testing
    import json
    from pathlib import Path
    
    def load_real_indicators_for_network(limit=5):
        """Load real indicators for network rule generation testing."""
        enriched_dir = Path('data/enriched')
        
        if not enriched_dir.exists():
            # Fallback to hardcoded examples if no real data
            return [
                {
                    'value': '192.168.1.100',
                    'type': 'ip',
                    'malware_family': 'Emotet',
                    'threat_score': 85,
                    'confidence_score': 90,
                    'time_window': '24h'
                },
                {
                    'value': 'malicious-domain.com',
                    'type': 'domain',
                    'threat_actor': 'APT28',
                    'threat_score': 75,
                    'confidence_score': 85
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
                                    # Convert to format expected by network rule generator
                                    indicator = {
                                        'value': data.get('value'),
                                        'type': data.get('indicator_type', 'unknown'),
                                        'threat_score': data.get('confidence', 50),
                                        'confidence_score': data.get('confidence', 50),
                                        'time_window': '24h'
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
                    'type': 'ip',
                    'malware_family': 'Emotet',
                    'threat_score': 85,
                    'confidence_score': 90,
                    'time_window': '24h'
                },
                {
                    'value': 'malicious-domain.com',
                    'type': 'domain',
                    'threat_actor': 'APT28',
                    'threat_score': 75,
                    'confidence_score': 85
                }
            ]
        
        return indicators
    
    # Sample network indicators
    sample_indicators = load_real_indicators_for_network()
    
    # Generate rules
    batch_generator = NetworkRuleBatchGenerator()
    results = batch_generator.generate_batch_rules(sample_indicators)
    
    print(f"Generated {results['statistics']['successful']} network rules")
    print(f"Protocol distribution: {results['statistics']['by_protocol']}")
    
    # Export to file
    if results['generated_rules']:
        success = batch_generator.export_rules_to_file(results['generated_rules'])
        if success:
            print(f"Exported {len(results['generated_rules'])} rules to network_rules.rules")