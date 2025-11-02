"""
SIEM Detection Integration for ThreatSight Pipeline

Generates platform-specific detection queries for Splunk, Elastic, QRadar, and other SIEM platforms.
Supports field mapping, alerting configuration, and dashboard integration.
"""

import json
import yaml
from typing import Dict, List, Any, Optional, Set, Union
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
import logging
import re
from abc import ABC, abstractmethod

class SiemPlatform(Enum):
    """Supported SIEM platforms"""
    SPLUNK = "splunk"
    ELASTIC = "elastic"
    QRADAR = "qradar"
    SENTINEL = "sentinel"
    CHRONICLE = "chronicle"
    ARCSIGHT = "arcsight"

class AlertSeverity(Enum):
    """Alert severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class SiemQuery:
    """SIEM detection query structure"""
    name: str
    description: str
    platform: SiemPlatform
    query: str
    time_window: str
    severity: AlertSeverity
    tags: List[str] = field(default_factory=list)
    fields: List[str] = field(default_factory=list)
    threshold: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    alert_config: Dict[str, Any] = field(default_factory=dict)

@dataclass
class FieldMapping:
    """Field mapping between generic and platform-specific fields"""
    generic_field: str
    platform_field: str
    transformation: Optional[str] = None
    required: bool = True

class SiemPlatformAdapter(ABC):
    """Abstract base class for SIEM platform adapters"""
    
    @abstractmethod
    def generate_query(self, indicator_data: Dict[str, Any]) -> str:
        """Generate platform-specific query"""
        pass
    
    @abstractmethod
    def get_field_mappings(self) -> Dict[str, FieldMapping]:
        """Get platform-specific field mappings"""
        pass
    
    @abstractmethod
    def format_time_window(self, window: str) -> str:
        """Format time window for platform"""
        pass
    
    @abstractmethod
    def create_alert_config(self, query_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create alerting configuration"""
        pass

class SplunkAdapter(SiemPlatformAdapter):
    """Splunk SIEM platform adapter"""
    
    def __init__(self):
        self.field_mappings = {
            'source_ip': FieldMapping('source_ip', 'src_ip'),
            'destination_ip': FieldMapping('destination_ip', 'dest_ip'),
            'source_port': FieldMapping('source_port', 'src_port'),
            'destination_port': FieldMapping('destination_port', 'dest_port'),
            'domain': FieldMapping('domain', 'query'),
            'url': FieldMapping('url', 'url'),
            'user_agent': FieldMapping('user_agent', 'http_user_agent'),
            'process_name': FieldMapping('process_name', 'process_name'),
            'file_hash': FieldMapping('file_hash', 'file_hash'),
            'timestamp': FieldMapping('timestamp', '_time'),
            'hostname': FieldMapping('hostname', 'host'),
            'username': FieldMapping('username', 'user')
        }
    
    def get_field_mappings(self) -> Dict[str, FieldMapping]:
        """Get Splunk field mappings"""
        return self.field_mappings
    
    def generate_query(self, indicator_data: Dict[str, Any]) -> str:
        """Generate Splunk SPL query"""
        indicator_value = indicator_data.get('value', '')
        indicator_type = indicator_data.get('type', '').lower()
        
        # Base search
        base_search = "search"
        
        # Add index if specified
        if 'index' in indicator_data:
            base_search += f" index={indicator_data['index']}"
        else:
            base_search += " index=*"
        
        # Build search criteria based on indicator type
        search_criteria = []
        
        if indicator_type == 'ip':
            search_criteria.extend([
                f'src_ip="{indicator_value}"',
                f'dest_ip="{indicator_value}"',
                f'src="{indicator_value}"',
                f'dest="{indicator_value}"'
            ])
            query_part = f"({' OR '.join(search_criteria)})"
            
        elif indicator_type == 'domain':
            search_criteria.extend([
                f'query="*{indicator_value}*"',
                f'domain="*{indicator_value}*"',
                f'dns_query="*{indicator_value}*"'
            ])
            query_part = f"({' OR '.join(search_criteria)})"
            
        elif indicator_type == 'url':
            search_criteria.extend([
                f'url="*{indicator_value}*"',
                f'uri="*{indicator_value}*"',
                f'uri_path="*{indicator_value}*"'
            ])
            query_part = f"({' OR '.join(search_criteria)})"
            
        elif indicator_type == 'hash':
            search_criteria.extend([
                f'file_hash="{indicator_value}"',
                f'md5="{indicator_value}"',
                f'sha1="{indicator_value}"',
                f'sha256="{indicator_value}"'
            ])
            query_part = f"({' OR '.join(search_criteria)})"
            
        elif indicator_type == 'user_agent':
            query_part = f'http_user_agent="*{indicator_value}*"'
            
        else:
            # Generic search
            query_part = f'"{indicator_value}"'
        
        # Add time window
        time_window = indicator_data.get('time_window', '-24h@h')
        
        # Build complete query
        spl_query = f"{base_search} earliest={time_window} {query_part}"
        
        # Add statistical analysis
        spl_query += " | stats count by src_ip, dest_ip, user, host"
        spl_query += " | where count > 1"
        spl_query += " | sort - count"
        
        return spl_query
    
    def format_time_window(self, window: str) -> str:
        """Format time window for Splunk"""
        # Convert standard time formats to Splunk format
        time_mappings = {
            '1h': '-1h@h',
            '24h': '-24h@h',
            '7d': '-7d@d',
            '30d': '-30d@d'
        }
        return time_mappings.get(window, window)
    
    def create_alert_config(self, query_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create Splunk alert configuration"""
        return {
            'alert_type': 'number of events',
            'alert_comparator': 'greater than',
            'alert_threshold': query_data.get('threshold', 0),
            'cron_schedule': '*/15 * * * *',  # Every 15 minutes
            'actions': [
                {
                    'action': 'email',
                    'email.to': 'security@company.com',
                    'email.subject': f"ThreatSight Alert: {query_data.get('name', 'Unknown')}"
                },
                {
                    'action': 'webhook',
                    'webhook.url': 'https://siem.company.com/alerts'
                }
            ]
        }

class ElasticAdapter(SiemPlatformAdapter):
    """Elasticsearch/Kibana SIEM platform adapter"""
    
    def __init__(self):
        self.field_mappings = {
            'source_ip': FieldMapping('source_ip', 'source.ip'),
            'destination_ip': FieldMapping('destination_ip', 'destination.ip'),
            'source_port': FieldMapping('source_port', 'source.port'),
            'destination_port': FieldMapping('destination_port', 'destination.port'),
            'domain': FieldMapping('domain', 'dns.question.name'),
            'url': FieldMapping('url', 'url.full'),
            'user_agent': FieldMapping('user_agent', 'user_agent.original'),
            'process_name': FieldMapping('process_name', 'process.name'),
            'file_hash': FieldMapping('file_hash', 'file.hash.sha256'),
            'timestamp': FieldMapping('timestamp', '@timestamp'),
            'hostname': FieldMapping('hostname', 'host.name'),
            'username': FieldMapping('username', 'user.name')
        }
    
    def get_field_mappings(self) -> Dict[str, FieldMapping]:
        """Get Elasticsearch field mappings"""
        return self.field_mappings
    
    def generate_query(self, indicator_data: Dict[str, Any]) -> str:
        """Generate Elasticsearch DSL query"""
        indicator_value = indicator_data.get('value', '')
        indicator_type = indicator_data.get('type', '').lower()
        
        # Build query based on indicator type
        if indicator_type == 'ip':
            query = {
                "bool": {
                    "should": [
                        {"term": {"source.ip": indicator_value}},
                        {"term": {"destination.ip": indicator_value}},
                        {"term": {"client.ip": indicator_value}},
                        {"term": {"server.ip": indicator_value}}
                    ],
                    "minimum_should_match": 1
                }
            }
            
        elif indicator_type == 'domain':
            query = {
                "bool": {
                    "should": [
                        {"wildcard": {"dns.question.name": f"*{indicator_value}*"}},
                        {"wildcard": {"url.domain": f"*{indicator_value}*"}},
                        {"wildcard": {"destination.domain": f"*{indicator_value}*"}}
                    ],
                    "minimum_should_match": 1
                }
            }
            
        elif indicator_type == 'url':
            query = {
                "bool": {
                    "should": [
                        {"wildcard": {"url.full": f"*{indicator_value}*"}},
                        {"wildcard": {"http.request.uri": f"*{indicator_value}*"}}
                    ],
                    "minimum_should_match": 1
                }
            }
            
        elif indicator_type == 'hash':
            query = {
                "bool": {
                    "should": [
                        {"term": {"file.hash.md5": indicator_value}},
                        {"term": {"file.hash.sha1": indicator_value}},
                        {"term": {"file.hash.sha256": indicator_value}}
                    ],
                    "minimum_should_match": 1
                }
            }
            
        else:
            # Generic multi-match query
            query = {
                "multi_match": {
                    "query": indicator_value,
                    "fields": ["*"],
                    "type": "phrase_prefix"
                }
            }
        
        # Add time range
        time_window = indicator_data.get('time_window', '24h')
        time_range = {
            "range": {
                "@timestamp": {
                    "gte": f"now-{time_window}"
                }
            }
        }
        
        # Combine query and time filter
        full_query = {
            "query": {
                "bool": {
                    "must": [query],
                    "filter": [time_range]
                }
            },
            "aggs": {
                "by_source_ip": {
                    "terms": {
                        "field": "source.ip",
                        "size": 10
                    }
                },
                "by_destination": {
                    "terms": {
                        "field": "destination.ip",
                        "size": 10
                    }
                }
            }
        }
        
        return json.dumps(full_query, indent=2)
    
    def format_time_window(self, window: str) -> str:
        """Format time window for Elasticsearch"""
        # Elasticsearch uses relative time formats
        return window  # Already in correct format (1h, 24h, 7d, etc.)
    
    def create_alert_config(self, query_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create Elasticsearch/Watcher alert configuration"""
        return {
            "trigger": {
                "schedule": {
                    "interval": "15m"
                }
            },
            "input": {
                "search": {
                    "request": {
                        "search_type": "query_then_fetch",
                        "indices": ["logs-*"],
                        "body": json.loads(query_data.get('query', '{}'))
                    }
                }
            },
            "condition": {
                "compare": {
                    "ctx.payload.hits.total": {
                        "gt": query_data.get('threshold', 0)
                    }
                }
            },
            "actions": {
                "send_email": {
                    "email": {
                        "to": ["security@company.com"],
                        "subject": f"ThreatSight Alert: {query_data.get('name', 'Unknown')}",
                        "body": "Threat indicator detected: {{ctx.payload.hits.total}} events found"
                    }
                }
            }
        }

class SentinelAdapter(SiemPlatformAdapter):
    """Microsoft Sentinel (Azure Sentinel) adapter"""
    
    def __init__(self):
        self.field_mappings = {
            'source_ip': FieldMapping('source_ip', 'SrcIpAddr'),
            'destination_ip': FieldMapping('destination_ip', 'DstIpAddr'),
            'source_port': FieldMapping('source_port', 'SrcPortNumber'),
            'destination_port': FieldMapping('destination_port', 'DstPortNumber'),
            'domain': FieldMapping('domain', 'DnsQuery'),
            'url': FieldMapping('url', 'Url'),
            'user_agent': FieldMapping('user_agent', 'UserAgent'),
            'process_name': FieldMapping('process_name', 'ProcessName'),
            'file_hash': FieldMapping('file_hash', 'FileHashSha256'),
            'timestamp': FieldMapping('timestamp', 'TimeGenerated'),
            'hostname': FieldMapping('hostname', 'Computer'),
            'username': FieldMapping('username', 'AccountName')
        }
    
    def get_field_mappings(self) -> Dict[str, FieldMapping]:
        """Get Sentinel field mappings"""
        return self.field_mappings
    
    def generate_query(self, indicator_data: Dict[str, Any]) -> str:
        """Generate KQL (Kusto Query Language) query"""
        indicator_value = indicator_data.get('value', '')
        indicator_type = indicator_data.get('type', '').lower()
        
        # Base tables to search
        base_tables = []
        
        if indicator_type == 'ip':
            kql_query = f"""
            union
            (CommonSecurityLog | where SrcIpAddr == "{indicator_value}" or DstIpAddr == "{indicator_value}"),
            (NetworkCommunicationEvents | where RemoteIP == "{indicator_value}" or LocalIP == "{indicator_value}"),
            (DnsEvents | where ClientIP == "{indicator_value}"),
            (W3CIISLog | where cIP == "{indicator_value}" or sIP == "{indicator_value}")
            """
            
        elif indicator_type == 'domain':
            kql_query = f"""
            union
            (DnsEvents | where Name has "{indicator_value}"),
            (CommonSecurityLog | where RequestURL has "{indicator_value}"),
            (W3CIISLog | where csHost has "{indicator_value}")
            """
            
        elif indicator_type == 'url':
            kql_query = f"""
            union
            (CommonSecurityLog | where RequestURL has "{indicator_value}"),
            (W3CIISLog | where csUriStem has "{indicator_value}"),
            (OfficeActivity | where OfficeWorkload == "SharePoint" and SourceFileName has "{indicator_value}")
            """
            
        elif indicator_type == 'hash':
            kql_query = f"""
            union
            (DeviceFileEvents | where SHA256 == "{indicator_value}" or SHA1 == "{indicator_value}" or MD5 == "{indicator_value}"),
            (SecurityEvent | where FileHash == "{indicator_value}"),
            (CommonSecurityLog | where FileHash == "{indicator_value}")
            """
            
        else:
            # Generic search across multiple tables
            kql_query = f"""
            search "{indicator_value}"
            | where TimeGenerated > ago(24h)
            """
        
        # Add time filter and aggregation
        time_window = indicator_data.get('time_window', '24h')
        
        kql_query += f"""
        | where TimeGenerated > ago({time_window})
        | summarize EventCount = count(), 
                   FirstSeen = min(TimeGenerated), 
                   LastSeen = max(TimeGenerated),
                   Computers = make_set(Computer),
                   Users = make_set(AccountName)
                   by bin(TimeGenerated, 1h)
        | order by TimeGenerated desc
        """
        
        return kql_query.strip()
    
    def format_time_window(self, window: str) -> str:
        """Format time window for KQL"""
        # KQL uses formats like 1h, 24h, 7d
        return window
    
    def create_alert_config(self, query_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create Sentinel alert rule configuration"""
        return {
            "displayName": query_data.get('name', 'ThreatSight Detection'),
            "description": query_data.get('description', 'Auto-generated threat detection'),
            "severity": query_data.get('severity', 'Medium'),
            "enabled": True,
            "query": query_data.get('query', ''),
            "queryFrequency": "PT15M",  # Run every 15 minutes
            "queryPeriod": "PT1H",     # Look back 1 hour
            "triggerOperator": "GreaterThan",
            "triggerThreshold": query_data.get('threshold', 0),
            "suppressionDuration": "PT1H",
            "suppressionEnabled": False,
            "tactics": ["InitialAccess", "Execution", "CommandAndControl"],
            "alertRuleTemplateName": None,
            "incidentConfiguration": {
                "createIncident": True,
                "groupingConfiguration": {
                    "enabled": True,
                    "reopenClosedIncident": False,
                    "lookbackDuration": "PT1H",
                    "matchingMethod": "AllEntities"
                }
            }
        }

class SiemDetectionGenerator:
    """Main SIEM detection generation engine"""
    
    def __init__(self):
        self.adapters = {
            SiemPlatform.SPLUNK: SplunkAdapter(),
            SiemPlatform.ELASTIC: ElasticAdapter(),
            SiemPlatform.SENTINEL: SentinelAdapter()
        }
        self.logger = logging.getLogger(__name__)
    
    def generate_detection(self, indicator_data: Dict[str, Any], 
                          platform: SiemPlatform) -> Optional[SiemQuery]:
        """Generate SIEM detection for specific platform"""
        try:
            if platform not in self.adapters:
                self.logger.error(f"Unsupported SIEM platform: {platform}")
                return None
            
            adapter = self.adapters[platform]
            
            # Generate platform-specific query
            query = adapter.generate_query(indicator_data)
            
            # Create detection metadata
            detection_name = self._generate_detection_name(indicator_data)
            description = self._generate_description(indicator_data)
            severity = self._calculate_severity(indicator_data)
            tags = self._extract_tags(indicator_data)
            
            # Create alert configuration
            alert_config = adapter.create_alert_config({
                'name': detection_name,
                'description': description,
                'query': query,
                'threshold': indicator_data.get('alert_threshold', 1),
                'severity': severity.value
            })
            
            # Build SIEM query object
            siem_query = SiemQuery(
                name=detection_name,
                description=description,
                platform=platform,
                query=query,
                time_window=indicator_data.get('time_window', '24h'),
                severity=severity,
                tags=tags,
                fields=self._extract_relevant_fields(indicator_data, adapter),
                metadata=self._build_metadata(indicator_data),
                alert_config=alert_config
            )
            
            return siem_query
            
        except Exception as e:
            self.logger.error(f"Error generating SIEM detection: {str(e)}")
            return None
    
    def _generate_detection_name(self, indicator_data: Dict[str, Any]) -> str:
        """Generate detection rule name"""
        indicator_value = indicator_data.get('value', '')[:20]
        indicator_type = indicator_data.get('type', 'unknown')
        malware_family = indicator_data.get('malware_family', 'Unknown')
        
        return f"ThreatSight - {malware_family} {indicator_type.title()} Detection - {indicator_value}"
    
    def _generate_description(self, indicator_data: Dict[str, Any]) -> str:
        """Generate detection description"""
        indicator_value = indicator_data.get('value', '')
        indicator_type = indicator_data.get('type', 'indicator')
        
        description = f"Detects activity related to malicious {indicator_type} {indicator_value}"
        
        if 'malware_family' in indicator_data:
            description += f" associated with {indicator_data['malware_family']}"
        
        if 'threat_actor' in indicator_data:
            description += f" linked to threat actor {indicator_data['threat_actor']}"
        
        return description
    
    def _calculate_severity(self, indicator_data: Dict[str, Any]) -> AlertSeverity:
        """Calculate alert severity based on threat intelligence"""
        threat_score = indicator_data.get('threat_score', 0)
        confidence = indicator_data.get('confidence_score', 0)
        
        # Combine threat score and confidence
        combined_score = (threat_score * 0.7) + (confidence * 0.3)
        
        if combined_score >= 90:
            return AlertSeverity.CRITICAL
        elif combined_score >= 70:
            return AlertSeverity.HIGH
        elif combined_score >= 50:
            return AlertSeverity.MEDIUM
        else:
            return AlertSeverity.LOW
    
    def _extract_tags(self, indicator_data: Dict[str, Any]) -> List[str]:
        """Extract tags for detection rule"""
        tags = ['threatsight', 'automated']
        
        if 'malware_family' in indicator_data:
            family = indicator_data['malware_family'].lower().replace(' ', '_')
            tags.append(f"malware.{family}")
        
        if 'threat_actor' in indicator_data:
            actor = indicator_data['threat_actor'].lower().replace(' ', '_')
            tags.append(f"actor.{actor}")
        
        if 'mitre_techniques' in indicator_data:
            for technique in indicator_data['mitre_techniques']:
                tags.append(f"mitre.{technique.lower()}")
        
        return tags
    
    def _extract_relevant_fields(self, indicator_data: Dict[str, Any], 
                                adapter: SiemPlatformAdapter) -> List[str]:
        """Extract relevant fields for the detection"""
        field_mappings = adapter.get_field_mappings()
        indicator_type = indicator_data.get('type', '').lower()
        
        relevant_fields = ['timestamp', 'hostname']
        
        if indicator_type == 'ip':
            relevant_fields.extend(['source_ip', 'destination_ip', 'source_port', 'destination_port'])
        elif indicator_type == 'domain':
            relevant_fields.extend(['domain', 'source_ip'])
        elif indicator_type == 'url':
            relevant_fields.extend(['url', 'user_agent', 'source_ip'])
        elif indicator_type == 'hash':
            relevant_fields.extend(['file_hash', 'process_name', 'username'])
        
        # Convert to platform-specific fields
        platform_fields = []
        for field in relevant_fields:
            if field in field_mappings:
                platform_fields.append(field_mappings[field].platform_field)
        
        return platform_fields
    
    def _build_metadata(self, indicator_data: Dict[str, Any]) -> Dict[str, Any]:
        """Build detection metadata"""
        metadata = {
            'created_at': datetime.now().isoformat(),
            'indicator_type': indicator_data.get('type', 'unknown'),
            'threat_score': indicator_data.get('threat_score', 0),
            'confidence_score': indicator_data.get('confidence_score', 0)
        }
        
        optional_fields = ['malware_family', 'threat_actor', 'campaign', 'first_seen']
        for field in optional_fields:
            if field in indicator_data:
                metadata[field] = indicator_data[field]
        
        return metadata

class SiemBatchDetectionGenerator:
    """Batch SIEM detection generation"""
    
    def __init__(self):
        self.generator = SiemDetectionGenerator()
        self.logger = logging.getLogger(__name__)
    
    def generate_batch_detections(self, indicators: List[Dict[str, Any]], 
                                 platforms: List[SiemPlatform]) -> Dict[str, Any]:
        """Generate detections for multiple indicators and platforms"""
        results = {
            'generated_detections': {},
            'failed_indicators': [],
            'statistics': {
                'total_indicators': len(indicators),
                'total_platforms': len(platforms),
                'successful': 0,
                'failed': 0,
                'by_platform': {},
                'by_severity': {}
            }
        }
        
        # Initialize platform results
        for platform in platforms:
            results['generated_detections'][platform.value] = []
            results['statistics']['by_platform'][platform.value] = 0
        
        for indicator_data in indicators:
            for platform in platforms:
                try:
                    detection = self.generator.generate_detection(indicator_data, platform)
                    
                    if detection:
                        results['generated_detections'][platform.value].append(detection)
                        results['statistics']['successful'] += 1
                        results['statistics']['by_platform'][platform.value] += 1
                        
                        # Update severity statistics
                        severity = detection.severity.value
                        results['statistics']['by_severity'][severity] = \
                            results['statistics']['by_severity'].get(severity, 0) + 1
                    else:
                        results['failed_indicators'].append({
                            'indicator': indicator_data.get('value', 'unknown'),
                            'platform': platform.value,
                            'reason': 'Detection generation failed'
                        })
                        results['statistics']['failed'] += 1
                        
                except Exception as e:
                    results['failed_indicators'].append({
                        'indicator': indicator_data.get('value', 'unknown'),
                        'platform': platform.value,
                        'reason': str(e)
                    })
                    results['statistics']['failed'] += 1
                    self.logger.error(f"Failed to process indicator {indicator_data} for {platform}: {str(e)}")
        
        return results
    
    def export_detections(self, detections: Dict[str, List[SiemQuery]], 
                         output_dir: str = "siem_detections") -> Dict[str, str]:
        """Export detections to platform-specific files"""
        from pathlib import Path
        
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        exported_files = {}
        
        for platform, detection_list in detections.items():
            if not detection_list:
                continue
                
            platform_dir = output_path / platform
            platform_dir.mkdir(exist_ok=True)
            
            # Export queries
            queries_file = platform_dir / f"{platform}_queries.json"
            queries_data = []
            
            for detection in detection_list:
                query_data = {
                    'name': detection.name,
                    'description': detection.description,
                    'query': detection.query,
                    'severity': detection.severity.value,
                    'tags': detection.tags,
                    'metadata': detection.metadata
                }
                queries_data.append(query_data)
            
            with open(queries_file, 'w') as f:
                json.dump(queries_data, f, indent=2)
            
            exported_files[f"{platform}_queries"] = str(queries_file)
            
            # Export alert configurations
            alerts_file = platform_dir / f"{platform}_alerts.json"
            alerts_data = []
            
            for detection in detection_list:
                alerts_data.append({
                    'name': detection.name,
                    'config': detection.alert_config
                })
            
            with open(alerts_file, 'w') as f:
                json.dump(alerts_data, f, indent=2)
            
            exported_files[f"{platform}_alerts"] = str(alerts_file)
        
        return exported_files

# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Load real indicators for testing
    import json
    from pathlib import Path
    
    def load_real_indicators_for_siem(limit=5):
        """Load real indicators for SIEM detection generation testing."""
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
                                    # Convert to format expected by SIEM generator
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
    
    # Sample indicators
    sample_indicators = load_real_indicators_for_siem()
    
    # Generate detections for multiple platforms
    batch_generator = SiemBatchDetectionGenerator()
    platforms = [SiemPlatform.SPLUNK, SiemPlatform.ELASTIC, SiemPlatform.SENTINEL]
    
    results = batch_generator.generate_batch_detections(sample_indicators, platforms)
    
    print(f"Generated {results['statistics']['successful']} detections")
    print(f"Platform distribution: {results['statistics']['by_platform']}")
    
    # Export detections
    if any(results['generated_detections'].values()):
        exported = batch_generator.export_detections(results['generated_detections'])
        print(f"Exported detection files: {list(exported.keys())}")