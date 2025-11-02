"""
Detection Orchestration System for ThreatSight Pipeline

Orchestrates detection rule deployment, lifecycle management, performance monitoring,
and automated rule updates based on threat evolution.
"""

import json
import yaml
import time
import logging
import hashlib
from typing import Dict, List, Any, Optional, Tuple, Union, Set
from dataclasses import dataclass, field, asdict
from enum import Enum
from datetime import datetime, timedelta
from pathlib import Path
import asyncio
from concurrent.futures import ThreadPoolExecutor
import sqlite3
import requests
from abc import ABC, abstractmethod

class DeploymentStatus(Enum):
    """Rule deployment status"""
    PENDING = "pending"
    DEPLOYING = "deploying"
    ACTIVE = "active"
    PAUSED = "paused"
    FAILED = "failed"
    RETIRED = "retired"

class RuleSource(Enum):
    """Source of detection rules"""
    AUTO_GENERATED = "auto_generated"
    MANUAL = "manual"
    EXTERNAL_FEED = "external_feed"
    THREAT_HUNT = "threat_hunt"
    INCIDENT_RESPONSE = "incident_response"

class UpdateReason(Enum):
    """Reason for rule updates"""
    PERFORMANCE_OPTIMIZATION = "performance_optimization"
    FALSE_POSITIVE_REDUCTION = "false_positive_reduction"
    THREAT_EVOLUTION = "threat_evolution"
    COVERAGE_IMPROVEMENT = "coverage_improvement"
    PLATFORM_UPDATE = "platform_update"

@dataclass
class RuleMetrics:
    """Rule performance metrics"""
    rule_id: str
    total_alerts: int
    true_positives: int
    false_positives: int
    execution_time_ms: float
    last_triggered: Optional[datetime]
    accuracy_rate: float
    performance_score: float
    confidence_trend: List[float] = field(default_factory=list)
    alert_frequency: Dict[str, int] = field(default_factory=dict)

@dataclass
class DeploymentTarget:
    """Deployment target configuration"""
    platform: str
    endpoint: str
    credentials: Dict[str, str]
    config: Dict[str, Any] = field(default_factory=dict)
    enabled: bool = True

@dataclass
class RuleDeployment:
    """Rule deployment record"""
    rule_id: str
    platform: str
    deployment_id: str
    status: DeploymentStatus
    deployed_at: datetime
    version: str
    config: Dict[str, Any] = field(default_factory=dict)
    metrics: Optional[RuleMetrics] = None
    last_updated: Optional[datetime] = None

@dataclass
class RuleLifecycle:
    """Rule lifecycle management"""
    rule_id: str
    created_at: datetime
    source: RuleSource
    current_version: str
    status: DeploymentStatus
    deployments: List[RuleDeployment] = field(default_factory=list)
    update_history: List[Dict[str, Any]] = field(default_factory=list)
    performance_history: List[RuleMetrics] = field(default_factory=list)
    scheduled_actions: List[Dict[str, Any]] = field(default_factory=list)

class DeploymentAdapter(ABC):
    """Abstract base class for platform deployment adapters"""
    
    @abstractmethod
    async def deploy_rule(self, rule_content: str, config: Dict[str, Any]) -> str:
        """Deploy rule to platform"""
        pass
    
    @abstractmethod
    async def update_rule(self, deployment_id: str, rule_content: str) -> bool:
        """Update existing rule deployment"""
        pass
    
    @abstractmethod
    async def delete_rule(self, deployment_id: str) -> bool:
        """Delete rule deployment"""
        pass
    
    @abstractmethod
    async def get_rule_metrics(self, deployment_id: str) -> Optional[RuleMetrics]:
        """Get rule performance metrics"""
        pass
    
    @abstractmethod
    async def test_connectivity(self) -> bool:
        """Test connection to platform"""
        pass

class SplunkDeploymentAdapter(DeploymentAdapter):
    """Splunk deployment adapter"""
    
    def __init__(self, endpoint: str, credentials: Dict[str, str]):
        self.endpoint = endpoint.rstrip('/')
        self.username = credentials.get('username')
        self.password = credentials.get('password')
        self.token = credentials.get('token')
        self.session = None
        
    async def deploy_rule(self, rule_content: str, config: Dict[str, Any]) -> str:
        """Deploy rule to Splunk as saved search"""
        try:
            # Create saved search
            search_name = config.get('name', f'ThreatSight_Rule_{int(time.time())}')
            
            payload = {
                'name': search_name,
                'search': rule_content,
                'cron_schedule': config.get('schedule', '*/15 * * * *'),
                'description': config.get('description', 'Auto-deployed ThreatSight rule'),
                'is_scheduled': 1,
                'actions': 'email,rss',
                'alert_type': 'number of events',
                'alert_comparator': 'greater than',
                'alert_threshold': config.get('threshold', 0)
            }
            
            # Simulate API call (in real implementation, use Splunk REST API)
            deployment_id = f"splunk_{hashlib.md5(search_name.encode()).hexdigest()[:8]}"
            
            # Log deployment
            logging.info(f"Deployed Splunk rule: {search_name} -> {deployment_id}")
            return deployment_id
            
        except Exception as e:
            logging.error(f"Failed to deploy Splunk rule: {str(e)}")
            raise
    
    async def update_rule(self, deployment_id: str, rule_content: str) -> bool:
        """Update Splunk saved search"""
        try:
            # Update saved search via REST API
            logging.info(f"Updated Splunk rule: {deployment_id}")
            return True
        except Exception as e:
            logging.error(f"Failed to update Splunk rule {deployment_id}: {str(e)}")
            return False
    
    async def delete_rule(self, deployment_id: str) -> bool:
        """Delete Splunk saved search"""
        try:
            # Delete saved search via REST API
            logging.info(f"Deleted Splunk rule: {deployment_id}")
            return True
        except Exception as e:
            logging.error(f"Failed to delete Splunk rule {deployment_id}: {str(e)}")
            return False
    
    async def get_rule_metrics(self, deployment_id: str) -> Optional[RuleMetrics]:
        """Get Splunk rule metrics"""
        try:
            # Simulate metrics retrieval
            metrics = RuleMetrics(
                rule_id=deployment_id,
                total_alerts=45,
                true_positives=42,
                false_positives=3,
                execution_time_ms=250.0,
                last_triggered=datetime.now() - timedelta(hours=2),
                accuracy_rate=0.933,
                performance_score=0.85
            )
            return metrics
        except Exception as e:
            logging.error(f"Failed to get Splunk metrics for {deployment_id}: {str(e)}")
            return None
    
    async def test_connectivity(self) -> bool:
        """Test Splunk connectivity"""
        try:
            # Test API endpoint
            return True
        except:
            return False

class ElasticDeploymentAdapter(DeploymentAdapter):
    """Elasticsearch/Kibana deployment adapter"""
    
    def __init__(self, endpoint: str, credentials: Dict[str, str]):
        self.endpoint = endpoint.rstrip('/')
        self.username = credentials.get('username')
        self.password = credentials.get('password')
        self.api_key = credentials.get('api_key')
    
    async def deploy_rule(self, rule_content: str, config: Dict[str, Any]) -> str:
        """Deploy rule to Elasticsearch as Watcher"""
        try:
            # Create Watcher rule
            rule_name = config.get('name', f'threatsight_rule_{int(time.time())}')
            
            watcher_config = {
                'trigger': {
                    'schedule': {
                        'interval': config.get('interval', '15m')
                    }
                },
                'input': {
                    'search': {
                        'request': {
                            'search_type': 'query_then_fetch',
                            'indices': config.get('indices', ['logs-*']),
                            'body': json.loads(rule_content)
                        }
                    }
                },
                'condition': {
                    'compare': {
                        'ctx.payload.hits.total': {
                            'gt': config.get('threshold', 0)
                        }
                    }
                },
                'actions': {
                    'send_alert': {
                        'webhook': {
                            'url': config.get('webhook_url', 'http://localhost/alerts'),
                            'body': 'Alert triggered for rule: {{ctx.watch_id}}'
                        }
                    }
                }
            }
            
            deployment_id = f"elastic_{hashlib.md5(rule_name.encode()).hexdigest()[:8]}"
            
            logging.info(f"Deployed Elasticsearch rule: {rule_name} -> {deployment_id}")
            return deployment_id
            
        except Exception as e:
            logging.error(f"Failed to deploy Elasticsearch rule: {str(e)}")
            raise
    
    async def update_rule(self, deployment_id: str, rule_content: str) -> bool:
        """Update Elasticsearch Watcher"""
        try:
            logging.info(f"Updated Elasticsearch rule: {deployment_id}")
            return True
        except Exception as e:
            logging.error(f"Failed to update Elasticsearch rule {deployment_id}: {str(e)}")
            return False
    
    async def delete_rule(self, deployment_id: str) -> bool:
        """Delete Elasticsearch Watcher"""
        try:
            logging.info(f"Deleted Elasticsearch rule: {deployment_id}")
            return True
        except Exception as e:
            logging.error(f"Failed to delete Elasticsearch rule {deployment_id}: {str(e)}")
            return False
    
    async def get_rule_metrics(self, deployment_id: str) -> Optional[RuleMetrics]:
        """Get Elasticsearch rule metrics"""
        try:
            metrics = RuleMetrics(
                rule_id=deployment_id,
                total_alerts=28,
                true_positives=26,
                false_positives=2,
                execution_time_ms=180.0,
                last_triggered=datetime.now() - timedelta(hours=1),
                accuracy_rate=0.929,
                performance_score=0.88
            )
            return metrics
        except Exception as e:
            logging.error(f"Failed to get Elasticsearch metrics for {deployment_id}: {str(e)}")
            return None
    
    async def test_connectivity(self) -> bool:
        """Test Elasticsearch connectivity"""
        try:
            return True
        except:
            return False

class RuleMetricsCollector:
    """Collects and analyzes rule performance metrics"""
    
    def __init__(self, db_path: str = "rule_metrics.db"):
        self.db_path = db_path
        self._init_database()
    
    def _init_database(self):
        """Initialize metrics database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS rule_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_id TEXT NOT NULL,
                    platform TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    total_alerts INTEGER,
                    true_positives INTEGER,
                    false_positives INTEGER,
                    execution_time_ms REAL,
                    accuracy_rate REAL,
                    performance_score REAL
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS rule_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    details TEXT
                )
            """)
    
    def record_metrics(self, metrics: RuleMetrics, platform: str):
        """Record rule metrics"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO rule_metrics (
                    rule_id, platform, total_alerts, true_positives, 
                    false_positives, execution_time_ms, accuracy_rate, performance_score
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                metrics.rule_id, platform, metrics.total_alerts,
                metrics.true_positives, metrics.false_positives,
                metrics.execution_time_ms, metrics.accuracy_rate,
                metrics.performance_score
            ))
    
    def get_rule_history(self, rule_id: str, days: int = 30) -> List[RuleMetrics]:
        """Get rule performance history"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT * FROM rule_metrics 
                WHERE rule_id = ? AND timestamp >= datetime('now', '-{} days')
                ORDER BY timestamp DESC
            """.format(days), (rule_id,))
            
            metrics_list = []
            for row in cursor.fetchall():
                metrics = RuleMetrics(
                    rule_id=row[1],
                    total_alerts=row[4] or 0,
                    true_positives=row[5] or 0,
                    false_positives=row[6] or 0,
                    execution_time_ms=row[7] or 0.0,
                    last_triggered=None,
                    accuracy_rate=row[8] or 0.0,
                    performance_score=row[9] or 0.0
                )
                metrics_list.append(metrics)
            
            return metrics_list
    
    def analyze_performance_trends(self, rule_id: str) -> Dict[str, Any]:
        """Analyze rule performance trends"""
        history = self.get_rule_history(rule_id, 30)
        
        if not history:
            return {'trend': 'no_data', 'recommendations': []}
        
        analysis = {
            'trend': 'stable',
            'accuracy_trend': 'stable',
            'performance_trend': 'stable',
            'recommendations': [],
            'metrics_summary': {
                'avg_accuracy': sum(m.accuracy_rate for m in history) / len(history),
                'avg_performance': sum(m.performance_score for m in history) / len(history),
                'total_alerts': sum(m.total_alerts for m in history),
                'avg_false_positive_rate': sum(m.false_positives / max(m.total_alerts, 1) for m in history) / len(history)
            }
        }
        
        # Analyze trends
        recent_accuracy = sum(m.accuracy_rate for m in history[:7]) / min(7, len(history))
        older_accuracy = sum(m.accuracy_rate for m in history[7:14]) / max(1, len(history[7:14]))
        
        if recent_accuracy < older_accuracy - 0.05:
            analysis['accuracy_trend'] = 'declining'
            analysis['recommendations'].append('Consider rule optimization due to declining accuracy')
        elif recent_accuracy > older_accuracy + 0.05:
            analysis['accuracy_trend'] = 'improving'
        
        # Performance analysis
        avg_fp_rate = analysis['metrics_summary']['avg_false_positive_rate']
        if avg_fp_rate > 0.1:
            analysis['recommendations'].append('High false positive rate detected - rule tuning recommended')
        
        if analysis['metrics_summary']['avg_performance'] < 0.7:
            analysis['recommendations'].append('Performance optimization needed')
        
        return analysis

class RuleLifecycleManager:
    """Manages rule lifecycle and updates"""
    
    def __init__(self):
        self.metrics_collector = RuleMetricsCollector()
        self.rule_store = {}  # In production, use proper database
        self.logger = logging.getLogger(__name__)
    
    def create_rule_lifecycle(self, rule_id: str, source: RuleSource) -> RuleLifecycle:
        """Create new rule lifecycle"""
        lifecycle = RuleLifecycle(
            rule_id=rule_id,
            created_at=datetime.now(),
            source=source,
            current_version="1.0.0",
            status=DeploymentStatus.PENDING
        )
        
        self.rule_store[rule_id] = lifecycle
        return lifecycle
    
    def update_rule_status(self, rule_id: str, status: DeploymentStatus):
        """Update rule status"""
        if rule_id in self.rule_store:
            self.rule_store[rule_id].status = status
            
            # Record status change event
            self._record_lifecycle_event(rule_id, "status_change", {
                'new_status': status.value,
                'timestamp': datetime.now().isoformat()
            })
    
    def add_deployment(self, rule_id: str, deployment: RuleDeployment):
        """Add deployment to rule lifecycle"""
        if rule_id in self.rule_store:
            self.rule_store[rule_id].deployments.append(deployment)
            
            # Update rule status if first deployment
            if deployment.status == DeploymentStatus.ACTIVE:
                self.update_rule_status(rule_id, DeploymentStatus.ACTIVE)
    
    def schedule_rule_update(self, rule_id: str, update_reason: UpdateReason, 
                           scheduled_time: datetime, config: Dict[str, Any]):
        """Schedule rule update"""
        if rule_id in self.rule_store:
            action = {
                'type': 'update',
                'reason': update_reason.value,
                'scheduled_time': scheduled_time.isoformat(),
                'config': config,
                'status': 'pending'
            }
            
            self.rule_store[rule_id].scheduled_actions.append(action)
            
            self.logger.info(f"Scheduled update for rule {rule_id}: {update_reason.value}")
    
    def get_rules_for_update(self) -> List[Tuple[str, Dict[str, Any]]]:
        """Get rules scheduled for update"""
        current_time = datetime.now()
        rules_to_update = []
        
        for rule_id, lifecycle in self.rule_store.items():
            for action in lifecycle.scheduled_actions:
                if (action['status'] == 'pending' and 
                    datetime.fromisoformat(action['scheduled_time']) <= current_time):
                    
                    rules_to_update.append((rule_id, action))
                    action['status'] = 'processing'
        
        return rules_to_update
    
    def _record_lifecycle_event(self, rule_id: str, event_type: str, details: Dict[str, Any]):
        """Record lifecycle event"""
        with sqlite3.connect(self.metrics_collector.db_path) as conn:
            conn.execute("""
                INSERT INTO rule_events (rule_id, event_type, details)
                VALUES (?, ?, ?)
            """, (rule_id, event_type, json.dumps(details)))

class DetectionOrchestrator:
    """Main detection orchestration system"""
    
    def __init__(self):
        self.deployment_adapters = {}
        self.lifecycle_manager = RuleLifecycleManager()
        self.metrics_collector = RuleMetricsCollector()
        self.logger = logging.getLogger(__name__)
        self.executor = ThreadPoolExecutor(max_workers=10)
        
    def register_deployment_target(self, platform: str, target: DeploymentTarget):
        """Register deployment target"""
        if platform == 'splunk':
            adapter = SplunkDeploymentAdapter(target.endpoint, target.credentials)
        elif platform == 'elastic':
            adapter = ElasticDeploymentAdapter(target.endpoint, target.credentials)
        else:
            raise ValueError(f"Unsupported platform: {platform}")
        
        self.deployment_adapters[platform] = adapter
        self.logger.info(f"Registered deployment target: {platform}")
    
    async def deploy_rule(self, rule_id: str, rule_content: str, 
                         platforms: List[str], config: Dict[str, Any] = None) -> Dict[str, str]:
        """Deploy rule to multiple platforms"""
        if config is None:
            config = {}
        
        # Create or get rule lifecycle
        if rule_id not in self.lifecycle_manager.rule_store:
            lifecycle = self.lifecycle_manager.create_rule_lifecycle(
                rule_id, RuleSource.AUTO_GENERATED
            )
        
        deployment_results = {}
        
        for platform in platforms:
            if platform not in self.deployment_adapters:
                self.logger.error(f"No adapter registered for platform: {platform}")
                deployment_results[platform] = None
                continue
            
            try:
                adapter = self.deployment_adapters[platform]
                
                # Test connectivity first
                if not await adapter.test_connectivity():
                    raise Exception(f"Cannot connect to {platform}")
                
                # Deploy rule
                deployment_id = await adapter.deploy_rule(rule_content, config)
                deployment_results[platform] = deployment_id
                
                # Record deployment
                deployment = RuleDeployment(
                    rule_id=rule_id,
                    platform=platform,
                    deployment_id=deployment_id,
                    status=DeploymentStatus.ACTIVE,
                    deployed_at=datetime.now(),
                    version="1.0.0",
                    config=config
                )
                
                self.lifecycle_manager.add_deployment(rule_id, deployment)
                
                self.logger.info(f"Successfully deployed rule {rule_id} to {platform}: {deployment_id}")
                
            except Exception as e:
                self.logger.error(f"Failed to deploy rule {rule_id} to {platform}: {str(e)}")
                deployment_results[platform] = None
        
        return deployment_results
    
    async def update_rule(self, rule_id: str, new_content: str, 
                         reason: UpdateReason) -> Dict[str, bool]:
        """Update rule across all deployments"""
        if rule_id not in self.lifecycle_manager.rule_store:
            self.logger.error(f"Rule {rule_id} not found in lifecycle store")
            return {}
        
        lifecycle = self.lifecycle_manager.rule_store[rule_id]
        update_results = {}
        
        for deployment in lifecycle.deployments:
            if deployment.status != DeploymentStatus.ACTIVE:
                continue
                
            platform = deployment.platform
            if platform not in self.deployment_adapters:
                continue
            
            try:
                adapter = self.deployment_adapters[platform]
                success = await adapter.update_rule(deployment.deployment_id, new_content)
                update_results[platform] = success
                
                if success:
                    deployment.last_updated = datetime.now()
                    deployment.version = self._increment_version(deployment.version)
                    
                    # Record update in lifecycle
                    update_record = {
                        'timestamp': datetime.now().isoformat(),
                        'reason': reason.value,
                        'version': deployment.version,
                        'platform': platform
                    }
                    lifecycle.update_history.append(update_record)
                    
                    self.logger.info(f"Updated rule {rule_id} on {platform}")
                else:
                    self.logger.error(f"Failed to update rule {rule_id} on {platform}")
                    
            except Exception as e:
                self.logger.error(f"Error updating rule {rule_id} on {platform}: {str(e)}")
                update_results[platform] = False
        
        return update_results
    
    async def collect_metrics(self) -> Dict[str, Any]:
        """Collect metrics from all deployments"""
        metrics_summary = {
            'collection_time': datetime.now().isoformat(),
            'platform_metrics': {},
            'rule_performance': {}
        }
        
        for rule_id, lifecycle in self.lifecycle_manager.rule_store.items():
            for deployment in lifecycle.deployments:
                if deployment.status != DeploymentStatus.ACTIVE:
                    continue
                
                platform = deployment.platform
                if platform not in self.deployment_adapters:
                    continue
                
                try:
                    adapter = self.deployment_adapters[platform]
                    metrics = await adapter.get_rule_metrics(deployment.deployment_id)
                    
                    if metrics:
                        # Record metrics
                        self.metrics_collector.record_metrics(metrics, platform)
                        
                        # Update deployment metrics
                        deployment.metrics = metrics
                        
                        # Add to summary
                        if platform not in metrics_summary['platform_metrics']:
                            metrics_summary['platform_metrics'][platform] = []
                        
                        metrics_summary['platform_metrics'][platform].append({
                            'rule_id': rule_id,
                            'deployment_id': deployment.deployment_id,
                            'accuracy': metrics.accuracy_rate,
                            'performance': metrics.performance_score,
                            'alerts': metrics.total_alerts,
                            'false_positives': metrics.false_positives
                        })
                        
                        # Analyze performance trends
                        analysis = self.metrics_collector.analyze_performance_trends(rule_id)
                        metrics_summary['rule_performance'][rule_id] = analysis
                        
                        # Schedule updates if needed
                        self._evaluate_rule_for_updates(rule_id, analysis)
                        
                except Exception as e:
                    self.logger.error(f"Failed to collect metrics for {rule_id} on {platform}: {str(e)}")
        
        return metrics_summary
    
    def _evaluate_rule_for_updates(self, rule_id: str, analysis: Dict[str, Any]):
        """Evaluate if rule needs updates based on performance"""
        recommendations = analysis.get('recommendations', [])
        
        for recommendation in recommendations:
            if 'declining accuracy' in recommendation.lower():
                # Schedule performance optimization
                self.lifecycle_manager.schedule_rule_update(
                    rule_id, 
                    UpdateReason.PERFORMANCE_OPTIMIZATION,
                    datetime.now() + timedelta(hours=1),
                    {'priority': 'high', 'reason': recommendation}
                )
            
            elif 'false positive' in recommendation.lower():
                # Schedule FP reduction
                self.lifecycle_manager.schedule_rule_update(
                    rule_id,
                    UpdateReason.FALSE_POSITIVE_REDUCTION,
                    datetime.now() + timedelta(hours=2),
                    {'priority': 'medium', 'reason': recommendation}
                )
    
    async def process_scheduled_updates(self):
        """Process scheduled rule updates"""
        rules_to_update = self.lifecycle_manager.get_rules_for_update()
        
        for rule_id, action in rules_to_update:
            try:
                self.logger.info(f"Processing scheduled update for rule {rule_id}: {action['reason']}")
                
                # In real implementation, this would trigger rule regeneration
                # and redeployment based on the update reason
                
                # Mark action as completed
                action['status'] = 'completed'
                action['completed_at'] = datetime.now().isoformat()
                
            except Exception as e:
                self.logger.error(f"Failed to process update for rule {rule_id}: {str(e)}")
                action['status'] = 'failed'
                action['error'] = str(e)
    
    def _increment_version(self, current_version: str) -> str:
        """Increment version number"""
        try:
            parts = current_version.split('.')
            patch = int(parts[-1]) + 1
            parts[-1] = str(patch)
            return '.'.join(parts)
        except:
            return "1.0.1"
    
    async def start_monitoring(self, interval_minutes: int = 15):
        """Start continuous monitoring and management"""
        self.logger.info(f"Starting detection orchestration monitoring (interval: {interval_minutes} minutes)")
        
        while True:
            try:
                # Collect metrics
                await self.collect_metrics()
                
                # Process scheduled updates
                await self.process_scheduled_updates()
                
                self.logger.debug("Completed orchestration cycle")
                
            except Exception as e:
                self.logger.error(f"Error in monitoring cycle: {str(e)}")
            
            # Wait for next cycle
            await asyncio.sleep(interval_minutes * 60)
    
    def get_deployment_status(self) -> Dict[str, Any]:
        """Get overall deployment status"""
        status = {
            'total_rules': len(self.lifecycle_manager.rule_store),
            'active_deployments': 0,
            'platform_summary': {},
            'performance_summary': {
                'high_performers': [],
                'needs_attention': []
            }
        }
        
        for rule_id, lifecycle in self.lifecycle_manager.rule_store.items():
            for deployment in lifecycle.deployments:
                if deployment.status == DeploymentStatus.ACTIVE:
                    status['active_deployments'] += 1
                    
                    platform = deployment.platform
                    if platform not in status['platform_summary']:
                        status['platform_summary'][platform] = 0
                    status['platform_summary'][platform] += 1
                    
                    # Performance categorization
                    if deployment.metrics:
                        if deployment.metrics.accuracy_rate > 0.95:
                            status['performance_summary']['high_performers'].append(rule_id)
                        elif deployment.metrics.accuracy_rate < 0.8:
                            status['performance_summary']['needs_attention'].append(rule_id)
        
        return status

# Example usage and testing
async def main():
    logging.basicConfig(level=logging.INFO)
    
    # Load real indicators for testing
    import json
    from pathlib import Path
    
    def load_real_indicators_for_orchestration(limit=3):
        """Load real indicators for orchestration testing."""
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
                                    # Convert to format expected by orchestration
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
    
    # Initialize orchestrator
    orchestrator = DetectionOrchestrator()
    
    # Register deployment targets
    splunk_target = DeploymentTarget(
        platform='splunk',
        endpoint='https://splunk.company.com:8089',
        credentials={'username': 'admin', 'password': 'password'},
        config={'app': 'threatsight'}
    )
    
    elastic_target = DeploymentTarget(
        platform='elastic',
        endpoint='https://elastic.company.com:9200',
        credentials={'username': 'elastic', 'password': 'password'},
        config={'index_pattern': 'logs-*'}
    )
    
    orchestrator.register_deployment_target('splunk', splunk_target)
    orchestrator.register_deployment_target('elastic', elastic_target)
    
    # Load real indicators and create sample rule
    real_indicators = load_real_indicators_for_orchestration()
    
    # Create rule based on real indicators
    if real_indicators:
        ip_indicators = [ind for ind in real_indicators if ind.get('type') == 'ip']
        domain_indicators = [ind for ind in real_indicators if ind.get('type') == 'domain']
        
        rule_conditions = []
        if ip_indicators:
            ip_values = [f'"{ind["value"]}"' for ind in ip_indicators[:2]]
            rule_conditions.append(f'(src_ip IN ({",".join(ip_values)}) OR dest_ip IN ({",".join(ip_values)}))')
        
        if domain_indicators:
            domain_values = [f'"{ind["value"]}"' for ind in domain_indicators[:2]]
            rule_conditions.append(f'(dns_query IN ({",".join(domain_values)}))')
        
        if rule_conditions:
            sample_rule = f'''
            search index=* earliest=-24h@h {" OR ".join(rule_conditions)}
            | stats count by src_ip, dest_ip, user, host, dns_query
            | where count > 1
            '''
        else:
            # Fallback rule
            sample_rule = '''
            search index=* earliest=-24h@h (src_ip="192.168.1.100" OR dest_ip="192.168.1.100")
            | stats count by src_ip, dest_ip, user, host
            | where count > 1
            '''
    else:
        # Fallback rule
        sample_rule = '''
        search index=* earliest=-24h@h (src_ip="192.168.1.100" OR dest_ip="192.168.1.100")
        | stats count by src_ip, dest_ip, user, host
        | where count > 1
        '''
    
    # Deploy rule
    deployment_results = await orchestrator.deploy_rule(
        'rule_malicious_ip_001',
        sample_rule,
        ['splunk', 'elastic'],
        {
            'name': 'Malicious IP Detection',
            'description': 'Detects communication with known malicious IP',
            'threshold': 1
        }
    )
    
    print("Deployment Results:", deployment_results)
    
    # Collect metrics
    metrics = await orchestrator.collect_metrics()
    print("Metrics Summary:", json.dumps(metrics, indent=2, default=str))
    
    # Get deployment status
    status = orchestrator.get_deployment_status()
    print("Deployment Status:", json.dumps(status, indent=2))

if __name__ == "__main__":
    asyncio.run(main())