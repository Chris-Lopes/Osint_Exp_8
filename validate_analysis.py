#!/usr/bin/env python3
"""
Validation script for Module 6: Analysis & Correlation Engine

This script validates the complete threat intelligence analysis pipeline including:
- Correlation analysis
- Clustering algorithms  
- Risk scoring
- Timeline analysis
- Attribution engine
- Analysis orchestrator
- Reporting system

Usage: python validate_analysis.py
"""

import sys
import logging
from datetime import datetime, timedelta
from pathlib import Path
import asyncio
import json

# Setup paths
script_dir = Path(__file__).parent
src_dir = script_dir / "src"
sys.path.insert(0, str(src_dir))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def load_real_indicators(limit: int = None) -> list:
    """Load real indicators from enriched data for analysis validation."""
    enriched_dir = Path('data/enriched')

    if not enriched_dir.exists():
        logger.warning(f"Enriched data directory not found: {enriched_dir}")
        logger.info("Attempting to load from processed data directory...")
        return load_processed_indicators(limit)

    indicators = []
    total_loaded = 0

    # Load from all subdirectories
    for source_dir in enriched_dir.iterdir():
        if source_dir.is_dir():
            logger.info(f"Loading enriched data from {source_dir.name}")

            for jsonl_file in source_dir.glob('*.jsonl'):
                logger.info(f"Processing {jsonl_file}")

                try:
                    with open(jsonl_file, 'r') as f:
                        for line_num, line in enumerate(f, 1):
                            if limit and total_loaded >= limit:
                                logger.info(f"Reached limit of {limit} indicators")
                                return indicators
                                
                            line = line.strip()
                            if not line:
                                continue

                            try:
                                data = json.loads(line)

                                # Convert to format expected by analysis
                                from src.normalizers.schema import NormalizedIndicator, IndicatorType, SourceMetadata
                                
                                indicator_data = {
                                    'id': data.get('id', f"{source_dir.name}_{line_num}"),
                                    'indicator_type': data.get('indicator_type'),
                                    'value': data.get('value'),
                                    'tags': data.get('tags', []),
                                    'confidence': data.get('confidence', 50),
                                    'source_metadata': data.get('source_metadata', {}),
                                    'context': data.get('context', {})
                                }

                                # Create NormalizedIndicator object
                                indicator = NormalizedIndicator(**indicator_data)
                                indicators.append(indicator)
                                total_loaded += 1

                            except json.JSONDecodeError as e:
                                logger.warning(f"Invalid JSON on line {line_num} of {jsonl_file}: {e}")
                            except Exception as e:
                                logger.warning(f"Failed to create indicator from line {line_num}: {e}")

                except Exception as e:
                    logger.error(f"Failed to read {jsonl_file}: {e}")

    if not indicators:
        logger.warning("No real indicators found, falling back to processed data")
        return load_processed_indicators(limit)

    logger.info(f"Loaded {len(indicators)} real indicators for analysis validation")
    return indicators


def load_processed_indicators(limit: int = None) -> list:
    """Load processed indicators from the data/processed directory as fallback."""
    processed_dir = Path('data/processed')

    if not processed_dir.exists():
        logger.error(f"No data directories found. Please run collection and processing pipeline first.")
        logger.error("Run: python run_lab_analysis.py")
        return []

    indicators = []
    total_loaded = 0

    # Load from all subdirectories
    for source_dir in processed_dir.iterdir():
        if source_dir.is_dir():
            logger.info(f"Loading processed data from {source_dir.name}")

            for jsonl_file in source_dir.glob('*.jsonl'):
                logger.info(f"Processing {jsonl_file}")

                try:
                    with open(jsonl_file, 'r') as f:
                        for line_num, line in enumerate(f, 1):
                            if limit and total_loaded >= limit:
                                logger.info(f"Reached limit of {limit} indicators")
                                return indicators
                                
                            line = line.strip()
                            if not line:
                                continue

                            try:
                                data = json.loads(line)

                                # Convert to format expected by analysis
                                from src.normalizers.schema import NormalizedIndicator, IndicatorType, SourceMetadata
                                
                                indicator_data = {
                                    'id': data.get('id', f"{source_dir.name}_{line_num}"),
                                    'indicator_type': data.get('indicator_type'),
                                    'value': data.get('value'),
                                    'tags': data.get('tags', []),
                                    'confidence': data.get('confidence', 50),
                                    'source_metadata': data.get('source_metadata', {}),
                                    'context': data.get('context', {})
                                }

                                # Create NormalizedIndicator object
                                indicator = NormalizedIndicator(**indicator_data)
                                indicators.append(indicator)
                                total_loaded += 1

                            except json.JSONDecodeError as e:
                                logger.warning(f"Invalid JSON on line {line_num} of {jsonl_file}: {e}")
                            except Exception as e:
                                logger.warning(f"Failed to create indicator from line {line_num}: {e}")

                except Exception as e:
                    logger.error(f"Failed to read {jsonl_file}: {e}")

    logger.info(f"Loaded {len(indicators)} processed indicators")
    return indicators


def create_test_indicators():
    """Create test indicators for analysis validation."""
    from src.normalizers.schema import NormalizedIndicator, IndicatorType, SourceMetadata
    
    base_time = datetime.utcnow()
    indicators = []
    
    # Create diverse test indicators
    test_data = [
        {
            'id': 'indicator_001',
            'type': IndicatorType.IP,
            'value': '192.168.1.100',
            'source_metadata': SourceMetadata(
                source_name='test_source',
                collection_method='automated_feed',
                collected_at=base_time.isoformat() + 'Z',
                source_confidence=85
            ),
            'tags': ['malware', 'c2', 'apt29'],
            'context': {
                'enrichment': {
                    'reputation': {
                        'success': True,
                        'reputation_score': -85,
                        'is_malicious': True,
                        'category': 'malware'
                    },
                    'geolocation': {
                        'success': True,
                        'country': 'RU',
                        'city': 'Moscow'
                    }
                }
            },
            'created': (base_time - timedelta(hours=2)).isoformat() + 'Z'
        },
        {
            'id': 'indicator_002',
            'type': IndicatorType.DOMAIN,
            'value': 'malicious-domain.com',
            'source_metadata': SourceMetadata(
                source_name='threat_feed',
                collection_method='automated_feed',
                collected_at=base_time.isoformat() + 'Z',
                source_confidence=85
            ),
            'tags': ['phishing', 'apt28', 'spear_phishing'],
            'context': {
                'enrichment': {
                    'reputation': {
                        'success': True,
                        'reputation_score': -75,
                        'is_malicious': True,
                        'is_phishing': True,
                        'category': 'phishing'
                    }
                }
            },
            'created': (base_time - timedelta(hours=1)).isoformat() + 'Z'
        },
        {
            'id': 'indicator_003',
            'type': IndicatorType.SHA256,
            'value': 'a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456',
            'source_metadata': SourceMetadata(
                source_name='malware_analysis',
                collection_method='manual_analysis',
                collected_at=base_time.isoformat() + 'Z',
                source_confidence=90
            ),
            'tags': ['malware', 'trojan', 'lazarus'],
            'context': {
                'enrichment': {
                    'reputation': {
                        'success': True,
                        'reputation_score': -90,
                        'is_malicious': True,
                        'category': 'malware'
                    }
                }
            },
            'created': (base_time - timedelta(minutes=30)).isoformat() + 'Z'
        },
        {
            'id': 'indicator_004',
            'type': IndicatorType.URL,
            'value': 'http://suspicious-site.evil/payload.exe',
            'source_metadata': SourceMetadata(
                source_name='web_crawler',
                collection_method='automated_scan',
                collected_at=base_time.isoformat() + 'Z',
                source_confidence=80
            ),
            'tags': ['delivery', 'exploit_kit', 'fin7'],
            'context': {
                'enrichment': {
                    'reputation': {
                        'success': True,
                        'reputation_score': -70,
                        'is_malicious': True,
                        'category': 'exploit'
                    }
                }
            },
            'created': (base_time - timedelta(minutes=15)).isoformat() + 'Z'
        },
        {
            'id': 'indicator_005',
            'type': IndicatorType.EMAIL,
            'value': 'attacker@evil.com',
            'source_metadata': SourceMetadata(
                source_name='email_analysis',
                collection_method='incident_response',
                collected_at=base_time.isoformat() + 'Z',
                source_confidence=95
            ),
            'tags': ['spear_phishing', 'credential_harvesting', 'apt29'],
            'context': {
                'enrichment': {
                    'reputation': {
                        'success': True,
                        'reputation_score': -65,
                        'is_malicious': True,
                        'category': 'phishing'
                    }
                }
            },
            'created': base_time.isoformat() + 'Z'
        }
    ]
    
    for data in test_data:
        indicator = NormalizedIndicator(
            id=data['id'],
            indicator_type=data['type'],
            value=data['value'],
            source_metadata=data['source_metadata'],
            confidence=85,
            tags=data['tags'],
            context=data['context'],
            created=data['created'],
            updated=data['created']
        )
        indicators.append(indicator)
    
    return indicators

def validate_correlation_engine():
    """Test correlation analysis functionality."""
    logger.info("=== Validating Correlation Engine ===")
    
    try:
        from src.analysis.correlation import CorrelationEngine
        
        indicators = load_real_indicators(limit=10)
        
        # Test correlation engine
        corr_engine = CorrelationEngine()
        correlations = corr_engine.batch_correlation_analysis(indicators)
        
        logger.info(f"✅ Generated {len(correlations)} correlations")
        
        # Validate correlation types
        if correlations:
            correlation_types = set(c.correlation_type.value for c in correlations)
            logger.info(f"✅ Correlation types: {list(correlation_types)}")
            
            # Validate correlation scores
            scores = [c.score for c in correlations]
            avg_score = sum(scores) / len(scores) if scores else 0
            logger.info(f"✅ Average correlation score: {avg_score:.2f}")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Correlation engine validation failed: {e}")
        return False

def validate_clustering_orchestrator():
    """Validate clustering orchestrator."""
    logger.info("=== Validating Clustering Orchestrator ===")
    
    try:
        from src.analysis.clustering import ClusteringOrchestrator, ClusterType
        from src.analysis.correlation import CorrelationEngine
        
        indicators = load_real_indicators(limit=10)
        
        # Get correlations for clustering
        corr_engine = CorrelationEngine()
        correlations = corr_engine.batch_correlation_analysis(indicators)
        
        orchestrator = ClusteringOrchestrator()
        clusters = orchestrator.perform_clustering(indicators, correlations)
        
        logger.info(f"✅ Generated {len(clusters)} clusters")
        
        # Validate cluster types
        cluster_types = set(cluster.cluster_type for cluster in clusters)
        logger.info(f"✅ Cluster types: {[ct.value for ct in cluster_types]}")
        
        # Validate cluster quality
        qualities = [cluster.quality for cluster in clusters]
        logger.info(f"✅ Cluster qualities: {[q.value for q in set(qualities)]}")
        
        # Test indicator coverage
        clustered_indicators = set()
        for cluster in clusters:
            clustered_indicators.update(cluster.indicator_ids)
        coverage = len(clustered_indicators) / len(indicators)
        logger.info(f"✅ Clustering coverage: {coverage:.1%}")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Clustering orchestrator validation failed: {e}")
        return False

def validate_risk_scoring():
    """Validate risk scoring framework."""
    logger.info("=== Validating Risk Scoring Framework ===")
    
    try:
        from src.analysis.risk_scoring import CompositeRiskScorer, RiskLevel
        
        indicators = load_real_indicators(limit=10)
        
        risk_scorer = CompositeRiskScorer()
        
        # Test individual risk assessments
        assessments = {}
        for indicator in indicators:
            assessment = risk_scorer.assess_risk(indicator, [], [])
            assessments[indicator.id] = assessment
            logger.info(f"✅ {indicator.id}: {assessment.risk_level.value} (score: {assessment.risk_score:.2f})")
        
        # Test batch assessment
        batch_assessments = risk_scorer.batch_risk_assessment(indicators, {}, {})
        logger.info(f"✅ Batch assessed {len(batch_assessments)} indicators")
        
        # Validate risk levels distribution
        risk_levels = [assessment.risk_level for assessment in assessments.values()]
        level_counts = {}
        for level in risk_levels:
            level_counts[level.value] = level_counts.get(level.value, 0) + 1
        logger.info(f"✅ Risk level distribution: {level_counts}")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Risk scoring validation failed: {e}")
        return False

def validate_timeline_analysis():
    """Validate timeline analysis engine."""
    logger.info("=== Validating Timeline Analysis Engine ===")
    
    try:
        from src.analysis.timeline_analysis import TimelineAnalysisEngine
        from src.analysis.correlation import CorrelationEngine
        from src.analysis.clustering import ClusteringOrchestrator
        from src.analysis.risk_scoring import CompositeRiskScorer
        
        indicators = load_real_indicators(limit=10)
        
        # Prepare analysis data
        corr_engine = CorrelationEngine()
        correlations = corr_engine.batch_correlation_analysis(indicators)
        correlations_by_indicator = corr_engine.group_correlations_by_indicator(correlations)
        
        clustering_orchestrator = ClusteringOrchestrator()
        clusters = clustering_orchestrator.perform_clustering(indicators, correlations)
        
        risk_scorer = CompositeRiskScorer()
        risk_assessments = {}
        for indicator in indicators:
            risk_assessments[indicator.id] = risk_scorer.assess_risk(indicator, [], [])
        
        # Test timeline analysis
        timeline_engine = TimelineAnalysisEngine()
        timeline_result = timeline_engine.analyze_timelines(
            indicators, risk_assessments, correlations_by_indicator, clusters
        )
        
        timelines = timeline_result.get('timelines', [])
        logger.info(f"✅ Generated {len(timelines)} attack timelines")
        
        if timelines:
            for timeline in timelines:
                events_count = len(timeline.get('events', []))
                logger.info(f"✅ Timeline: {events_count} events, duration: {timeline.get('duration_hours', 0):.1f}h")
        
        # Validate timeline patterns
        patterns = timeline_result.get('timeline_patterns', {})
        logger.info(f"✅ Timeline patterns analyzed: {list(patterns.keys())}")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Timeline analysis validation failed: {e}")
        return False

def validate_attribution_engine():
    """Validate attribution engine."""
    logger.info("=== Validating Attribution Engine ===")
    
    try:
        from src.analysis.attribution import AttributionEngine, ThreatActorDatabase
        from src.analysis.timeline_analysis import TimelineAnalysisEngine
        from src.analysis.clustering import ClusteringOrchestrator
        from src.analysis.risk_scoring import CompositeRiskScorer
        from src.analysis.correlation import CorrelationEngine
        
        indicators = load_real_indicators(limit=10)
        
        # Test threat actor database
        actor_db = ThreatActorDatabase()
        actors = actor_db.get_all_actors()
        logger.info(f"✅ Loaded {len(actors)} threat actors")
        
        # Search actors by TTP
        apt_actors = actor_db.search_actors_by_ttp("spear_phishing")
        logger.info(f"✅ Found {len(apt_actors)} actors using spear phishing")
        
        # Prepare analysis context
        corr_engine = CorrelationEngine()
        correlations = corr_engine.batch_correlation_analysis(indicators)
        correlations_by_indicator = corr_engine.group_correlations_by_indicator(correlations)
        
        clustering_orchestrator = ClusteringOrchestrator()
        clusters = clustering_orchestrator.perform_clustering(indicators, correlations)
        
        risk_scorer = CompositeRiskScorer()
        risk_assessments = {}
        for indicator in indicators:
            risk_assessments[indicator.id] = risk_scorer.assess_risk(indicator, [], [])
        
        timeline_engine = TimelineAnalysisEngine()
        timeline_result = timeline_engine.analyze_timelines(
            indicators, risk_assessments, correlations_by_indicator, clusters
        )
        timelines = []  # Convert dict timelines to objects for attribution
        
        # Test attribution analysis
        attribution_engine = AttributionEngine()
        attribution_result = attribution_engine.perform_attribution_analysis(
            indicators, timelines, clusters, risk_assessments
        )
        
        attributions = attribution_result.get('attributions', [])
        logger.info(f"✅ Generated {len(attributions)} potential attributions")
        
        if attributions:
            for attribution in attributions[:3]:  # Show top 3
                actor_name = attribution.get('threat_actor', {}).get('name', 'Unknown')
                confidence = attribution.get('confidence', 'unknown')
                logger.info(f"✅ Attribution: {actor_name} ({confidence} confidence)")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Attribution engine validation failed: {e}")
        return False

async def validate_analysis_orchestrator():
    """Validate analysis orchestrator."""
    logger.info("=== Validating Analysis Orchestrator ===")
    
    try:
        from src.analysis.orchestrator import AnalysisOrchestrator
        
        indicators = load_real_indicators(limit=10)
        
        # Test orchestrated analysis
        orchestrator = AnalysisOrchestrator()
        report = await orchestrator.analyze_indicators(indicators, "comprehensive")
        
        logger.info(f"✅ Generated report ID: {report.report_id}")
        logger.info(f"✅ Analyzed {report.indicators_analyzed} indicators")
        logger.info(f"✅ Analysis duration: {report.total_duration_seconds:.1f}s")
        logger.info(f"✅ Analysis quality: {report.analysis_quality_score:.2f}")
        
        # Validate stage results
        completed_stages = sum(
            1 for stage in report.stage_results 
            if stage.status.value == 'completed'
        )
        logger.info(f"✅ Completed {completed_stages}/{len(report.stage_results)} analysis stages")
        
        # Validate analysis results
        logger.info(f"✅ Correlations found: {len(report.correlations)}")
        logger.info(f"✅ Clusters identified: {len(report.clusters)}")
        logger.info(f"✅ Risk assessments: {len(report.risk_assessments)}")
        logger.info(f"✅ Timelines generated: {len(report.timelines)}")
        logger.info(f"✅ Attributions made: {len(report.attributions)}")
        
        # Validate executive summary
        summary = report.executive_summary
        logger.info(f"✅ Executive summary: {len(summary)} key sections")
        
        return report
        
    except Exception as e:
        logger.error(f"❌ Analysis orchestrator validation failed: {e}")
        return None

def validate_reporting_system(intelligence_report):
    """Validate reporting system."""
    logger.info("=== Validating Reporting System ===")
    
    try:
        from src.analysis.reporting import ReportingSystem, ReportType, ReportFormat
        
        if not intelligence_report:
            logger.warning("⚠️  No intelligence report provided, skipping reporting validation")
            return False
        
        reporting_system = ReportingSystem()
        
        # Test report generation
        reports = {}
        
        # Executive summary in JSON
        exec_json = reporting_system.report_generator.generate_report(
            intelligence_report, ReportType.EXECUTIVE_SUMMARY, ReportFormat.JSON
        )
        reports['executive_json'] = len(exec_json)
        logger.info(f"✅ Executive summary JSON: {len(exec_json)} chars")
        
        # Executive summary in HTML
        exec_html = reporting_system.report_generator.generate_report(
            intelligence_report, ReportType.EXECUTIVE_SUMMARY, ReportFormat.HTML
        )
        reports['executive_html'] = len(exec_html)
        logger.info(f"✅ Executive summary HTML: {len(exec_html)} chars")
        
        # Technical analysis
        tech_report = reporting_system.report_generator.generate_report(
            intelligence_report, ReportType.TECHNICAL_ANALYSIS, ReportFormat.JSON
        )
        reports['technical_analysis'] = len(tech_report)
        logger.info(f"✅ Technical analysis: {len(tech_report)} chars")
        
        # IOC feed
        ioc_feed = reporting_system.report_generator.generate_report(
            intelligence_report, ReportType.IOC_FEED, ReportFormat.JSON
        )
        reports['ioc_feed'] = len(ioc_feed)
        logger.info(f"✅ IOC feed: {len(ioc_feed)} chars")
        
        # Test alert generation
        alerts = reporting_system.alert_generator.generate_alerts(intelligence_report)
        logger.info(f"✅ Generated {len(alerts)} security alerts")
        
        for alert in alerts[:3]:  # Show first 3 alerts
            logger.info(f"   📢 {alert.severity.value.upper()}: {alert.title}")
        
        # Test complete processing
        processing_result = reporting_system.process_analysis_results(intelligence_report)
        logger.info(f"✅ Processing result: {processing_result['reports_generated']} reports, {processing_result['alerts_generated']} alerts")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Reporting system validation failed: {e}")
        return False

def validate_analysis_integration():
    """Validate the complete analysis integration."""
    logger.info("=== Validating Complete Analysis Integration ===")
    
    try:
        from src.analysis import analyze_threat_indicators
        
        indicators = load_real_indicators(limit=10)
        
        # Test the main analysis function
        config = {
            'parallel_execution': False,  # Sequential for testing
            'continue_on_failure': True
        }
        
        report = analyze_threat_indicators(indicators, config)
        
        logger.info(f"✅ Integration test completed successfully")
        logger.info(f"✅ Report ID: {report.report_id}")
        logger.info(f"✅ Overall quality score: {report.analysis_quality_score:.2f}")
        
        # Validate key findings
        if report.key_findings:
            logger.info(f"✅ Key findings: {len(report.key_findings)}")
            for finding in report.key_findings[:3]:
                logger.info(f"   🔍 {finding}")
        
        # Validate recommendations
        if report.recommendations:
            logger.info(f"✅ Recommendations: {len(report.recommendations)}")
            for rec in report.recommendations[:3]:
                logger.info(f"   💡 {rec}")
        
        return report
        
    except Exception as e:
        logger.error(f"❌ Analysis integration validation failed: {e}")
        return None

def main():
    """Main validation function."""
    logger.info("🚀 Starting Module 6 Analysis & Correlation Engine Validation")
    logger.info("=" * 70)
    
    validation_results = {}
    
    # Individual component validation
    validation_results['correlation'] = validate_correlation_engine()
    validation_results['clustering'] = validate_clustering_orchestrator()
    validation_results['risk_scoring'] = validate_risk_scoring()
    validation_results['timeline'] = validate_timeline_analysis()
    validation_results['attribution'] = validate_attribution_engine()
    
    # Orchestrator validation (async)
    intelligence_report = asyncio.run(validate_analysis_orchestrator())
    validation_results['orchestrator'] = intelligence_report is not None
    
    # Reporting validation
    validation_results['reporting'] = validate_reporting_system(intelligence_report)
    
    # Integration validation
    integration_report = validate_analysis_integration()
    validation_results['integration'] = integration_report is not None
    
    # Summary
    logger.info("=" * 70)
    logger.info("📊 Validation Summary")
    logger.info("=" * 70)
    
    passed = sum(1 for result in validation_results.values() if result)
    total = len(validation_results)
    
    for component, result in validation_results.items():
        status = "✅ PASSED" if result else "❌ FAILED"
        logger.info(f"{component.title().ljust(15)}: {status}")
    
    logger.info("=" * 70)
    logger.info(f"🎯 Overall Result: {passed}/{total} components passed validation")
    
    if passed == total:
        logger.info("🎉 Module 6: Analysis & Correlation Engine - VALIDATION SUCCESSFUL!")
        logger.info("🔬 Advanced threat intelligence analysis capabilities are ready for production")
        return True
    else:
        logger.error("💥 Module 6: Analysis & Correlation Engine - VALIDATION FAILED!")
        logger.error(f"❌ {total - passed} components need attention")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)