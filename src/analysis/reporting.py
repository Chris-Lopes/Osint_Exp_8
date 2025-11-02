"""
Analysis reporting system for threat intelligence.

This module creates comprehensive reporting capabilities that generate threat intelligence
reports, dashboards, and alerts from analysis results. It provides multiple output
formats and visualization capabilities for different stakeholders.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import json
import csv
import io
from collections import defaultdict, Counter

try:
    from ..normalizers.schema import NormalizedIndicator
    from .orchestrator import ThreatIntelligenceReport, AnalysisStageResult
    from .risk_scoring import RiskAssessment, RiskLevel, ThreatCategory
    from .timeline_analysis import AttackTimeline, TimelineEvent
    from .attribution import Attribution, AttributionConfidence
    from .clustering import IndicatorCluster, ClusterType
    from .correlation import CorrelationResult, CorrelationStrength
except ImportError:
    from normalizers.schema import NormalizedIndicator
    from analysis.orchestrator import ThreatIntelligenceReport, AnalysisStageResult
    from analysis.risk_scoring import RiskAssessment, RiskLevel, ThreatCategory
    from analysis.timeline_analysis import AttackTimeline, TimelineEvent
    from analysis.attribution import Attribution, AttributionConfidence
    from analysis.clustering import IndicatorCluster, ClusterType
    from analysis.correlation import CorrelationResult, CorrelationStrength

logger = logging.getLogger(__name__)


class ReportFormat(Enum):
    """Available report formats."""
    JSON = "json"
    HTML = "html"
    PDF = "pdf"
    CSV = "csv"
    STIX = "stix"
    MISP = "misp"
    MARKDOWN = "markdown"


class ReportType(Enum):
    """Types of reports."""
    EXECUTIVE_SUMMARY = "executive_summary"
    TECHNICAL_ANALYSIS = "technical_analysis"
    IOC_FEED = "ioc_feed"
    ATTRIBUTION_REPORT = "attribution_report"
    TIMELINE_REPORT = "timeline_report"
    RISK_ASSESSMENT = "risk_assessment"
    COMPREHENSIVE = "comprehensive"


class AlertSeverity(Enum):
    """Alert severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


@dataclass
class Alert:
    """Security alert generated from analysis."""
    alert_id: str
    title: str
    severity: AlertSeverity
    description: str
    
    # Alert metadata
    timestamp: datetime
    source_analysis: str  # Analysis report ID
    
    # Related indicators and evidence
    indicators: List[str]
    evidence: Dict[str, Any]
    
    # Response information
    recommended_actions: List[str]
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            'alert_id': self.alert_id,
            'title': self.title,
            'severity': self.severity.value,
            'description': self.description,
            'timestamp': self.timestamp.isoformat(),
            'source_analysis': self.source_analysis,
            'indicators': self.indicators,
            'evidence': self.evidence,
            'recommended_actions': self.recommended_actions,
            'mitre_tactics': self.mitre_tactics,
            'mitre_techniques': self.mitre_techniques
        }


class ReportGenerator:
    """Generates threat intelligence reports in various formats."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize report generator."""
        self.config = config or {}
        
        # Report configuration
        self.template_dir = self.config.get('template_dir', 'templates')
        self.output_dir = self.config.get('output_dir', 'reports')
        self.organization_name = self.config.get('organization_name', 'Threat Intelligence Team')
        
        # Formatting options
        self.max_indicators_per_report = self.config.get('max_indicators_per_report', 1000)
        self.include_raw_data = self.config.get('include_raw_data', False)
        
        logger.info("Report generator initialized")
    
    def generate_report(self, intelligence_report: ThreatIntelligenceReport,
                       report_type: ReportType,
                       format_type: ReportFormat) -> str:
        """Generate a report in the specified format."""
        
        logger.info(f"Generating {report_type.value} report in {format_type.value} format")
        
        # Generate report content based on type
        if report_type == ReportType.EXECUTIVE_SUMMARY:
            content = self._generate_executive_summary_content(intelligence_report)
        elif report_type == ReportType.TECHNICAL_ANALYSIS:
            content = self._generate_technical_analysis_content(intelligence_report)
        elif report_type == ReportType.IOC_FEED:
            content = self._generate_ioc_feed_content(intelligence_report)
        elif report_type == ReportType.ATTRIBUTION_REPORT:
            content = self._generate_attribution_report_content(intelligence_report)
        elif report_type == ReportType.TIMELINE_REPORT:
            content = self._generate_timeline_report_content(intelligence_report)
        elif report_type == ReportType.RISK_ASSESSMENT:
            content = self._generate_risk_assessment_content(intelligence_report)
        else:  # COMPREHENSIVE
            content = self._generate_comprehensive_content(intelligence_report)
        
        # Format the content
        if format_type == ReportFormat.JSON:
            return self._format_as_json(content)
        elif format_type == ReportFormat.HTML:
            return self._format_as_html(content, report_type)
        elif format_type == ReportFormat.MARKDOWN:
            return self._format_as_markdown(content, report_type)
        elif format_type == ReportFormat.CSV:
            return self._format_as_csv(content, report_type)
        elif format_type == ReportFormat.STIX:
            return self._format_as_stix(content)
        else:
            # Default to JSON
            return self._format_as_json(content)
    
    def _generate_executive_summary_content(self, report: ThreatIntelligenceReport) -> Dict[str, Any]:
        """Generate executive summary content."""
        
        # Key metrics
        total_indicators = report.indicators_analyzed
        high_risk_count = sum(
            1 for assessment in report.risk_assessments.values()
            if assessment.risk_level in {RiskLevel.CRITICAL, RiskLevel.HIGH}
        )
        
        critical_alerts = sum(
            1 for assessment in report.risk_assessments.values()
            if assessment.risk_level == RiskLevel.CRITICAL
        )
        
        # Campaign analysis
        campaigns_identified = len([t for t in report.timelines if t.campaign_name])
        
        # Attribution summary
        high_confidence_attributions = sum(
            1 for attr in report.attributions
            if attr.confidence in {AttributionConfidence.HIGH, AttributionConfidence.VERY_HIGH}
        )
        
        return {
            'report_metadata': {
                'report_id': report.report_id,
                'analysis_timestamp': report.analysis_timestamp,
                'analysis_scope': report.analysis_scope,
                'organization': self.organization_name
            },
            'key_metrics': {
                'total_indicators_analyzed': total_indicators,
                'high_risk_indicators': high_risk_count,
                'critical_threats': critical_alerts,
                'attack_campaigns_identified': campaigns_identified,
                'threat_actor_attributions': len(report.attributions),
                'high_confidence_attributions': high_confidence_attributions
            },
            'threat_landscape': {
                'primary_threat_categories': self._get_top_threat_categories(report),
                'geographic_distribution': self._get_geographic_distribution(report),
                'attack_timeline_summary': self._get_timeline_summary(report)
            },
            'risk_assessment': {
                'overall_risk_level': self._calculate_overall_risk_level(report),
                'immediate_threats': critical_alerts,
                'trending_risks': self._identify_trending_risks(report)
            },
            'recommendations': {
                'immediate_actions': self._get_immediate_actions(report),
                'strategic_recommendations': self._get_strategic_recommendations(report)
            }
        }
    
    def _generate_technical_analysis_content(self, report: ThreatIntelligenceReport) -> Dict[str, Any]:
        """Generate detailed technical analysis content."""
        
        return {
            'analysis_overview': {
                'methodology': 'Multi-stage threat intelligence analysis',
                'analysis_stages': [sr.stage.value for sr in report.stage_results],
                'analysis_quality_score': report.analysis_quality_score,
                'total_duration': report.total_duration_seconds
            },
            'correlation_analysis': {
                'total_correlations': len(report.correlations),
                'correlation_types': self._analyze_correlation_types(report.correlations),
                'strong_correlations': self._get_strong_correlations(report.correlations),
                'correlation_network': self._build_correlation_network(report.correlations)
            },
            'clustering_analysis': {
                'total_clusters': len(report.clusters),
                'cluster_types': self._analyze_cluster_types(report.clusters),
                'largest_clusters': self._get_largest_clusters(report.clusters),
                'cluster_quality_distribution': self._analyze_cluster_quality(report.clusters)
            },
            'risk_analysis': {
                'risk_distribution': self._analyze_risk_distribution(report.risk_assessments),
                'top_risk_factors': self._get_top_risk_factors(report.risk_assessments),
                'risk_correlation_matrix': self._build_risk_correlation_matrix(report)
            },
            'temporal_analysis': {
                'timeline_statistics': self._analyze_timeline_statistics(report.timelines),
                'attack_phase_distribution': self._analyze_attack_phases(report.timelines),
                'activity_patterns': self._analyze_activity_patterns(report.timelines)
            },
            'attribution_analysis': {
                'attribution_confidence_distribution': self._analyze_attribution_confidence(report.attributions),
                'threat_actor_profiles': self._get_threat_actor_profiles(report.attributions),
                'attribution_evidence_analysis': self._analyze_attribution_evidence(report.attributions)
            }
        }
    
    def _generate_ioc_feed_content(self, report: ThreatIntelligenceReport) -> Dict[str, Any]:
        """Generate IOC feed content."""
        
        iocs = []
        
        for indicator_id, assessment in report.risk_assessments.items():
            # Find the original indicator (this would need to be passed in or stored)
            ioc_entry = {
                'indicator_id': indicator_id,
                'type': 'unknown',  # Would need original indicator data
                'value': 'unknown',  # Would need original indicator data
                'risk_score': assessment.risk_score,
                'risk_level': assessment.risk_level.value,
                'confidence': assessment.confidence,
                'first_seen': assessment.assessment_timestamp.isoformat(),
                'last_seen': assessment.assessment_timestamp.isoformat(),
                'tags': [],
                'threat_categories': [assessment.threat_category.value],
                'recommended_actions': assessment.recommended_actions
            }
            
            # Add cluster information
            if assessment.cluster_memberships:
                ioc_entry['cluster_ids'] = assessment.cluster_memberships
            
            # Add correlation information
            ioc_entry['correlation_count'] = assessment.correlation_count
            
            iocs.append(ioc_entry)
        
        return {
            'feed_metadata': {
                'feed_id': f"ioc_feed_{report.report_id}",
                'generation_time': datetime.utcnow().isoformat(),
                'source': self.organization_name,
                'total_indicators': len(iocs)
            },
            'indicators': iocs,
            'feed_statistics': {
                'risk_level_distribution': Counter(ioc['risk_level'] for ioc in iocs),
                'threat_category_distribution': Counter(
                    cat for ioc in iocs for cat in ioc['threat_categories']
                )
            }
        }
    
    def _generate_attribution_report_content(self, report: ThreatIntelligenceReport) -> Dict[str, Any]:
        """Generate attribution-focused report content."""
        
        return {
            'attribution_summary': {
                'total_attributions': len(report.attributions),
                'unique_threat_actors': len(set(attr.threat_actor.actor_id for attr in report.attributions)),
                'high_confidence_attributions': sum(
                    1 for attr in report.attributions
                    if attr.confidence in {AttributionConfidence.HIGH, AttributionConfidence.VERY_HIGH}
                )
            },
            'threat_actor_analysis': {
                'identified_actors': [
                    {
                        'actor_name': attr.threat_actor.name,
                        'actor_type': attr.threat_actor.actor_type.value,
                        'confidence': attr.confidence.value,
                        'confidence_score': attr.confidence_score,
                        'matching_ttps': attr.matching_ttps,
                        'infrastructure_overlap': attr.infrastructure_overlap,
                        'campaign_name': attr.campaign_name
                    }
                    for attr in report.attributions
                ],
                'actor_type_distribution': Counter(
                    attr.threat_actor.actor_type.value for attr in report.attributions
                ),
                'confidence_distribution': Counter(
                    attr.confidence.value for attr in report.attributions
                )
            },
            'ttp_analysis': {
                'observed_ttps': list(set(
                    ttp for attr in report.attributions for ttp in attr.matching_ttps
                )),
                'ttp_frequency': Counter(
                    ttp for attr in report.attributions for ttp in attr.matching_ttps
                )
            },
            'campaign_mapping': [
                {
                    'campaign_name': attr.campaign_name,
                    'threat_actor': attr.threat_actor.name,
                    'confidence': attr.confidence.value,
                    'evidence_types': [e.evidence_type for e in attr.evidence]
                }
                for attr in report.attributions if attr.campaign_name
            ]
        }
    
    def _generate_timeline_report_content(self, report: ThreatIntelligenceReport) -> Dict[str, Any]:
        """Generate timeline-focused report content."""
        
        return {
            'timeline_overview': {
                'total_timelines': len(report.timelines),
                'total_events': sum(len(timeline.events) for timeline in report.timelines),
                'date_range': self._get_timeline_date_range(report.timelines),
                'campaigns_with_timelines': sum(1 for t in report.timelines if t.campaign_name)
            },
            'attack_progression': [
                {
                    'timeline_id': timeline.timeline_id,
                    'campaign_name': timeline.campaign_name,
                    'start_time': timeline.start_time.isoformat(),
                    'end_time': timeline.end_time.isoformat(),
                    'duration_hours': timeline.duration.total_seconds() / 3600,
                    'event_count': len(timeline.events),
                    'attack_phases': [phase.value for phase in timeline.attack_phases],
                    'escalation_detected': timeline.escalation_detected,
                    'activity_pattern': timeline.activity_pattern
                }
                for timeline in report.timelines
            ],
            'temporal_patterns': {
                'activity_pattern_distribution': Counter(
                    timeline.activity_pattern for timeline in report.timelines
                ),
                'escalation_frequency': sum(
                    1 for timeline in report.timelines if timeline.escalation_detected
                ),
                'average_campaign_duration': sum(
                    timeline.duration.total_seconds() for timeline in report.timelines
                ) / (len(report.timelines) * 3600) if report.timelines else 0
            },
            'event_analysis': {
                'event_type_frequency': self._analyze_event_types(report.timelines),
                'attack_phase_progression': self._analyze_phase_progression(report.timelines),
                'pivotal_events': self._identify_pivotal_events(report.timelines)
            }
        }
    
    def _generate_risk_assessment_content(self, report: ThreatIntelligenceReport) -> Dict[str, Any]:
        """Generate risk assessment report content."""
        
        return {
            'risk_overview': {
                'total_indicators_assessed': len(report.risk_assessments),
                'risk_distribution': Counter(
                    assessment.risk_level.value for assessment in report.risk_assessments.values()
                ),
                'average_risk_score': sum(
                    assessment.risk_score for assessment in report.risk_assessments.values()
                ) / len(report.risk_assessments) if report.risk_assessments else 0,
                'high_priority_indicators': sum(
                    1 for assessment in report.risk_assessments.values()
                    if assessment.priority_score >= 80
                )
            },
            'threat_categorization': {
                'category_distribution': Counter(
                    assessment.threat_category.value for assessment in report.risk_assessments.values()
                ),
                'category_risk_correlation': self._analyze_category_risk_correlation(report.risk_assessments)
            },
            'risk_factors': {
                'most_common_risk_factors': self._analyze_common_risk_factors(report.risk_assessments),
                'high_impact_factors': self._identify_high_impact_factors(report.risk_assessments)
            },
            'priority_actions': {
                'critical_indicators': [
                    {
                        'indicator_id': indicator_id,
                        'risk_score': assessment.risk_score,
                        'priority_score': assessment.priority_score,
                        'recommended_actions': assessment.recommended_actions
                    }
                    for indicator_id, assessment in report.risk_assessments.items()
                    if assessment.risk_level == RiskLevel.CRITICAL
                ],
                'immediate_recommendations': list(set(
                    action for assessment in report.risk_assessments.values()
                    for action in assessment.recommended_actions
                    if assessment.risk_level in {RiskLevel.CRITICAL, RiskLevel.HIGH}
                ))
            }
        }
    
    def _generate_comprehensive_content(self, report: ThreatIntelligenceReport) -> Dict[str, Any]:
        """Generate comprehensive report content combining all analysis types."""
        
        return {
            'executive_summary': self._generate_executive_summary_content(report),
            'technical_analysis': self._generate_technical_analysis_content(report),
            'attribution_analysis': self._generate_attribution_report_content(report),
            'timeline_analysis': self._generate_timeline_report_content(report),
            'risk_assessment': self._generate_risk_assessment_content(report),
            'ioc_feed': self._generate_ioc_feed_content(report)
        }
    
    def _format_as_json(self, content: Dict[str, Any]) -> str:
        """Format content as JSON."""
        return json.dumps(content, indent=2, default=str)
    
    def _format_as_markdown(self, content: Dict[str, Any], report_type: ReportType) -> str:
        """Format content as Markdown."""
        
        md_lines = []
        
        # Title
        title = f"# Threat Intelligence Report - {report_type.value.replace('_', ' ').title()}"
        md_lines.append(title)
        md_lines.append("")
        
        # Metadata
        if 'report_metadata' in content:
            metadata = content['report_metadata']
            md_lines.append("## Report Information")
            md_lines.append(f"- **Report ID**: {metadata.get('report_id', 'N/A')}")
            md_lines.append(f"- **Generated**: {metadata.get('analysis_timestamp', 'N/A')}")
            md_lines.append(f"- **Organization**: {metadata.get('organization', 'N/A')}")
            md_lines.append("")
        
        # Key metrics
        if 'key_metrics' in content:
            metrics = content['key_metrics']
            md_lines.append("## Key Metrics")
            for key, value in metrics.items():
                formatted_key = key.replace('_', ' ').title()
                md_lines.append(f"- **{formatted_key}**: {value}")
            md_lines.append("")
        
        # Add other sections recursively
        for section_name, section_data in content.items():
            if section_name not in ['report_metadata', 'key_metrics']:
                md_lines.extend(self._format_section_as_markdown(section_name, section_data, level=2))
        
        return '\n'.join(md_lines)
    
    def _format_section_as_markdown(self, section_name: str, section_data: Any, level: int = 2) -> List[str]:
        """Format a section as Markdown."""
        lines = []
        
        # Section header
        header_prefix = '#' * level
        formatted_name = section_name.replace('_', ' ').title()
        lines.append(f"{header_prefix} {formatted_name}")
        lines.append("")
        
        if isinstance(section_data, dict):
            for key, value in section_data.items():
                if isinstance(value, (dict, list)) and len(str(value)) > 100:
                    # Subsection
                    lines.extend(self._format_section_as_markdown(key, value, level + 1))
                else:
                    # Simple key-value
                    formatted_key = key.replace('_', ' ').title()
                    lines.append(f"- **{formatted_key}**: {value}")
            lines.append("")
        elif isinstance(section_data, list):
            for item in section_data[:10]:  # Limit to first 10 items
                if isinstance(item, dict):
                    lines.append("- " + json.dumps(item, default=str))
                else:
                    lines.append(f"- {item}")
            if len(section_data) > 10:
                lines.append(f"- ... and {len(section_data) - 10} more items")
            lines.append("")
        else:
            lines.append(str(section_data))
            lines.append("")
        
        return lines
    
    def _format_as_html(self, content: Dict[str, Any], report_type: ReportType) -> str:
        """Format content as HTML."""
        
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }}
        .header {{ background-color: #f4f4f4; padding: 20px; border-radius: 5px; }}
        .section {{ margin: 20px 0; }}
        .metric {{ background-color: #e9f4ff; padding: 10px; margin: 5px 0; border-radius: 3px; }}
        .risk-critical {{ background-color: #ffebee; }}
        .risk-high {{ background-color: #fff3e0; }}
        .risk-medium {{ background-color: #f3e5f5; }}
        .risk-low {{ background-color: #e8f5e8; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>{title}</h1>
        <p>Generated on: {timestamp}</p>
    </div>
    
    <div class="content">
        {content_html}
    </div>
</body>
</html>
        """
        
        title = f"Threat Intelligence Report - {report_type.value.replace('_', ' ').title()}"
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        
        content_html = self._dict_to_html(content)
        
        return html_template.format(
            title=title,
            timestamp=timestamp,
            content_html=content_html
        )
    
    def _dict_to_html(self, data: Any, level: int = 1) -> str:
        """Convert dictionary to HTML."""
        if isinstance(data, dict):
            html = ""
            for key, value in data.items():
                formatted_key = key.replace('_', ' ').title()
                html += f"<h{min(level + 1, 6)}>{formatted_key}</h{min(level + 1, 6)}>"
                html += f"<div class='section'>{self._dict_to_html(value, level + 1)}</div>"
            return html
        elif isinstance(data, list):
            if not data:
                return "<p>No items</p>"
            html = "<ul>"
            for item in data[:20]:  # Limit to first 20 items
                html += f"<li>{self._dict_to_html(item, level + 1)}</li>"
            if len(data) > 20:
                html += f"<li><em>... and {len(data) - 20} more items</em></li>"
            html += "</ul>"
            return html
        else:
            return f"<div class='metric'>{str(data)}</div>"
    
    def _format_as_csv(self, content: Dict[str, Any], report_type: ReportType) -> str:
        """Format content as CSV (for IOC feeds and tabular data)."""
        
        output = io.StringIO()
        
        if report_type == ReportType.IOC_FEED and 'indicators' in content:
            # IOC feed CSV format
            indicators = content['indicators']
            if indicators:
                fieldnames = indicators[0].keys()
                writer = csv.DictWriter(output, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(indicators)
        else:
            # Flatten nested structure for CSV
            flattened_data = self._flatten_dict(content)
            if flattened_data:
                fieldnames = flattened_data[0].keys()
                writer = csv.DictWriter(output, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(flattened_data)
        
        return output.getvalue()
    
    def _format_as_stix(self, content: Dict[str, Any]) -> str:
        """Format content as STIX JSON (simplified)."""
        
        stix_bundle = {
            "type": "bundle",
            "id": f"bundle--{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}",
            "spec_version": "2.1",
            "objects": []
        }
        
        # Add identity object
        identity = {
            "type": "identity",
            "id": f"identity--{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}",
            "created": datetime.utcnow().isoformat() + "Z",
            "modified": datetime.utcnow().isoformat() + "Z",
            "name": self.organization_name,
            "identity_class": "organization"
        }
        stix_bundle["objects"].append(identity)
        
        # Add indicator objects (simplified)
        if 'indicators' in content:
            for i, indicator_data in enumerate(content['indicators'][:100]):  # Limit to 100
                indicator = {
                    "type": "indicator",
                    "id": f"indicator--{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}-{i}",
                    "created": datetime.utcnow().isoformat() + "Z",
                    "modified": datetime.utcnow().isoformat() + "Z",
                    "pattern": f"[{indicator_data.get('type', 'unknown')}:value = '{indicator_data.get('value', 'unknown')}']",
                    "labels": ["malicious-activity"],
                    "confidence": int(indicator_data.get('confidence', 0.5) * 100)
                }
                stix_bundle["objects"].append(indicator)
        
        return json.dumps(stix_bundle, indent=2)
    
    # Helper methods for analysis
    def _get_top_threat_categories(self, report: ThreatIntelligenceReport) -> List[Tuple[str, int]]:
        """Get top threat categories."""
        category_counts = Counter(
            assessment.threat_category.value for assessment in report.risk_assessments.values()
        )
        return category_counts.most_common(5)
    
    def _get_geographic_distribution(self, report: ThreatIntelligenceReport) -> Dict[str, int]:
        """Get geographic distribution from timelines."""
        geo_counts = Counter()
        for timeline in report.timelines:
            geo_counts.update(timeline.geographic_scope)
        return dict(geo_counts.most_common(10))
    
    def _get_timeline_summary(self, report: ThreatIntelligenceReport) -> Dict[str, Any]:
        """Get timeline analysis summary."""
        if not report.timelines:
            return {}
        
        total_events = sum(len(timeline.events) for timeline in report.timelines)
        avg_duration = sum(
            timeline.duration.total_seconds() for timeline in report.timelines
        ) / len(report.timelines) / 3600  # Convert to hours
        
        return {
            'total_timelines': len(report.timelines),
            'total_events': total_events,
            'average_duration_hours': round(avg_duration, 2),
            'escalation_detected': sum(1 for t in report.timelines if t.escalation_detected)
        }
    
    def _calculate_overall_risk_level(self, report: ThreatIntelligenceReport) -> str:
        """Calculate overall risk level."""
        if not report.risk_assessments:
            return "unknown"
        
        risk_scores = [assessment.risk_score for assessment in report.risk_assessments.values()]
        avg_risk = sum(risk_scores) / len(risk_scores)
        
        if avg_risk >= 0.8:
            return "critical"
        elif avg_risk >= 0.6:
            return "high"
        elif avg_risk >= 0.4:
            return "medium"
        else:
            return "low"
    
    def _identify_trending_risks(self, report: ThreatIntelligenceReport) -> List[str]:
        """Identify trending risk patterns."""
        trends = []
        
        # Analyze risk factors
        risk_factors = Counter()
        for assessment in report.risk_assessments.values():
            for factor in assessment.risk_factors:
                risk_factors[factor.name] += 1
        
        # Top trending factors
        for factor_name, count in risk_factors.most_common(3):
            trends.append(f"Increasing {factor_name.replace('_', ' ')} activity ({count} instances)")
        
        return trends
    
    def _get_immediate_actions(self, report: ThreatIntelligenceReport) -> List[str]:
        """Get immediate action recommendations."""
        actions = set()
        
        for assessment in report.risk_assessments.values():
            if assessment.risk_level == RiskLevel.CRITICAL:
                actions.update(assessment.recommended_actions[:2])  # Top 2 actions
        
        return list(actions)[:5]  # Limit to 5 actions
    
    def _get_strategic_recommendations(self, report: ThreatIntelligenceReport) -> List[str]:
        """Get strategic recommendations."""
        recommendations = [
            "Implement continuous threat monitoring for identified indicators",
            "Enhance detection rules based on discovered TTPs",
            "Develop threat hunting queries for attributed threat actors",
            "Update incident response playbooks with timeline patterns",
            "Share threat intelligence with industry partners"
        ]
        
        return recommendations[:3]  # Top 3 strategic recommendations
    
    def _flatten_dict(self, d: Dict[str, Any], parent_key: str = '', sep: str = '_') -> List[Dict[str, Any]]:
        """Flatten nested dictionary for CSV export."""
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep=sep))
            elif isinstance(v, list) and v and isinstance(v[0], dict):
                for i, item in enumerate(v):
                    items.extend(self._flatten_dict(item, f"{new_key}_{i}", sep=sep))
            else:
                items.append({new_key: v})
        
        return items
    
    # Additional analysis helper methods
    def _analyze_correlation_types(self, correlations: List[CorrelationResult]) -> Dict[str, int]:
        """Analyze correlation type distribution."""
        return Counter(corr.correlation_type.value for corr in correlations)
    
    def _get_strong_correlations(self, correlations: List[CorrelationResult]) -> List[Dict[str, Any]]:
        """Get strong correlations for technical analysis."""
        strong_corrs = [
            corr for corr in correlations
            if corr.strength in {CorrelationStrength.STRONG, CorrelationStrength.VERY_STRONG}
        ]
        return [corr.to_dict() for corr in strong_corrs[:10]]  # Top 10
    
    def _build_correlation_network(self, correlations: List[CorrelationResult]) -> Dict[str, Any]:
        """Build correlation network statistics."""
        indicators = set()
        for corr in correlations:
            indicators.add(corr.indicator1_id)
            indicators.add(corr.indicator2_id)
        
        return {
            'total_nodes': len(indicators),
            'total_edges': len(correlations),
            'network_density': len(correlations) / (len(indicators) * (len(indicators) - 1) / 2) if len(indicators) > 1 else 0
        }
    
    def _analyze_cluster_types(self, clusters: List[IndicatorCluster]) -> Dict[str, int]:
        """Analyze cluster type distribution."""
        return Counter(cluster.cluster_type.value for cluster in clusters)
    
    def _get_largest_clusters(self, clusters: List[IndicatorCluster]) -> List[Dict[str, Any]]:
        """Get largest clusters."""
        sorted_clusters = sorted(clusters, key=lambda c: len(c.indicator_ids), reverse=True)
        return [
            {
                'cluster_id': cluster.id,
                'cluster_type': cluster.cluster_type.value,
                'size': len(cluster.indicator_ids),
                'quality': cluster.quality.value
            }
            for cluster in sorted_clusters[:5]
        ]
    
    def _analyze_cluster_quality(self, clusters: List[IndicatorCluster]) -> Dict[str, int]:
        """Analyze cluster quality distribution."""
        return Counter(cluster.quality.value for cluster in clusters)


class AlertGenerator:
    """Generates security alerts from analysis results."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize alert generator."""
        self.config = config or {}
        
        # Alert thresholds
        self.critical_risk_threshold = self.config.get('critical_risk_threshold', 0.9)
        self.high_risk_threshold = self.config.get('high_risk_threshold', 0.7)
        self.correlation_alert_threshold = self.config.get('correlation_alert_threshold', 10)
        
        logger.info("Alert generator initialized")
    
    def generate_alerts(self, intelligence_report: ThreatIntelligenceReport) -> List[Alert]:
        """Generate alerts from threat intelligence report."""
        
        alerts = []
        
        # Critical risk alerts
        alerts.extend(self._generate_risk_alerts(intelligence_report))
        
        # Campaign detection alerts
        alerts.extend(self._generate_campaign_alerts(intelligence_report))
        
        # Attribution alerts
        alerts.extend(self._generate_attribution_alerts(intelligence_report))
        
        # Correlation surge alerts
        alerts.extend(self._generate_correlation_alerts(intelligence_report))
        
        # Timeline escalation alerts
        alerts.extend(self._generate_escalation_alerts(intelligence_report))
        
        logger.info(f"Generated {len(alerts)} alerts from analysis")
        return alerts
    
    def _generate_risk_alerts(self, report: ThreatIntelligenceReport) -> List[Alert]:
        """Generate alerts for high-risk indicators."""
        alerts = []
        
        critical_indicators = [
            (indicator_id, assessment) for indicator_id, assessment in report.risk_assessments.items()
            if assessment.risk_score >= self.critical_risk_threshold
        ]
        
        if critical_indicators:
            alert = Alert(
                alert_id=f"risk_alert_{report.report_id}",
                title=f"Critical Risk Indicators Detected",
                severity=AlertSeverity.CRITICAL,
                description=f"Identified {len(critical_indicators)} indicators with critical risk scores",
                timestamp=datetime.utcnow(),
                source_analysis=report.report_id,
                indicators=[indicator_id for indicator_id, _ in critical_indicators],
                evidence={
                    'critical_count': len(critical_indicators),
                    'avg_risk_score': sum(assessment.risk_score for _, assessment in critical_indicators) / len(critical_indicators),
                    'top_risk_factors': list(set(
                        factor.name for _, assessment in critical_indicators
                        for factor in assessment.risk_factors[:3]
                    ))
                },
                recommended_actions=[
                    "Immediately block critical indicators",
                    "Investigate for active threats",
                    "Review security controls"
                ]
            )
            alerts.append(alert)
        
        return alerts
    
    def _generate_campaign_alerts(self, report: ThreatIntelligenceReport) -> List[Alert]:
        """Generate alerts for detected campaigns."""
        alerts = []
        
        campaigns = [timeline for timeline in report.timelines if timeline.campaign_name]
        
        for campaign in campaigns:
            alert = Alert(
                alert_id=f"campaign_alert_{campaign.timeline_id}",
                title=f"Attack Campaign Detected: {campaign.campaign_name}",
                severity=AlertSeverity.HIGH,
                description=f"Identified coordinated attack campaign with {len(campaign.events)} events",
                timestamp=datetime.utcnow(),
                source_analysis=report.report_id,
                indicators=[event.indicator.id for event in campaign.events],
                evidence={
                    'campaign_duration_hours': campaign.duration.total_seconds() / 3600,
                    'attack_phases': [phase.value for phase in campaign.attack_phases],
                    'ttp_patterns': campaign.ttp_patterns,
                    'escalation_detected': campaign.escalation_detected
                },
                recommended_actions=[
                    "Monitor campaign indicators",
                    "Implement campaign-specific detections",
                    "Review similar attack patterns"
                ]
            )
            alerts.append(alert)
        
        return alerts
    
    def _generate_attribution_alerts(self, report: ThreatIntelligenceReport) -> List[Alert]:
        """Generate alerts for high-confidence attributions."""
        alerts = []
        
        high_conf_attributions = [
            attr for attr in report.attributions
            if attr.confidence in {AttributionConfidence.HIGH, AttributionConfidence.VERY_HIGH}
        ]
        
        for attribution in high_conf_attributions:
            alert = Alert(
                alert_id=f"attribution_alert_{attribution.attribution_id}",
                title=f"Threat Actor Attribution: {attribution.threat_actor.name}",
                severity=AlertSeverity.HIGH,
                description=f"High-confidence attribution to {attribution.threat_actor.name} ({attribution.threat_actor.actor_type.value})",
                timestamp=datetime.utcnow(),
                source_analysis=report.report_id,
                indicators=attribution.matched_indicators,
                evidence={
                    'confidence_score': attribution.confidence_score,
                    'matching_ttps': attribution.matching_ttps,
                    'infrastructure_overlap': attribution.infrastructure_overlap,
                    'threat_actor_type': attribution.threat_actor.actor_type.value
                },
                recommended_actions=[
                    f"Deploy {attribution.threat_actor.name}-specific detections",
                    "Review historical {attribution.threat_actor.name} activities",
                    "Implement targeted threat hunting"
                ]
            )
            alerts.append(alert)
        
        return alerts
    
    def _generate_correlation_alerts(self, report: ThreatIntelligenceReport) -> List[Alert]:
        """Generate alerts for correlation surges."""
        alerts = []
        
        if len(report.correlations) >= self.correlation_alert_threshold:
            alert = Alert(
                alert_id=f"correlation_surge_{report.report_id}",
                title="High Correlation Activity Detected",
                severity=AlertSeverity.MEDIUM,
                description=f"Detected {len(report.correlations)} correlations indicating coordinated activity",
                timestamp=datetime.utcnow(),
                source_analysis=report.report_id,
                indicators=[],
                evidence={
                    'correlation_count': len(report.correlations),
                    'strong_correlations': sum(
                        1 for corr in report.correlations
                        if corr.strength in {CorrelationStrength.STRONG, CorrelationStrength.VERY_STRONG}
                    )
                },
                recommended_actions=[
                    "Investigate correlation patterns",
                    "Review related indicators",
                    "Monitor for campaign activity"
                ]
            )
            alerts.append(alert)
        
        return alerts
    
    def _generate_escalation_alerts(self, report: ThreatIntelligenceReport) -> List[Alert]:
        """Generate alerts for attack escalation."""
        alerts = []
        
        escalating_timelines = [
            timeline for timeline in report.timelines
            if timeline.escalation_detected
        ]
        
        if escalating_timelines:
            alert = Alert(
                alert_id=f"escalation_alert_{report.report_id}",
                title="Attack Escalation Detected",
                severity=AlertSeverity.CRITICAL,
                description=f"Detected escalation in {len(escalating_timelines)} attack timelines",
                timestamp=datetime.utcnow(),
                source_analysis=report.report_id,
                indicators=[],
                evidence={
                    'escalating_campaigns': len(escalating_timelines),
                    'timeline_names': [t.campaign_name for t in escalating_timelines if t.campaign_name]
                },
                recommended_actions=[
                    "Activate incident response",
                    "Escalate to security leadership",
                    "Implement emergency controls"
                ]
            )
            alerts.append(alert)
        
        return alerts


class ReportingSystem:
    """Main reporting system that coordinates report generation and alerting."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize reporting system."""
        self.config = config or {}
        
        self.report_generator = ReportGenerator(self.config.get('report_generator', {}))
        self.alert_generator = AlertGenerator(self.config.get('alert_generator', {}))
        
        # Storage configuration
        self.report_storage_path = self.config.get('report_storage_path', './reports')
        self.alert_storage_path = self.config.get('alert_storage_path', './alerts')
        
        logger.info("Reporting system initialized")
    
    def process_analysis_results(self, intelligence_report: ThreatIntelligenceReport) -> Dict[str, Any]:
        """Process analysis results and generate reports and alerts."""
        
        logger.info(f"Processing analysis results for report {intelligence_report.report_id}")
        
        # Generate reports
        reports = {}
        
        # Executive summary (JSON and HTML)
        reports['executive_summary_json'] = self.report_generator.generate_report(
            intelligence_report, ReportType.EXECUTIVE_SUMMARY, ReportFormat.JSON
        )
        reports['executive_summary_html'] = self.report_generator.generate_report(
            intelligence_report, ReportType.EXECUTIVE_SUMMARY, ReportFormat.HTML
        )
        
        # Technical analysis
        reports['technical_analysis'] = self.report_generator.generate_report(
            intelligence_report, ReportType.TECHNICAL_ANALYSIS, ReportFormat.JSON
        )
        
        # IOC feed
        reports['ioc_feed_json'] = self.report_generator.generate_report(
            intelligence_report, ReportType.IOC_FEED, ReportFormat.JSON
        )
        reports['ioc_feed_csv'] = self.report_generator.generate_report(
            intelligence_report, ReportType.IOC_FEED, ReportFormat.CSV
        )
        
        # Attribution report
        if intelligence_report.attributions:
            reports['attribution_report'] = self.report_generator.generate_report(
                intelligence_report, ReportType.ATTRIBUTION_REPORT, ReportFormat.JSON
            )
        
        # Timeline report
        if intelligence_report.timelines:
            reports['timeline_report'] = self.report_generator.generate_report(
                intelligence_report, ReportType.TIMELINE_REPORT, ReportFormat.JSON
            )
        
        # Generate alerts
        alerts = self.alert_generator.generate_alerts(intelligence_report)
        
        # Store reports and alerts (implement file storage if needed)
        
        return {
            'reports_generated': len(reports),
            'alerts_generated': len(alerts),
            'reports': {k: len(v) for k, v in reports.items()},
            'alerts': [alert.to_dict() for alert in alerts],
            'processing_timestamp': datetime.utcnow().isoformat()
        }