"""
Analysis module for OSINT Lab 8 Threat Intelligence System.

This module provides advanced threat intelligence analysis capabilities including
correlation analysis, clustering, risk assessment, timeline reconstruction,
attribution analysis, and comprehensive reporting.

Version: 1.0.0
"""

__version__ = "1.0.0"

# Import all analysis components
from .correlation import (
    CorrelationEngine,
    CorrelationResult,
    CorrelationType,
    CorrelationStrength,
    TemporalCorrelationAnalyzer,
    NetworkCorrelationAnalyzer,
    AttributeCorrelationAnalyzer,
    EnrichmentCorrelationAnalyzer
)

from .clustering import (
    ClusteringOrchestrator,
    IndicatorCluster,
    ClusterType,
    ClusterQuality,
    GraphBasedClustering,
    TemporalClustering
)

from .risk_scoring import (
    CompositeRiskScorer,
    RiskAssessment,
    RiskLevel,
    ThreatCategory,
    RiskFactor,
    ReputationRiskScorer,
    CorrelationRiskScorer,
    TemporalRiskScorer,
    ClusterRiskScorer,
    SourceCredibilityScorer,
    GeographicRiskScorer
)

from .timeline_analysis import (
    TimelineAnalysisEngine,
    AttackTimeline,
    TimelineEvent,
    TimelineEventType,
    AttackPhase,
    TimelineBuilder,
    EventClassifier
)

from .attribution import (
    AttributionEngine,
    Attribution,
    AttributionConfidence,
    ThreatActor,
    ThreatActorType,
    AttributionEvidence,
    ThreatActorDatabase,
    AttributionAnalyzer
)

from .orchestrator import (
    AnalysisOrchestrator,
    ThreatIntelligenceReport,
    AnalysisStageResult,
    AnalysisStage,
    AnalysisStatus
)

from .reporting import (
    ReportingSystem,
    ReportGenerator,
    AlertGenerator,
    Alert,
    AlertSeverity,
    ReportFormat,
    ReportType
)

# Main analysis workflow function
def analyze_threat_indicators(indicators, config=None):
    """
    Perform comprehensive threat intelligence analysis on indicators.
    
    Args:
        indicators: List of NormalizedIndicator objects
        config: Optional configuration dictionary
    
    Returns:
        ThreatIntelligenceReport with complete analysis results
    """
    import asyncio
    
    orchestrator = AnalysisOrchestrator(config)
    
    # Run the async analysis in a new event loop if needed
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    
    return loop.run_until_complete(
        orchestrator.analyze_indicators(indicators)
    )

__all__ = [
    # Core analysis engines
    'AnalysisOrchestrator',
    'analyze_threat_indicators',
    
    # Correlation analysis
    'CorrelationEngine',
    'CorrelationResult',
    'CorrelationType',
    'CorrelationStrength',
    
    # Clustering analysis
    'ClusteringOrchestrator',
    'IndicatorCluster',
    'ClusterType',
    'ClusterQuality',
    
    # Risk scoring
    'CompositeRiskScorer',
    'RiskAssessment',
    'RiskLevel',
    'ThreatCategory',
    'RiskFactor',
    
    # Timeline analysis
    'TimelineAnalysisEngine',
    'AttackTimeline',
    'TimelineEvent',
    'TimelineEventType',
    'AttackPhase',
    
    # Attribution analysis
    'AttributionEngine',
    'Attribution',
    'AttributionConfidence',
    'ThreatActor',
    'ThreatActorType',
    
    # Reporting and alerting
    'ReportingSystem',
    'ReportGenerator',
    'AlertGenerator',
    'Alert',
    'AlertSeverity',
    'ReportFormat',
    'ReportType',
    
    # Main report object
    'ThreatIntelligenceReport',
    'AnalysisStageResult',
    'AnalysisStage',
    'AnalysisStatus'
]