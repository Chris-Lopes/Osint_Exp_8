"""
Main correlation module for the threat intelligence aggregation system.

This module provides the primary interface for advanced correlation capabilities,
integrating all correlation components into a cohesive system for knowledge
graph creation, relationship detection, and advanced analysis.
"""

import logging
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timezone

try:
    from ..normalizers.schema import NormalizedIndicator
    from .engine import CorrelationEngine, CorrelationResult
    from .relationships import RelationshipDetector
    from .rules import CorrelationRulesEngine
    from .analysis import GraphAnalysisOrchestrator
    from .storage import KnowledgeGraphManager
    from .validation import ValidationOrchestrator, ValidationLevel
except ImportError:
    from normalizers.schema import NormalizedIndicator
    from correlation.engine import CorrelationEngine, CorrelationResult
    from correlation.relationships import RelationshipDetector
    from correlation.rules import CorrelationRulesEngine
    from correlation.analysis import GraphAnalysisOrchestrator
    from correlation.storage import KnowledgeGraphManager
    from correlation.validation import ValidationOrchestrator, ValidationLevel

logger = logging.getLogger(__name__)


class AdvancedCorrelationSystem:
    """
    Advanced correlation system for threat intelligence.
    
    This system provides comprehensive correlation capabilities including:
    - Knowledge graph creation and management
    - Advanced relationship detection algorithms
    - Rule-based correlation engine
    - Sophisticated graph analysis and pattern detection
    - Comprehensive validation and testing framework
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the advanced correlation system.
        
        Args:
            config: Configuration dictionary with component settings
        """
        self.config = config or {}
        
        # Initialize core components
        self.correlation_engine = CorrelationEngine(
            self.config.get('correlation_engine', {})
        )
        
        self.relationship_detector = RelationshipDetector(
            self.config.get('relationship_detector', {})
        )
        
        self.rules_engine = CorrelationRulesEngine(
            self.config.get('rules_engine', {})
        )
        
        self.graph_analyzer = GraphAnalysisOrchestrator(
            self.config.get('graph_analysis', {})
        )
        
        self.storage_manager = KnowledgeGraphManager(
            self.config.get('storage', {})
        )
        
        self.validator = ValidationOrchestrator(
            self.config.get('validation', {})
        )
        
        # System state
        self._initialized = True
        self._last_correlation_id = None
        
        logger.info("Advanced correlation system initialized")
    
    def correlate_threats(self, 
                         indicators: List[NormalizedIndicator],
                         correlation_id: Optional[str] = None) -> CorrelationResult:
        """
        Perform comprehensive threat correlation.
        
        This is the main entry point for threat correlation, combining all
        system capabilities to create a comprehensive knowledge graph with
        advanced analysis.
        
        Args:
            indicators: List of normalized threat intelligence indicators
            correlation_id: Optional correlation identifier for tracking
            
        Returns:
            CorrelationResult with comprehensive correlation data
        """
        if not correlation_id:
            correlation_id = f"correlation_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
        
        self._last_correlation_id = correlation_id
        
        logger.info(f"Starting comprehensive threat correlation: {correlation_id} "
                   f"with {len(indicators)} indicators")
        
        try:
            # Phase 1: Basic correlation and graph creation
            logger.debug("Phase 1: Basic correlation and graph creation")
            correlation_result = self.correlation_engine.correlate_indicators(indicators)
            
            if not correlation_result.nodes:
                logger.warning("No nodes created in basic correlation")
                return correlation_result
            
            # Phase 2: Advanced relationship detection
            logger.debug("Phase 2: Advanced relationship detection")
            additional_relationships = self.relationship_detector.detect_relationships(
                correlation_result.nodes, list(correlation_result.relationships.values())
            )
            
            # Merge additional relationships
            for rel in additional_relationships:
                correlation_result.relationships[rel.relationship_id] = rel
            
            # Phase 3: Rule-based correlation enhancement
            logger.debug("Phase 3: Rule-based correlation enhancement")
            rule_relationships = self.rules_engine.correlate_nodes(
                correlation_result.nodes, correlation_result.relationships
            )
            
            # Merge rule-based relationships
            for rel_id, rel in rule_relationships.items():
                if rel_id not in correlation_result.relationships:
                    correlation_result.relationships[rel_id] = rel
            
            # Phase 4: Advanced graph analysis
            logger.debug("Phase 4: Advanced graph analysis")
            analysis_results = self.graph_analyzer.analyze_complete_graph(
                correlation_result.nodes, correlation_result.relationships
            )
            
            # Enhance correlation result with analysis
            correlation_result.analysis = analysis_results
            correlation_result.correlation_id = correlation_id
            correlation_result.processing_complete = True
            correlation_result.last_updated = datetime.now(timezone.utc)
            
            # Phase 5: Store results
            logger.debug("Phase 5: Storing correlation results")
            storage_success = self.storage_manager.save_graph(
                correlation_id,
                correlation_result.nodes,
                correlation_result.relationships,
                metadata={
                    'correlation_type': 'comprehensive',
                    'analysis_results': analysis_results,
                    'input_indicator_count': len(indicators),
                    'processing_timestamp': datetime.now(timezone.utc).isoformat()
                }
            )
            
            if storage_success:
                correlation_result.storage_location = self.storage_manager.get_graph_path(correlation_id)
            
            logger.info(f"Correlation completed: {correlation_id}, "
                       f"{len(correlation_result.nodes)} nodes, "
                       f"{len(correlation_result.relationships)} relationships")
            
            return correlation_result
            
        except Exception as e:
            logger.error(f"Correlation failed: {correlation_id}: {e}", exc_info=True)
            
            # Return minimal result with error information
            error_result = CorrelationResult(
                correlation_id=correlation_id,
                nodes={},
                relationships={},
                processing_complete=False,
                error_message=str(e)
            )
            
            return error_result
    
    def analyze_existing_graph(self, correlation_id: str) -> Optional[Dict[str, Any]]:
        """
        Analyze an existing correlation graph.
        
        Args:
            correlation_id: ID of the stored correlation graph
            
        Returns:
            Analysis results or None if graph not found
        """
        try:
            # Load graph from storage
            nodes, relationships = self.storage_manager.load_graph(correlation_id)
            
            if not nodes:
                logger.warning(f"No graph found for correlation ID: {correlation_id}")
                return None
            
            logger.info(f"Analyzing existing graph: {correlation_id} "
                       f"({len(nodes)} nodes, {len(relationships)} relationships)")
            
            # Perform analysis
            analysis_results = self.graph_analyzer.analyze_complete_graph(nodes, relationships)
            
            # Update stored metadata
            self.storage_manager.update_graph_metadata(correlation_id, {
                'last_analyzed': datetime.now(timezone.utc).isoformat(),
                'analysis_version': 'v1.0'
            })
            
            return analysis_results
            
        except Exception as e:
            logger.error(f"Failed to analyze graph {correlation_id}: {e}", exc_info=True)
            return None
    
    def query_correlations(self, 
                          query_params: Dict[str, Any],
                          correlation_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Query correlation results with advanced filtering.
        
        Args:
            query_params: Query parameters for filtering and searching
            correlation_id: Optional specific correlation to query
            
        Returns:
            Query results
        """
        try:
            if correlation_id:
                # Query specific correlation
                return self.storage_manager.query_graph(correlation_id, query_params)
            else:
                # Query across all correlations (if supported)
                logger.warning("Cross-correlation querying not yet implemented")
                return {'results': [], 'total': 0}
                
        except Exception as e:
            logger.error(f"Query failed: {e}", exc_info=True)
            return {'error': str(e), 'results': [], 'total': 0}
    
    def validate_system(self, 
                       validation_level: ValidationLevel = ValidationLevel.BASIC) -> Tuple[bool, Dict[str, Any]]:
        """
        Run comprehensive system validation.
        
        Args:
            validation_level: Level of validation to perform
            
        Returns:
            Tuple of (success, validation_results)
        """
        logger.info(f"Running system validation: {validation_level.value}")
        
        try:
            summary, results = self.validator.run_comprehensive_validation(
                correlation_engine=self.correlation_engine,
                relationship_detector=self.relationship_detector,
                rules_engine=self.rules_engine,
                graph_analyzer=self.graph_analyzer,
                storage_manager=self.storage_manager,
                validation_level=validation_level
            )
            
            success = summary.success_rate >= 0.8  # 80% success threshold
            
            validation_results = {
                'summary': summary.to_dict(),
                'detailed_results': [result.to_dict() for result in results],
                'system_status': 'healthy' if success else 'degraded'
            }
            
            logger.info(f"Validation completed: {summary.success_rate:.1%} success rate")
            
            return success, validation_results
            
        except Exception as e:
            logger.error(f"Validation failed: {e}", exc_info=True)
            return False, {'error': str(e)}
    
    def get_system_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive system statistics.
        
        Returns:
            System statistics and health information
        """
        try:
            stats = {
                'system_info': {
                    'initialized': self._initialized,
                    'last_correlation_id': self._last_correlation_id,
                    'components': {
                        'correlation_engine': bool(self.correlation_engine),
                        'relationship_detector': bool(self.relationship_detector),
                        'rules_engine': bool(self.rules_engine),
                        'graph_analyzer': bool(self.graph_analyzer),
                        'storage_manager': bool(self.storage_manager),
                        'validator': bool(self.validator)
                    }
                }
            }
            
            # Get component statistics
            if self.rules_engine:
                stats['rules_engine'] = self.rules_engine.get_statistics()
            
            if self.storage_manager:
                stats['storage'] = self.storage_manager.get_statistics()
            
            if self.validator:
                stats['validation'] = self.validator.get_validation_statistics()
            
            return stats
            
        except Exception as e:
            logger.error(f"Failed to get system statistics: {e}", exc_info=True)
            return {'error': str(e)}
    
    def export_correlation_data(self, 
                               correlation_id: str,
                               export_format: str = 'json',
                               file_path: Optional[str] = None) -> Optional[str]:
        """
        Export correlation data in various formats.
        
        Args:
            correlation_id: ID of correlation to export
            export_format: Export format ('json', 'graphml', 'pickle')
            file_path: Optional custom file path
            
        Returns:
            Path to exported file or None if failed
        """
        try:
            return self.storage_manager.export_graph(
                correlation_id, export_format, file_path
            )
        except Exception as e:
            logger.error(f"Export failed: {e}", exc_info=True)
            return None
    
    def import_correlation_data(self, 
                               file_path: str,
                               correlation_id: Optional[str] = None) -> Optional[str]:
        """
        Import correlation data from file.
        
        Args:
            file_path: Path to import file
            correlation_id: Optional custom correlation ID
            
        Returns:
            Correlation ID if successful, None if failed
        """
        try:
            return self.storage_manager.import_graph(file_path, correlation_id)
        except Exception as e:
            logger.error(f"Import failed: {e}", exc_info=True)
            return None
    
    def cleanup_old_correlations(self, 
                                max_age_days: int = 30,
                                keep_minimum: int = 10) -> int:
        """
        Clean up old correlation data.
        
        Args:
            max_age_days: Maximum age in days for correlations
            keep_minimum: Minimum number of correlations to keep
            
        Returns:
            Number of correlations deleted
        """
        try:
            return self.storage_manager.cleanup_old_graphs(max_age_days, keep_minimum)
        except Exception as e:
            logger.error(f"Cleanup failed: {e}", exc_info=True)
            return 0


# Convenience functions for quick access
def correlate_threats(indicators: List[NormalizedIndicator], 
                     config: Optional[Dict[str, Any]] = None) -> CorrelationResult:
    """
    Convenience function for quick threat correlation.
    
    Args:
        indicators: List of normalized indicators
        config: Optional configuration
        
    Returns:
        CorrelationResult
    """
    system = AdvancedCorrelationSystem(config)
    return system.correlate_threats(indicators)


def validate_correlation_system(config: Optional[Dict[str, Any]] = None) -> Tuple[bool, Dict[str, Any]]:
    """
    Convenience function for system validation.
    
    Args:
        config: Optional configuration
        
    Returns:
        Tuple of (success, validation_results)
    """
    system = AdvancedCorrelationSystem(config)
    return system.validate_system(ValidationLevel.COMPREHENSIVE)