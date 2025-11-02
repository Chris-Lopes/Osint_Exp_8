#!/usr/bin/env python3
"""
Analysis & Correlation Engine - Production Pipeline Execution

This script runs the complete threat intelligence analysis pipeline on real data:
- Loads indicators from data/enriched/ directory (or data/processed/ as fallback)
- Correlation Engine (4 analyzers)
- Clustering Orchestrator (graph-based & temporal clustering)
- Risk Scoring Framework (6 component scorers)
- Timeline Analysis Engine (16 event types)
- Attribution Engine (threat actor matching)
- Analysis Orchestrator (6-stage workflow)
- Reporting System (7 report formats)
- Complete integration execution

Expected execution results:
✅ All 8 major components should execute successfully on real threat data
✅ Each component should demonstrate proper functionality
✅ Integration execution should show end-to-end workflow
✅ Results should be based on actual collected and processed indicators
"""

import logging
import sys
import json
from datetime import datetime, timedelta
from typing import List, Dict, Any
from pathlib import Path
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Import all analysis components
from src.normalizers.schema import (
    NormalizedIndicator, IndicatorType, SeverityLevel, TLPMarking
)
from src.analysis import analyze_threat_indicators


def load_enriched_indicators(limit: int = None) -> List[NormalizedIndicator]:
    """Load enriched indicators from the data/enriched directory."""
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

                                # Convert to NormalizedIndicator
                                # Handle the enriched data format
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

    logger.info(f"Loaded {len(indicators)} enriched indicators")
    return indicators


def load_processed_indicators(limit: int = None) -> List[NormalizedIndicator]:
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

                                # Convert to NormalizedIndicator
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


def run_analysis_pipeline():
    """Run the complete analysis pipeline."""
    logger.info("🚀 Starting Analysis & Correlation Engine Execution")
    logger.info("=" * 75)
    
    results = {}
    
    try:
        # Load real indicators from enriched data (or fallback to processed)
        indicators = load_enriched_indicators(limit=1000)  # Limit for testing
        if not indicators:
            logger.error("❌ No indicators found in data directories")
            logger.error("Please run the collection and processing pipeline first:")
            logger.error("  python run_lab_analysis.py")
            return False
            
        logger.info(f"📊 Loaded {len(indicators)} real indicators for analysis")
        
        # Run complete analysis
        logger.info("=== Running Complete Analysis Pipeline ===")
        
        try:
            # This should trigger the full analysis workflow
            analysis_result = analyze_threat_indicators(indicators)
            
            if analysis_result:
                logger.info("✅ Complete analysis pipeline executed successfully")
                results['integration'] = True
                
                # Log summary of results
                if hasattr(analysis_result, 'correlations'):
                    logger.info(f"📈 Generated {len(analysis_result.correlations)} correlations")
                    
                if hasattr(analysis_result, 'clusters'):
                    logger.info(f"🔗 Created {len(analysis_result.clusters)} clusters")
                    
                if hasattr(analysis_result, 'risk_assessments'):
                    logger.info(f"⚠️  Completed {len(analysis_result.risk_assessments)} risk assessments")
                    
                if hasattr(analysis_result, 'timeline'):
                    logger.info(f"📅 Built timeline with {len(analysis_result.timeline.events)} events")
                    
                if hasattr(analysis_result, 'attributions'):
                    logger.info(f"🎯 Generated {len(analysis_result.attributions)} attributions")
                    
            else:
                logger.error("❌ Analysis pipeline returned no results")
                results['integration'] = False
                
        except Exception as e:
            logger.error(f"❌ Analysis pipeline failed: {e}")
            results['integration'] = False
            
    except Exception as e:
        logger.error(f"❌ Validation setup failed: {e}")
        return False
    
    # Print summary
    logger.info("=" * 75)
    logger.info("📊 Validation Summary")
    logger.info("=" * 75)
    
    success_count = sum(1 for result in results.values() if result)
    total_count = len(results)
    
    for component, success in results.items():
        status = "✅ PASSED" if success else "❌ FAILED"
        logger.info(f"{component.capitalize():<15}: {status}")
    
    logger.info("=" * 75)
    logger.info(f"🎯 Overall Result: {success_count}/{total_count} components passed validation")
    
    if success_count == total_count and success_count > 0:
        logger.info("🎉 Module 6: Analysis & Correlation Engine - VALIDATION SUCCESSFUL!")
        logger.info("✅ All components working correctly")
        return True
    else:
        logger.error("💥 Module 6: Analysis & Correlation Engine - VALIDATION FAILED!")
        logger.error(f"❌ {total_count - success_count} components need attention")
        return False


if __name__ == "__main__":
    success = run_analysis_pipeline()
    sys.exit(0 if success else 1)