#!/usr/bin/env python3
"""
Analysis script for enriched threat intelligence data.

This script loads enriched indicators from the data/enriched directory
and runs the complete analysis pipeline to generate threat intelligence
insights, correlations, clusters, risk assessments, timelines, and attributions.
"""

import logging
import json
import sys
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Import analysis components
from src.normalizers.schema import NormalizedIndicator
from src.analysis import analyze_threat_indicators


def load_enriched_indicators(limit: int = None) -> List[NormalizedIndicator]:
    """Load enriched indicators from the data/enriched directory."""
    enriched_dir = Path('data/enriched')

    if not enriched_dir.exists():
        logger.error(f"Enriched data directory not found: {enriched_dir}")
        return []

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


def save_analysis_results(report, output_dir: Path = None):
    """Save analysis results to files."""
    if output_dir is None:
        output_dir = Path('data/analysis')

    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    # Save full report
    report_file = output_dir / f'analysis_report_{timestamp}.json'
    with open(report_file, 'w') as f:
        json.dump(report.to_dict(), f, indent=2, default=str)

    logger.info(f"Analysis report saved to: {report_file}")

    # Save summary
    summary = {
        'report_id': report.report_id,
        'timestamp': report.analysis_timestamp.isoformat(),
        'indicators_analyzed': report.indicators_analyzed,
        'correlations_found': len(report.correlations),
        'clusters_identified': len(report.clusters),
        'risk_assessments': len(report.risk_assessments),
        'timelines_generated': len(report.timelines),
        'attributions_found': len(report.attributions),
        'analysis_quality_score': report.analysis_quality_score,
        'total_duration_seconds': report.total_duration_seconds
    }

    summary_file = output_dir / f'analysis_summary_{timestamp}.json'
    with open(summary_file, 'w') as f:
        json.dump(summary, f, indent=2)

    logger.info(f"Analysis summary saved to: {summary_file}")

    # Save key findings
    findings_file = output_dir / f'key_findings_{timestamp}.txt'
    with open(findings_file, 'w') as f:
        f.write("THREAT INTELLIGENCE ANALYSIS - KEY FINDINGS\n")
        f.write("=" * 50 + "\n\n")
        f.write(f"Analysis ID: {report.report_id}\n")
        f.write(f"Date: {report.analysis_timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Indicators Analyzed: {report.indicators_analyzed}\n\n")

        f.write("EXECUTIVE SUMMARY:\n")
        f.write("-" * 20 + "\n")
        for key, value in report.executive_summary.items():
            f.write(f"{key.replace('_', ' ').title()}: {value}\n")
        f.write("\n")

        f.write("KEY FINDINGS:\n")
        f.write("-" * 15 + "\n")
        for finding in report.key_findings:
            f.write(f"• {finding}\n")
        f.write("\n")

        f.write("RECOMMENDATIONS:\n")
        f.write("-" * 18 + "\n")
        for rec in report.recommendations:
            f.write(f"• {rec}\n")
        f.write("\n")

        f.write("ANALYSIS METRICS:\n")
        f.write("-" * 18 + "\n")
        f.write(f"Correlations Discovered: {len(report.correlations)}\n")
        f.write(f"Threat Clusters Identified: {len(report.clusters)}\n")
        f.write(f"Risk Assessments Completed: {len(report.risk_assessments)}\n")
        f.write(f"Attack Timelines Reconstructed: {len(report.timelines)}\n")
        f.write(f"Threat Actor Attributions: {len(report.attributions)}\n")
        f.write(f"Analysis Quality Score: {report.analysis_quality_score:.2f}\n")
        f.write(f"Total Analysis Time: {report.total_duration_seconds:.1f}s\n")

    logger.info(f"Key findings saved to: {findings_file}")

    return {
        'report_file': str(report_file),
        'summary_file': str(summary_file),
        'findings_file': str(findings_file)
    }


def main():
    """Main analysis execution function."""
    logger.info("🔬 THREAT INTELLIGENCE ANALYSIS PIPELINE")
    logger.info("=" * 60)

    start_time = datetime.now()

    try:
        # Load enriched indicators
        logger.info("Loading enriched threat intelligence data...")
        # Start with a smaller subset for testing
        indicators = load_enriched_indicators(limit=1000)

        if not indicators:
            logger.error("No enriched indicators found. Please run enrichment first.")
            return False

        logger.info(f"✅ Loaded {len(indicators)} enriched indicators (limited for testing)")

        # Run analysis
        logger.info("Starting comprehensive threat intelligence analysis...")
        analysis_report = analyze_threat_indicators(indicators)

        if not analysis_report:
            logger.error("Analysis failed - no results returned")
            return False

        # Save results
        logger.info("Saving analysis results...")
        saved_files = save_analysis_results(analysis_report)

        # Print summary
        end_time = datetime.now()
        duration = end_time - start_time

        logger.info("=" * 60)
        logger.info("🎉 ANALYSIS COMPLETE!")
        logger.info("=" * 60)
        logger.info(f"Total execution time: {duration}")
        logger.info(f"Indicators analyzed: {analysis_report.indicators_analyzed}")
        logger.info(f"Correlations found: {len(analysis_report.correlations)}")
        logger.info(f"Clusters identified: {len(analysis_report.clusters)}")
        logger.info(f"Risk assessments: {len(analysis_report.risk_assessments)}")
        logger.info(f"Timelines generated: {len(analysis_report.timelines)}")
        logger.info(f"Attributions made: {len(analysis_report.attributions)}")
        logger.info(f"Analysis quality score: {analysis_report.analysis_quality_score:.2f}")

        logger.info("\n📁 Generated Files:")
        for file_type, file_path in saved_files.items():
            logger.info(f"• {file_type}: {file_path}")

        logger.info("\n📋 Key Findings:")
        for finding in analysis_report.key_findings[:5]:  # Show first 5
            logger.info(f"• {finding}")

        return True

    except Exception as e:
        logger.error(f"Analysis execution failed: {e}")
        import traceback    
        logger.error(traceback.format_exc())
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)