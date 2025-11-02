#!/usr/bin/env python3

"""
Enrichment Pipeline - Comprehensive Testing

This script runs comprehensive tests for the enrichment pipeline components
including individual services, orchestrator, file processing, and CLI integration.
"""

import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.enrichment.orchestrator import EnrichmentOrchestrator, EnrichmentResult
from src.enrichment.geolocation import GeolocationService
from src.enrichment.dns_service import DNSEnrichmentService
from src.enrichment.asn_lookup import ASNLookupService
from src.enrichment.reputation_scoring import ReputationScoringEngine
from src.normalizers.schema import NormalizedIndicator, IndicatorType

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def create_test_indicators() -> List[NormalizedIndicator]:
    """Create test indicators for enrichment testing."""
    test_data = [
        {
            "id": "test-ip-1",
            "value": "8.8.8.8",
            "indicator_type": "ipv4",
            "source": "test",
            "confidence": 75,
            "created": "2025-09-22T10:00:00Z",
            "modified": "2025-09-22T10:00:00Z",
            "context": {"test": True}
        },
        {
            "id": "test-ip-2",
            "value": "1.1.1.1",
            "indicator_type": "ipv4",
            "source": "test",
            "confidence": 80,
            "created": "2025-09-22T10:00:00Z",
            "modified": "2025-09-22T10:00:00Z",
            "context": {"test": True}
        },
        {
            "id": "test-domain-1",
            "value": "google.com",
            "indicator_type": "domain",
            "source": "test",
            "confidence": 85,
            "created": "2025-09-22T10:00:00Z",
            "modified": "2025-09-22T10:00:00Z",
            "context": {"test": True}
        },
        {
            "id": "test-domain-2",
            "value": "cloudflare.com",
            "indicator_type": "domain",
            "source": "test",
            "confidence": 90,
            "created": "2025-09-22T10:00:00Z",
            "modified": "2025-09-22T10:00:00Z",
            "context": {"test": True}
        },
        {
            "id": "test-url-1",
            "value": "https://example.com/path",
            "indicator_type": "url",
            "source": "test",
            "confidence": 70,
            "created": "2025-09-22T10:00:00Z",
            "modified": "2025-09-22T10:00:00Z",
            "context": {"test": True}
        },
        {
            "id": "test-hash-1",
            "value": "5d41402abc4b2a76b9719d911017c592",
            "indicator_type": "md5",
            "source": "test",
            "confidence": 95,
            "created": "2025-09-22T10:00:00Z",
            "modified": "2025-09-22T10:00:00Z",
            "context": {"test": True}
        }
    ]

    indicators = []
    for data in test_data:
        try:
            indicator = NormalizedIndicator(**data)
            indicators.append(indicator)
        except Exception as e:
            logger.error(f"Failed to create test indicator {data.get('id')}: {e}")
            
    return indicators


def load_real_indicators(limit: int = None) -> List[NormalizedIndicator]:
    """Load real indicators from processed data for enrichment testing."""
    processed_dir = Path('data/processed')

    if not processed_dir.exists():
        logger.warning(f"Processed data directory not found: {processed_dir}")
        logger.info("Falling back to test indicators for enrichment testing")
        return create_test_indicators()

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

    if not indicators:
        logger.warning("No real indicators found, falling back to test indicators")
        return create_test_indicators()

    logger.info(f"Loaded {len(indicators)} real indicators for enrichment testing")
    return indicators
def test_individual_services():
    """Test each enrichment service individually."""
    logger.info("Testing individual enrichment services...")

    test_results = {
        'geolocation': {'tested': False, 'success': False, 'error': None},
        'dns': {'tested': False, 'success': False, 'error': None},
        'asn': {'tested': False, 'success': False, 'error': None},
        'reputation': {'tested': False, 'success': False, 'error': None}
    }

    # Test geolocation service (skip MaxMind, test IP-API only)
    try:
        logger.info("Testing geolocation service...")
        from src.enrichment.geolocation import IPAPIGeolocationService
        geo_service = IPAPIGeolocationService()
        result = geo_service.lookup("8.8.8.8")

        test_results['geolocation']['tested'] = True
        test_results['geolocation']['success'] = result.success

        if result.success:
            logger.info(f"Geolocation success: {result.country}, {result.city}")
        else:
            logger.warning(f"Geolocation failed: {result.error}")

    except Exception as e:
        test_results['geolocation']['error'] = str(e)
        logger.error(f"Geolocation service error: {e}")

    # Test DNS service
    try:
        logger.info("Testing DNS service...")
        dns_service = DNSEnrichmentService()
        result = dns_service.enrich_domain("google.com")

        test_results['dns']['tested'] = True
        test_results['dns']['success'] = bool(result and result.get('dns_resolution_success'))

        if test_results['dns']['success']:
            logger.info(f"DNS success: {len(result.get('a_records', []))} A records")
        else:
            logger.warning("DNS resolution failed or returned no data")

    except Exception as e:
        test_results['dns']['error'] = str(e)
        logger.error(f"DNS service error: {e}")

    # Test ASN service
    try:
        logger.info("Testing ASN service...")
        asn_service = ASNLookupService()
        result = asn_service.enrich_network_context("8.8.8.8")

        test_results['asn']['tested'] = True
        test_results['asn']['success'] = result.get('asn_lookup_success', False)

        if test_results['asn']['success']:
            asn_num = result.get('asn_number', 'unknown')
            logger.info(f"ASN success: AS{asn_num}")
        else:
            logger.warning("ASN lookup failed")

    except Exception as e:
        test_results['asn']['error'] = str(e)
        logger.error(f"ASN service error: {e}")

    # Test reputation service
    try:
        logger.info("Testing reputation service...")
        rep_engine = ReputationScoringEngine()
        result = rep_engine.score_indicator("8.8.8.8", "ipv4", {})

        test_results['reputation']['tested'] = True
        test_results['reputation']['success'] = result.success

        if result.success:
            logger.info(f"Reputation success: score {result.reputation_score}")
        else:
            logger.warning(f"Reputation failed: {result.error}")

    except Exception as e:
        test_results['reputation']['error'] = str(e)
        logger.error(f"Reputation service error: {e}")

    return test_results


def test_enrichment_orchestrator():
    """Test the enrichment orchestrator with sample indicators."""
    logger.info("Testing enrichment orchestrator...")

    try:
        # Create orchestrator
        orchestrator = EnrichmentOrchestrator()

        # Create test indicators
        test_indicators = load_real_indicators(limit=50)
        logger.info(f"Loaded {len(test_indicators)} indicators for testing")

        # Test single indicator enrichment
        logger.info("Testing single indicator enrichment...")
        if test_indicators:
            result = orchestrator.enrich_indicator(test_indicators[0])
            logger.info(f"Single enrichment result: success={result.success}, "
                       f"sources={result.enrichment_sources}")

        # Test batch enrichment
        logger.info("Testing batch enrichment...")
        batch_results = orchestrator.enrich_batch(test_indicators)

        # Analyze results
        successful = sum(1 for r in batch_results if r.success)
        total = len(batch_results)
        success_rate = successful / total * 100 if total > 0 else 0

        logger.info(f"Batch enrichment: {successful}/{total} successful ({success_rate:.1f}%)")

        # Show detailed results
        for result in batch_results:
            indicator_type = result.indicator.indicator_type.value
            value = result.indicator.value
            sources = ", ".join(result.enrichment_sources) if result.enrichment_sources else "none"
            errors = len(result.enrichment_errors)

            logger.info(f"  {indicator_type} {value}: sources=[{sources}], errors={errors}")

        return {
            'success': True,
            'total_indicators': total,
            'successful_enrichments': successful,
            'success_rate': success_rate,
            'results': batch_results
        }

    except Exception as e:
        logger.error(f"Orchestrator test failed: {e}")
        return {'success': False, 'error': str(e)}


def test_file_processing():
    """Test file-to-file enrichment processing."""
    logger.info("Testing file processing...")

    try:
        # Create test normalized data file
        test_dir = Path("data/test")
        test_dir.mkdir(parents=True, exist_ok=True)

        input_file = test_dir / "test_normalized.jsonl"
        output_file = test_dir / "test_enriched.jsonl"

        # Create test indicators and write to file
        test_indicators = load_real_indicators(limit=20)

        with open(input_file, 'w') as f:
            for indicator in test_indicators:
                f.write(json.dumps(indicator.dict(), default=str) + '\n')

        logger.info(f"Created test input file: {input_file}")

        # Run file enrichment
        orchestrator = EnrichmentOrchestrator()
        file_results = orchestrator.enrich_from_file(input_file, output_file)

        logger.info(f"File enrichment results: {file_results}")

        # Verify output file
        if output_file.exists():
            with open(output_file, 'r') as f:
                enriched_lines = f.readlines()

            logger.info(f"Output file created with {len(enriched_lines)} enriched indicators")

            # Sample enriched indicator
            if enriched_lines:
                sample = json.loads(enriched_lines[0])
                has_enrichment = 'enrichment' in sample.get('context', {})
                logger.info(f"Sample enriched indicator has enrichment data: {has_enrichment}")

        return {
            'success': True,
            'file_results': file_results,
            'output_exists': output_file.exists()
        }

    except Exception as e:
        logger.error(f"File processing test failed: {e}")
        return {'success': False, 'error': str(e)}


def test_cli_integration():
    """Test CLI integration by running enrichment commands."""
    logger.info("Testing CLI integration...")

    try:
        # Test enrichment validation command
        import subprocess

        cmd = [sys.executable, "src/collection_cli.py", "enrich", "--validate", "--json"]

        logger.info(f"Running command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=Path.cwd())

        if result.returncode == 0:
            try:
                cli_output = json.loads(result.stdout)
                logger.info(f"CLI validation successful: {cli_output}")
                return {'success': True, 'cli_output': cli_output}
            except json.JSONDecodeError:
                logger.warning(f"CLI returned non-JSON output: {result.stdout}")
                return {'success': True, 'cli_output': result.stdout}
        else:
            logger.error(f"CLI command failed: {result.stderr}")
            return {'success': False, 'error': result.stderr}

    except Exception as e:
        logger.error(f"CLI integration test failed: {e}")
        return {'success': False, 'error': str(e)}


def run_comprehensive_test():
    """Run comprehensive enrichment pipeline test."""
    logger.info("=" * 60)
    logger.info("STARTING COMPREHENSIVE ENRICHMENT PIPELINE TEST")
    logger.info("=" * 60)

    overall_results = {
        'start_time': datetime.utcnow(),
        'individual_services': None,
        'orchestrator': None,
        'file_processing': None,
        'cli_integration': None,
        'overall_success': False
    }

    # Test 1: Individual services
    logger.info("\n" + "=" * 40)
    logger.info("TEST 1: Individual Services")
    logger.info("=" * 40)

    service_results = test_individual_services()
    overall_results['individual_services'] = service_results

    # Test 2: Orchestrator
    logger.info("\n" + "=" * 40)
    logger.info("TEST 2: Enrichment Orchestrator")
    logger.info("=" * 40)

    orchestrator_results = test_enrichment_orchestrator()
    overall_results['orchestrator'] = orchestrator_results

    # Test 3: File processing
    logger.info("\n" + "=" * 40)
    logger.info("TEST 3: File Processing")
    logger.info("=" * 40)

    file_results = test_file_processing()
    overall_results['file_processing'] = file_results

    # Test 4: CLI integration
    logger.info("\n" + "=" * 40)
    logger.info("TEST 4: CLI Integration")
    logger.info("=" * 40)

    cli_results = test_cli_integration()
    overall_results['cli_integration'] = cli_results

    # Overall assessment
    overall_results['end_time'] = datetime.utcnow()
    overall_results['duration'] = (overall_results['end_time'] - overall_results['start_time']).total_seconds()

    # Determine overall success
    service_success = any(s.get('success', False) for s in service_results.values())
    orchestrator_success = orchestrator_results.get('success', False)
    file_success = file_results.get('success', False)
    cli_success = cli_results.get('success', False)

    overall_results['overall_success'] = all([
        service_success,
        orchestrator_success,
        file_success,
        cli_success
    ])

    # Summary
    logger.info("\n" + "=" * 60)
    logger.info("TEST SUMMARY")
    logger.info("=" * 60)

    logger.info(f"Individual Services: {'PASS' if service_success else 'FAIL'}")
    for service, result in service_results.items():
        status = "✓" if result.get('success') else "✗"
        logger.info(f"  {status} {service}")

    logger.info(f"Orchestrator: {'PASS' if orchestrator_success else 'FAIL'}")
    if orchestrator_success:
        success_rate = orchestrator_results.get('success_rate', 0)
        logger.info(f"  Enrichment success rate: {success_rate:.1f}%")

    logger.info(f"File Processing: {'PASS' if file_success else 'FAIL'}")
    logger.info(f"CLI Integration: {'PASS' if cli_success else 'FAIL'}")

    logger.info(f"\nOverall Result: {'PASS' if overall_results['overall_success'] else 'FAIL'}")
    logger.info(f"Test Duration: {overall_results['duration']:.1f} seconds")

    return overall_results


def main():
    """Main test execution function."""
    try:
        results = run_comprehensive_test()

        # Save results to file
        results_file = Path("enrichment_test_results.json")
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)

        logger.info(f"\nDetailed results saved to: {results_file}")

        # Return appropriate exit code
        return 0 if results['overall_success'] else 1

    except Exception as e:
        logger.error(f"Test execution failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())