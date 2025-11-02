#!/usr/bin/env python3
"""
Normalization Engine - Production Execution

This script runs the normalization system to transform collected threat intelligence data
into the standardized format for further processing.
"""

import json
import logging
import tempfile
from datetime import datetime
from pathlib import Path

from src.normalizers.normalize_run import NormalizationProcessor
from src.normalizers.engine import IndicatorNormalizer
from src.normalizers.schema import NormalizedIndicator, IndicatorType

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


def create_sample_data():
    """Create sample data for normalization processing."""
    sample_data = {
        'virustotal': [
            {
                'id': 'vt_ip_1',
                'type': 'ip_address',
                'attributes': {
                    'country': 'US',
                    'as_owner': 'Example Corp',
                    'last_analysis_stats': {
                        'malicious': 5,
                        'clean': 80,
                        'undetected': 3
                    }
                },
                'value': '192.168.1.100'
            }
        ],
        'urlhaus': [
            {
                'id': '12345',
                'url': 'http://example-malware.com/payload.exe',
                'url_status': 'online',
                'threat': 'malware_download',
                'tags': ['exe', 'trojan'],
                'dateadded': '2025-09-22 10:30:00'
            }
        ]
    }
    
    return sample_data


def load_real_sample_data():
    """Load real sample data from processed directory for normalization testing."""
    import json
    from pathlib import Path
    
    processed_dir = Path('data/processed')
    
    if not processed_dir.exists():
        logger.warning(f"Processed data directory not found: {processed_dir}")
        logger.info("Falling back to sample data for normalization testing")
        return create_sample_data()
    
    sample_data = {}
    
    # Load a few examples from each source
    for source_dir in processed_dir.iterdir():
        if source_dir.is_dir():
            source_name = source_dir.name
            sample_data[source_name] = []
            
            for jsonl_file in source_dir.glob('*.jsonl'):
                try:
                    with open(jsonl_file, 'r') as f:
                        for line_num, line in enumerate(f, 1):
                            if line_num > 3:  # Only take first 3 indicators per source
                                break
                                
                            line = line.strip()
                            if not line:
                                continue
                                
                            try:
                                data = json.loads(line)
                                sample_data[source_name].append(data)
                            except json.JSONDecodeError:
                                continue
                except Exception as e:
                    logger.warning(f"Failed to read {jsonl_file}: {e}")
    
    if not any(sample_data.values()):
        logger.warning("No real data found, falling back to sample data")
        return create_sample_data()
    
    logger.info(f"Loaded real sample data from {len(sample_data)} sources")
    return sample_data


def create_sample_files(sample_data):
    """Create sample files for processing."""
    temp_dir = Path(tempfile.mkdtemp(prefix='norm_exec_'))
    raw_dir = temp_dir / 'data' / 'raw'
    
    for source_name, indicators in sample_data.items():
        source_dir = raw_dir / source_name
        source_dir.mkdir(parents=True, exist_ok=True)
        
        # Create sample file for today
        sample_file = source_dir / f"{datetime.now().strftime('%Y-%m-%d')}.jsonl"
        
        with open(sample_file, 'w') as f:
            for indicator in indicators:
                f.write(json.dumps(indicator) + '\n')
        
        logger.info(f"Created sample file: {sample_file}")
    
    return temp_dir


def run_individual_normalization():
    """Run individual indicator normalization."""
    print("\n" + "="*50)
    print("RUNNING INDIVIDUAL NORMALIZATION")
    print("="*50)
    
    normalizer = IndicatorNormalizer()
    sample_data = load_real_sample_data()
    
    for source_name, indicators in sample_data.items():
        print(f"\nProcessing {source_name}:")
        print("-" * 20)
        
        for i, raw_indicator in enumerate(indicators):
            result = normalizer.normalize_indicator(raw_indicator, source_name)
            
            if result.success and result.indicator:
                print(f"✓ Indicator {i+1}: {result.indicator.indicator_type.value} - {result.indicator.value}")
                print(f"  Confidence: {result.indicator.confidence}")
                print(f"  Source: {result.indicator.source_metadata.source_name}")
            else:
                print(f"✗ Indicator {i+1}: Failed - {', '.join(result.errors)}")
            
            if result.warnings:
                print(f"  Warnings: {', '.join(result.warnings)}")


def run_batch_normalization():
    """Run batch file normalization."""
    print("\n" + "="*50)
    print("RUNNING BATCH NORMALIZATION")
    print("="*50)
    
    # Create sample data and files
    sample_data = create_sample_data()
    temp_dir = create_sample_files(sample_data)
    
    try:
        # Change to temp directory for processing
        original_cwd = Path.cwd()
        import os
        os.chdir(temp_dir)
        
        # Initialize processor
        processor = NormalizationProcessor()
        
        # Run batch normalization
        results = processor.normalize_batch()
        
        print(f"\nBatch Results:")
        print(f"  Status: {results['status']}")
        print(f"  Files processed: {results['files_processed']}")
        print(f"  Total indicators: {results['total_indicators']}")
        print(f"  Normalized successfully: {results['normalized_indicators']}")
        print(f"  Success rate: {results.get('overall_success_rate', 0):.1f}%")
        
        # Check output files
        processed_dir = Path("data/processed")
        if processed_dir.exists():
            print(f"\nGenerated files:")
            for file_path in processed_dir.rglob("*.jsonl"):
                file_size = file_path.stat().st_size
                print(f"  {file_path}: {file_size} bytes")
                
                # Show sample content
                with open(file_path) as f:
                    first_line = f.readline().strip()
                    if first_line:
                        try:
                            sample = json.loads(first_line)
                            print(f"    Sample: {sample.get('indicator_type', 'unknown')} - {sample.get('value', 'no value')[:50]}")
                        except:
                            print(f"    Sample: (parsing error)")
        
        # Validate output
        print(f"\nValidation Results:")
        for file_path in processed_dir.rglob("*.jsonl"):
            validation = processor.validate_normalized_data(file_path)
            status = "✓" if validation['is_valid'] else "✗"
            print(f"  {status} {file_path.name}: {validation['total_indicators']} indicators")
            
            if validation['validation_errors']:
                for error in validation['validation_errors'][:3]:  # Show first 3 errors
                    print(f"      Error: {error}")
        
    finally:
        # Restore original directory
        os.chdir(original_cwd)
        
        # Cleanup temp directory
        import shutil
        try:
            shutil.rmtree(temp_dir)
            print(f"\nCleaned up temporary directory: {temp_dir}")
        except Exception as e:
            print(f"\nWarning: Could not clean up {temp_dir}: {e}")


def run_schema_validation():
    """Run schema validation with sample inputs."""
    print("\n" + "="*50)
    print("RUNNING SCHEMA VALIDATION")
    print("="*50)
    
    # Test valid indicator
    try:
        valid_indicator = NormalizedIndicator(
            id="exec_123",
            indicator_type=IndicatorType.IPV4,
            value="192.168.1.1",
            confidence=85,
            source_metadata={
                'source_name': 'execution_test',
                'collection_date': datetime.now(),
                'original_data': {'test': 'data'}
            }
        )
        print("✓ Valid indicator creation succeeded")
        print(f"  Type: {valid_indicator.indicator_type.value}")
        print(f"  Value: {valid_indicator.value}")
        print(f"  Confidence: {valid_indicator.confidence}")
        
    except Exception as e:
        print(f"✗ Valid indicator creation failed: {e}")
    
    # Test invalid indicators
    invalid_tests = [
        {
            'name': 'Invalid confidence (too high)',
            'data': {
                'id': 'exec_invalid_1',
                'indicator_type': IndicatorType.IPV4,
                'value': '192.168.1.1',
                'confidence': 150,  # Invalid: > 100
                'source_metadata': {'source_name': 'test'}
            }
        }
    ]
    
    for test in invalid_tests:
        try:
            NormalizedIndicator(**test['data'])
            print(f"✗ {test['name']}: Should have failed but didn't")
        except Exception as e:
            print(f"✓ {test['name']}: Correctly rejected - {type(e).__name__}")


def main():
    """Run normalization execution."""
    print("OSINT Normalization Engine - Production Execution")
    print("===============================================")
    
    try:
        run_schema_validation()
        run_individual_normalization()
        run_batch_normalization()
        
        print("\n" + "="*50)
        print("EXECUTION COMPLETED")
        print("="*50)
        print("✓ Schema validation executed")
        print("✓ Individual normalization executed")
        print("✓ Batch normalization executed")
        
    except Exception as e:
        print(f"\n✗ Execution failed: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())