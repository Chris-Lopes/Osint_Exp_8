"""
Normalization runner for processing collected threat intelligence data.

This module provides the main entry point for normalizing collected data
from raw format to standardized STIX-like format.
"""

import argparse
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from .engine import IndicatorNormalizer
from .schema import NormalizedIndicator, NormalizationResult

logger = logging.getLogger(__name__)


class NormalizationProcessor:
    """Main processor for normalizing collected threat intelligence."""
    
    def __init__(self, config_dir: str = "config"):
        """
        Initialize the normalization processor.
        
        Args:
            config_dir: Configuration directory path
        """
        self.normalizer = IndicatorNormalizer(config_dir)
        
        # Setup directories
        self.raw_dir = Path("data/raw")
        self.processed_dir = Path("data/processed")
        self.processed_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info("Initialized normalization processor")
    
    def find_raw_files(self, source_name: Optional[str] = None, 
                      date: Optional[str] = None) -> List[Path]:
        """
        Find raw collection files to normalize.
        
        Args:
            source_name: Optional source filter
            date: Optional date filter (YYYY-MM-DD)
            
        Returns:
            List of raw file paths to process
        """
        raw_files = []
        
        if source_name:
            # Process specific source
            source_dir = self.raw_dir / source_name
            if not source_dir.exists():
                logger.warning(f"Source directory not found: {source_dir}")
                return []
            
            if date:
                # Specific date file
                date_file = source_dir / f"{date}.jsonl"
                if date_file.exists():
                    raw_files.append(date_file)
            else:
                # All files for source
                raw_files.extend(source_dir.glob("*.jsonl"))
        else:
            # Process all sources
            for source_dir in self.raw_dir.iterdir():
                if not source_dir.is_dir():
                    continue
                
                if date:
                    # Specific date across all sources
                    date_file = source_dir / f"{date}.jsonl"
                    if date_file.exists():
                        raw_files.append(date_file)
                else:
                    # All files for all sources
                    raw_files.extend(source_dir.glob("*.jsonl"))
        
        return sorted(raw_files)
    
    def load_raw_indicators(self, file_path: Path) -> Iterator[Tuple[Dict[str, Any], int]]:
        """
        Load raw indicators from a JSONL file.
        
        Args:
            file_path: Path to raw data file
            
        Yields:
            Tuple of (indicator_data, line_number)
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        indicator_data = json.loads(line)
                        yield indicator_data, line_num
                    except json.JSONDecodeError as e:
                        logger.error(f"JSON decode error in {file_path}:{line_num}: {e}")
                        continue
                        
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")
    
    def normalize_file(self, raw_file: Path) -> Tuple[str, Dict[str, Any]]:
        """
        Normalize a single raw data file.
        
        Args:
            raw_file: Path to raw data file
            
        Returns:
            Tuple of (output_file_path, processing_stats)
        """
        # Extract source name from file path
        source_name = raw_file.parent.name
        file_date = raw_file.stem  # e.g., "2025-09-22"
        
        # Create output directory and file
        output_dir = self.processed_dir / source_name
        output_dir.mkdir(parents=True, exist_ok=True)
        output_file = output_dir / f"{file_date}.jsonl"
        
        logger.info(f"Normalizing {raw_file} -> {output_file}")
        
        # Processing statistics
        stats = {
            'source_name': source_name,
            'input_file': str(raw_file),
            'output_file': str(output_file),
            'start_time': datetime.now().isoformat(),
            'total_indicators': 0,
            'normalized_successfully': 0,
            'normalization_errors': 0,
            'errors': [],
            'warnings': []
        }
        
        try:
            with open(output_file, 'w', encoding='utf-8') as out_f:
                for raw_data, line_num in self.load_raw_indicators(raw_file):
                    stats['total_indicators'] += 1
                    
                    # Normalize the indicator
                    result = self.normalizer.normalize_indicator(raw_data, source_name)
                    
                    if result.success and result.indicator:
                        # Write normalized indicator
                        normalized_dict = result.indicator.dict()
                        out_f.write(json.dumps(normalized_dict, default=str) + '\n')
                        stats['normalized_successfully'] += 1
                    else:
                        stats['normalization_errors'] += 1
                        error_msg = f"Line {line_num}: {', '.join(result.errors)}"
                        stats['errors'].append(error_msg)
                        logger.warning(f"Normalization failed for {raw_file}:{line_num}: {result.errors}")
                    
                    # Collect warnings
                    if result.warnings:
                        warning_msg = f"Line {line_num}: {', '.join(result.warnings)}"
                        stats['warnings'].append(warning_msg)
        
        except Exception as e:
            error_msg = f"Failed to process file {raw_file}: {e}"
            stats['errors'].append(error_msg)
            logger.error(error_msg)
        
        stats['end_time'] = datetime.now().isoformat()
        stats['success_rate'] = (
            stats['normalized_successfully'] / stats['total_indicators'] * 100
            if stats['total_indicators'] > 0 else 0
        )
        
        logger.info(f"Normalization complete: {stats['normalized_successfully']}/{stats['total_indicators']} "
                   f"indicators processed ({stats['success_rate']:.1f}% success)")
        
        return str(output_file), stats
    
    def normalize_batch(self, source_name: Optional[str] = None,
                       date: Optional[str] = None) -> Dict[str, Any]:
        """
        Normalize a batch of raw data files.
        
        Args:
            source_name: Optional source filter
            date: Optional date filter
            
        Returns:
            Batch processing results and statistics
        """
        start_time = datetime.now()
        logger.info(f"Starting batch normalization (source={source_name}, date={date})")
        
        # Find files to process
        raw_files = self.find_raw_files(source_name, date)
        
        if not raw_files:
            logger.warning("No raw files found to process")
            return {
                'status': 'no_files',
                'message': 'No raw files found to process',
                'files_processed': 0,
                'total_indicators': 0,
                'normalized_indicators': 0
            }
        
        # Process files
        batch_results = {
            'status': 'completed',
            'start_time': start_time.isoformat(),
            'files_processed': 0,
            'files_with_errors': 0,
            'total_indicators': 0,
            'normalized_indicators': 0,
            'normalization_errors': 0,
            'processing_details': [],
            'source_summary': {}
        }
        
        for raw_file in raw_files:
            try:
                output_file, file_stats = self.normalize_file(raw_file)
                
                batch_results['files_processed'] += 1
                batch_results['total_indicators'] += file_stats['total_indicators']
                batch_results['normalized_indicators'] += file_stats['normalized_successfully']
                batch_results['normalization_errors'] += file_stats['normalization_errors']
                
                if file_stats['errors']:
                    batch_results['files_with_errors'] += 1
                
                # Add to processing details
                batch_results['processing_details'].append(file_stats)
                
                # Update source summary
                source = file_stats['source_name']
                if source not in batch_results['source_summary']:
                    batch_results['source_summary'][source] = {
                        'files': 0,
                        'indicators': 0,
                        'normalized': 0,
                        'errors': 0
                    }
                
                summary = batch_results['source_summary'][source]
                summary['files'] += 1
                summary['indicators'] += file_stats['total_indicators']
                summary['normalized'] += file_stats['normalized_successfully']
                summary['errors'] += file_stats['normalization_errors']
                
            except Exception as e:
                logger.error(f"Failed to process {raw_file}: {e}")
                batch_results['files_with_errors'] += 1
        
        # Calculate final statistics
        end_time = datetime.now()
        batch_results['end_time'] = end_time.isoformat()
        batch_results['duration_seconds'] = (end_time - start_time).total_seconds()
        batch_results['overall_success_rate'] = (
            batch_results['normalized_indicators'] / batch_results['total_indicators'] * 100
            if batch_results['total_indicators'] > 0 else 0
        )
        
        logger.info(f"Batch normalization complete: {batch_results['files_processed']} files, "
                   f"{batch_results['normalized_indicators']}/{batch_results['total_indicators']} indicators "
                   f"({batch_results['overall_success_rate']:.1f}% success)")
        
        return batch_results
    
    def validate_normalized_data(self, file_path: Path) -> Dict[str, Any]:
        """
        Validate normalized data file for consistency and completeness.
        
        Args:
            file_path: Path to normalized data file
            
        Returns:
            Validation results
        """
        validation_results = {
            'file_path': str(file_path),
            'is_valid': True,
            'total_indicators': 0,
            'validation_errors': [],
            'warnings': [],
            'type_distribution': {},
            'source_distribution': {},
            'confidence_stats': {'min': 100, 'max': 0, 'avg': 0}
        }
        
        try:
            confidences = []
            
            with open(file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        indicator_data = json.loads(line)
                        validation_results['total_indicators'] += 1
                        
                        # Validate required fields
                        required_fields = ['id', 'indicator_type', 'value', 'confidence', 'source_metadata']
                        for field in required_fields:
                            if field not in indicator_data:
                                validation_results['validation_errors'].append(
                                    f"Line {line_num}: Missing required field '{field}'"
                                )
                                validation_results['is_valid'] = False
                        
                        # Collect statistics
                        if 'indicator_type' in indicator_data:
                            indicator_type = indicator_data['indicator_type']
                            validation_results['type_distribution'][indicator_type] = \
                                validation_results['type_distribution'].get(indicator_type, 0) + 1
                        
                        if 'source_metadata' in indicator_data and 'source_name' in indicator_data['source_metadata']:
                            source_name = indicator_data['source_metadata']['source_name']
                            validation_results['source_distribution'][source_name] = \
                                validation_results['source_distribution'].get(source_name, 0) + 1
                        
                        if 'confidence' in indicator_data:
                            confidence = indicator_data['confidence']
                            confidences.append(confidence)
                            
                    except json.JSONDecodeError as e:
                        validation_results['validation_errors'].append(
                            f"Line {line_num}: JSON decode error: {e}"
                        )
                        validation_results['is_valid'] = False
            
            # Calculate confidence statistics
            if confidences:
                validation_results['confidence_stats'] = {
                    'min': min(confidences),
                    'max': max(confidences),
                    'avg': sum(confidences) / len(confidences)
                }
                
        except Exception as e:
            validation_results['validation_errors'].append(f"File processing error: {e}")
            validation_results['is_valid'] = False
        
        return validation_results


def main():
    """Main entry point for normalization CLI."""
    parser = argparse.ArgumentParser(
        description="Normalize collected threat intelligence data",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Normalize all collected data
  python -m src.normalizers.normalize_run
  
  # Normalize specific source
  python -m src.normalizers.normalize_run --source virustotal
  
  # Normalize specific date
  python -m src.normalizers.normalize_run --date 2025-09-22
  
  # Validate normalized data
  python -m src.normalizers.normalize_run --validate
        """
    )
    
    parser.add_argument('--source', help='Specific source to normalize')
    parser.add_argument('--date', help='Specific date to normalize (YYYY-MM-DD)')
    parser.add_argument('--validate', action='store_true', help='Validate normalized data')
    parser.add_argument('--config-dir', default='config', help='Configuration directory')
    parser.add_argument('--json', action='store_true', help='Output results as JSON')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose logging')
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    try:
        processor = NormalizationProcessor(args.config_dir)
        
        if args.validate:
            # Validation mode
            processed_dir = Path("data/processed")
            if not processed_dir.exists():
                print("No processed data directory found")
                return 1
            
            validation_results = []
            for file_path in processed_dir.rglob("*.jsonl"):
                result = processor.validate_normalized_data(file_path)
                validation_results.append(result)
            
            if args.json:
                print(json.dumps(validation_results, indent=2, default=str))
            else:
                for result in validation_results:
                    status = "✓" if result['is_valid'] else "✗"
                    print(f"{status} {result['file_path']}: {result['total_indicators']} indicators")
                    if result['validation_errors'] and args.verbose:
                        for error in result['validation_errors']:
                            print(f"    Error: {error}")
        
        else:
            # Normalization mode
            results = processor.normalize_batch(args.source, args.date)
            
            if args.json:
                print(json.dumps(results, indent=2, default=str))
            else:
                print(f"Normalization Results:")
                print(f"  Status: {results['status']}")
                print(f"  Files processed: {results['files_processed']}")
                print(f"  Total indicators: {results['total_indicators']}")
                print(f"  Normalized successfully: {results['normalized_indicators']}")
                print(f"  Success rate: {results.get('overall_success_rate', 0):.1f}%")
                
                if args.verbose and results.get('source_summary'):
                    print(f"\nBy Source:")
                    for source, summary in results['source_summary'].items():
                        print(f"  {source}: {summary['normalized']}/{summary['indicators']} indicators")
        
        return 0
        
    except Exception as e:
        logging.error(f"Normalization failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())