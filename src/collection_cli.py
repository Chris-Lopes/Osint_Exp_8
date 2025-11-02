#!/usr/bin/env python3
"""
Command-line interface for the OSINT threat aggregation system.

This module provides comprehensive CLI functionality for managing
data collection, monitoring system health, and reviewing collection history.
"""

import argparse
import json
import logging
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any

# Set up package structure for relative imports
current_dir = Path(__file__).parent
parent_dir = current_dir.parent

# Add parent directory to path so src can be imported as a package
sys.path.insert(0, str(parent_dir))

# Make src act as the top-level package
import src
sys.modules['src'] = src

# Now import modules using relative imports from the src package
try:
    from src.collectors.enhanced_orchestrator import EnhancedCollectionOrchestrator
    from src.normalizers.normalize_run import NormalizationProcessor
    from src.enrichment.orchestrator import EnrichmentOrchestrator
except ImportError as e:
    print(f"Import error: {e}")
    print("Make sure you're running this from the src directory or with proper PYTHONPATH")
    sys.exit(1)


def setup_logging(level: str = "INFO", log_file: str = None):
    """Set up logging configuration."""
    log_level = getattr(logging, level.upper(), logging.INFO)
    
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    
    handlers = [console_handler]
    
    # File handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        handlers.append(file_handler)
    
    logging.basicConfig(
        level=log_level,
        handlers=handlers,
        force=True
    )


def format_json_output(data: Dict[str, Any], indent: int = 2) -> str:
    """Format data as pretty JSON."""
    return json.dumps(data, indent=indent, default=str, sort_keys=True)


def format_table_output(data: Dict[str, Any], title: str = None) -> str:
    """Format data as a simple table."""
    output = []
    
    if title:
        output.append(f"\n{title}")
        output.append("=" * len(title))
    
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, (dict, list)):
                output.append(f"{key}: {json.dumps(value, default=str)}")
            else:
                output.append(f"{key}: {value}")
    else:
        output.append(str(data))
    
    return "\n".join(output)


def cmd_collect(args, orchestrator: EnhancedCollectionOrchestrator):
    """Handle collection commands."""
    print(f"Starting collection for {args.date or 'today'}...")
    
    if args.source:
        # Single source collection
        result = orchestrator.base_orchestrator.run_single_source(args.source, args.date)
        if result:
            print(f"✓ Collection complete: {result}")
            return 0
        else:
            print(f"✗ Collection failed for {args.source}")
            return 1
    else:
        # Full scheduled collection
        results = orchestrator.run_scheduled_collection(
            date=args.date,
            force=args.force,
            max_concurrent=args.max_concurrent,
            timeout_minutes=args.timeout
        )
        
        if args.json:
            print(format_json_output(results))
        else:
            status = results['status']
            print(f"Collection Status: {status}")
            print(f"Sources Attempted: {results.get('sources_attempted', 0)}")
            print(f"Sources Successful: {results.get('sources_successful', 0)}")
            print(f"Total Indicators: {results.get('total_indicators', 0)}")
            print(f"Duration: {results.get('duration_seconds', 0):.1f} seconds")
            
            if args.verbose:
                print("\nSource Details:")
                for source_name, source_result in results.get('sources', {}).items():
                    status_icon = "✓" if source_result.get('status') == 'success' else "✗"
                    count = source_result.get('indicator_count', 0)
                    print(f"  {status_icon} {source_name}: {count} indicators")
        
        return 0 if results['status'] != 'failed' else 1


def cmd_status(args, orchestrator: EnhancedCollectionOrchestrator):
    """Handle status commands."""
    status = orchestrator.get_collection_status(args.date)
    
    if args.json:
        print(format_json_output(status))
        return 0
    
    # Formatted output
    print(f"\nCollection Status for {status['date']}")
    print("=" * 40)
    
    overall = status['overall']
    print(f"Total Sources: {overall['total_sources']}")
    print(f"Healthy: {overall['healthy_sources']}")
    print(f"Failing: {overall['failing_sources']}")
    print(f"Disabled: {overall['disabled_sources']}")
    print(f"Currently Running: {overall['currently_running']}")
    print(f"Files Exist Today: {overall['files_exist_today']}")
    print(f"Total Indicators Today: {overall['total_indicators_today']}")
    
    if args.verbose:
        print(f"\nSource Details:")
        for source_name, source_info in status['sources'].items():
            health_icon = {
                'healthy': '✓',
                'failing': '⚠',
                'disabled': '✗',
                'unknown': '?'
            }.get(source_info.get('health_status', 'unknown'), '?')
            
            count = source_info.get('line_count', 0)
            failures = source_info.get('consecutive_failures', 0)
            running = " (RUNNING)" if source_info.get('currently_running') else ""
            
            print(f"  {health_icon} {source_name}: {count} indicators, "
                  f"{failures} failures{running}")
    
    return 0


def cmd_health(args, orchestrator: EnhancedCollectionOrchestrator):
    """Handle health check commands."""
    print("Running health check...")
    health = orchestrator.run_health_check()
    
    if args.json:
        print(format_json_output(health))
        return 0
    
    # Formatted output
    overall = health['overall']
    print(f"\nOverall Health: {overall['status'].upper()}")
    print(f"Healthy Sources: {overall['healthy_sources']}/{overall['total_sources']} "
          f"({overall['health_percentage']:.1f}%)")
    
    print(f"\nSource Health:")
    for source_name, source_health in health['sources'].items():
        status = source_health.get('status', 'unknown')
        icon = {'healthy': '✓', 'unhealthy': '✗', 'error': '⚠'}.get(status, '?')
        
        message = ""
        if status == 'error':
            message = f" - {source_health.get('message', 'Unknown error')}"
        elif status == 'unhealthy':
            failures = source_health.get('consecutive_failures', 0)
            if failures > 0:
                message = f" - {failures} consecutive failures"
        
        print(f"  {icon} {source_name}: {status.upper()}{message}")
    
    return 0 if overall['status'] != 'unhealthy' else 1


def cmd_history(args, orchestrator: EnhancedCollectionOrchestrator):
    """Handle history commands."""
    history = orchestrator.cache.get_collection_history(
        source_name=args.source,
        days=args.days
    )
    
    if args.json:
        print(format_json_output(history))
        return 0
    
    # Formatted output
    if not history:
        print("No collection history found")
        return 0
    
    print(f"\nCollection History ({args.days} days)")
    print("=" * 50)
    
    for run in history:
        status_icon = "✓" if run['status'] == 'success' else "✗"
        source = run['source_name']
        date = run['collection_date']
        count = run.get('indicator_count', 0)
        start_time = run.get('start_time', '')[:19] if run.get('start_time') else 'unknown'
        
        print(f"{status_icon} {source} [{date}] - {count} indicators at {start_time}")
        
        if run.get('error_message') and args.verbose:
            print(f"    Error: {run['error_message']}")
    
    return 0


def cmd_sources(args, orchestrator: EnhancedCollectionOrchestrator):
    """Handle sources listing commands."""
    sources = orchestrator.base_orchestrator.list_available_sources()
    stats = orchestrator.cache.get_source_stats()
    
    if args.json:
        combined_data = {}
        for source_name, source_info in sources.items():
            combined_data[source_name] = {
                **source_info,
                **stats.get(source_name, {})
            }
        print(format_json_output(combined_data))
        return 0
    
    # Formatted output
    print(f"\nAvailable Sources ({len(sources)})")
    print("=" * 30)
    
    for source_name, source_info in sources.items():
        available_icon = "✓" if source_info['available'] else "✗"
        source_stats = stats.get(source_name, {})
        
        total_indicators = source_stats.get('total_indicators', 0)
        failures = source_stats.get('consecutive_failures', 0)
        
        print(f"{available_icon} {source_name} ({source_info['class']})")
        
        if args.verbose:
            print(f"    Total indicators: {total_indicators}")
            print(f"    Consecutive failures: {failures}")
            if source_stats.get('last_successful_run'):
                print(f"    Last success: {source_stats['last_successful_run'][:19]}")
            print(f"    Avg runtime: {source_stats.get('avg_runtime_seconds', 0):.1f}s")
    
    return 0


def cmd_cleanup(args, orchestrator: EnhancedCollectionOrchestrator):
    """Handle cleanup commands."""
    if not args.yes:
        print(f"This will delete collection data older than {args.days} days.")
        response = input("Continue? [y/N]: ")
        if response.lower() != 'y':
            print("Cleanup cancelled")
            return 0
    
    print(f"Cleaning up data older than {args.days} days...")
    results = orchestrator.cleanup_old_data(args.days)
    
    if args.json:
        print(format_json_output(results))
    else:
        print(f"Cleanup complete:")
        print(f"  Files deleted: {results['files_deleted']}")
        print(f"  Space freed: {results['bytes_freed'] / 1024 / 1024:.1f} MB")
        print(f"  Cutoff date: {results['cutoff_date']}")
    
    return 0


def cmd_normalize(args):
    """Handle normalize commands."""
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
                print(format_json_output(validation_results))
            else:
                print(f"\nValidation Results")
                print("=" * 20)
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
                print(format_json_output(results))
            else:
                print(f"\nNormalization Results")
                print("=" * 25)
                print(f"Status: {results['status']}")
                print(f"Files processed: {results['files_processed']}")
                print(f"Total indicators: {results['total_indicators']}")
                print(f"Normalized successfully: {results['normalized_indicators']}")
                print(f"Success rate: {results.get('overall_success_rate', 0):.1f}%")
                
                if args.verbose and results.get('source_summary'):
                    print(f"\nBy Source:")
                    for source, summary in results['source_summary'].items():
                        print(f"  {source}: {summary['normalized']}/{summary['indicators']} indicators")
        
        return 0
        
    except Exception as e:
        logging.error(f"Normalization failed: {e}")
        return 1


def cmd_enrich(args):
    """Handle enrichment commands."""
    try:
        enrichment_orchestrator = EnrichmentOrchestrator(args.config_dir)
        
        if args.validate:
            # Validation mode - check if services are working
            results = {
                'geolocation_service': bool(enrichment_orchestrator.geolocation_service),
                'dns_service': bool(enrichment_orchestrator.dns_service),
                'asn_service': bool(enrichment_orchestrator.asn_service),
                'reputation_engine': bool(enrichment_orchestrator.reputation_engine)
            }
            
            if args.json:
                print(format_json_output(results))
            else:
                print(f"\nEnrichment Services Status")
                print("=" * 30)
                for service, status in results.items():
                    icon = "✓" if status else "✗"
                    print(f"{icon} {service}: {'Available' if status else 'Unavailable'}")
        
        else:
            # Enrichment mode
            input_dir = Path("data/processed")
            output_dir = Path("data/enriched")
            
            if not input_dir.exists():
                print("No processed data directory found. Run normalization first.")
                return 1
            
            # Get input files
            input_files = []
            if args.source:
                # Specific source
                pattern = f"*{args.source}*"
            else:
                pattern = "*"
            
            if args.date:
                pattern += f"_{args.date}*"
            
            pattern += ".jsonl"
            input_files = list(input_dir.rglob(pattern))
            
            if not input_files:
                print(f"No normalized data files found matching pattern: {pattern}")
                return 0
            
            # Process files
            all_results = []
            for input_file in input_files:
                print(f"Enriching {input_file.name}...")
                
                # Generate output filename
                output_file = output_dir / input_file.relative_to(input_dir)
                
                # Enrich file
                file_results = enrichment_orchestrator.enrich_from_file(input_file, output_file)
                all_results.append(file_results)
                
                if args.verbose:
                    success_rate = file_results['enriched_successfully'] / max(file_results['total_indicators'], 1) * 100
                    print(f"  ✓ {file_results['enriched_successfully']}/{file_results['total_indicators']} "
                          f"indicators enriched ({success_rate:.1f}%)")
            
            # Aggregate results
            total_indicators = sum(r['total_indicators'] for r in all_results)
            total_enriched = sum(r['enriched_successfully'] for r in all_results)
            total_errors = sum(r['enrichment_errors'] for r in all_results)
            
            summary = {
                'status': 'completed',
                'files_processed': len(all_results),
                'total_indicators': total_indicators,
                'enriched_successfully': total_enriched,
                'enrichment_errors': total_errors,
                'success_rate': total_enriched / max(total_indicators, 1) * 100,
                'processing_time': sum(r['processing_time'] for r in all_results)
            }
            
            if args.json:
                summary['file_results'] = all_results
                print(format_json_output(summary))
            else:
                print(f"\nEnrichment Results")
                print("=" * 20)
                print(f"Status: {summary['status']}")
                print(f"Files processed: {summary['files_processed']}")
                print(f"Total indicators: {summary['total_indicators']}")
                print(f"Enriched successfully: {summary['enriched_successfully']}")
                print(f"Errors: {summary['enrichment_errors']}")
                print(f"Success rate: {summary['success_rate']:.1f}%")
                print(f"Processing time: {summary['processing_time']:.1f}s")
        
        return 0
        
    except Exception as e:
        logging.error(f"Enrichment failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


def cmd_pipeline(args, orchestrator: EnhancedCollectionOrchestrator):
    """Handle pipeline commands for end-to-end processing."""
    try:
        results = {}
        
        if not args.skip_collection:
            print("Starting collection phase...")
            
            # Run collection
            collection_results = orchestrator.run_collection(
                source_name=None,  # All sources or filtered by args.sources
                date_str=None,  # Today
                max_concurrent=4,
                force_refresh=False
            )
            
            results['collection'] = collection_results
            
            if collection_results['status'] != 'completed':
                print(f"Collection failed: {collection_results.get('message', 'Unknown error')}")
                return 1
        
        if not args.skip_normalization:
            print("Starting normalization phase...")
            
            # Run normalization
            processor = NormalizationProcessor(args.config_dir)
            
            # Filter sources if specified
            source_filter = None
            if args.sources and len(args.sources) == 1:
                source_filter = args.sources[0]
            
            normalize_results = processor.normalize_batch(source_filter, None)
            results['normalization'] = normalize_results
            
            if normalize_results['status'] != 'completed':
                print(f"Normalization failed: {normalize_results.get('message', 'Unknown error')}")
                return 1
        
        if not args.skip_enrichment:
            print("Starting enrichment phase...")
            
            # Run enrichment
            enrichment_orchestrator = EnrichmentOrchestrator(args.config_dir)
            
            # Process normalized files
            input_dir = Path("data/processed")
            output_dir = Path("data/enriched")
            
            if not input_dir.exists():
                print("No processed data found for enrichment")
                return 1
            
            # Find files to enrich
            if args.sources:
                input_files = []
                for source in args.sources:
                    source_files = list(input_dir.glob(f"*{source}*.jsonl"))
                    input_files.extend(source_files)
            else:
                input_files = list(input_dir.glob("*.jsonl"))
            
            if not input_files:
                print("No normalized files found for enrichment")
                return 1
            
            # Enrich files
            enrichment_stats = {
                'files_processed': 0,
                'total_indicators': 0,
                'enriched_successfully': 0,
                'enrichment_errors': 0,
                'processing_time': 0
            }
            
            for input_file in input_files:
                output_file = output_dir / input_file.relative_to(input_dir)
                file_results = enrichment_orchestrator.enrich_from_file(input_file, output_file)
                
                enrichment_stats['files_processed'] += 1
                enrichment_stats['total_indicators'] += file_results['total_indicators']
                enrichment_stats['enriched_successfully'] += file_results['enriched_successfully']
                enrichment_stats['enrichment_errors'] += file_results['enrichment_errors']
                enrichment_stats['processing_time'] += file_results['processing_time']
            
            enrichment_stats['status'] = 'completed'
            enrichment_stats['success_rate'] = (
                enrichment_stats['enriched_successfully'] / 
                max(enrichment_stats['total_indicators'], 1) * 100
            )
            
            results['enrichment'] = enrichment_stats
        
        if args.json:
            print(format_json_output(results))
        else:
            print(f"\nPipeline Complete")
            print("=" * 20)
            
            if results.get('collection'):
                col_results = results['collection']
                print(f"Collection: {col_results.get('successful_sources', 0)} sources successful")
            
            if results.get('normalization'):
                norm_results = results['normalization']
                print(f"Normalization: {norm_results.get('normalized_indicators', 0)} indicators processed")
                print(f"Success rate: {norm_results.get('overall_success_rate', 0):.1f}%")
            
            if results.get('enrichment'):
                enrich_results = results['enrichment']
                print(f"Enrichment: {enrich_results.get('enriched_successfully', 0)} indicators enriched")
                print(f"Success rate: {enrich_results.get('success_rate', 0):.1f}%")
        
        return 0
        
    except Exception as e:
        logging.error(f"Pipeline failed: {e}")
        return 1


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Threat Intelligence Collection Management CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run collection for all sources
  python collection_cli.py collect
  
  # Run collection for specific source
  python collection_cli.py collect --source virustotal
  
  # Normalize collected data
  python collection_cli.py normalize
  
  # Normalize specific source
  python collection_cli.py normalize --source virustotal
  
  # Validate normalized data
  python collection_cli.py normalize --validate
  
  # Enrich normalized data  
  python collection_cli.py enrich
  
  # Enrich specific source
  python collection_cli.py enrich --source virustotal
  
  # Validate enrichment services
  python collection_cli.py enrich --validate
  
  # Run end-to-end pipeline
  python collection_cli.py pipeline
  
  # Check collection status
  python collection_cli.py status --verbose
  
  # Run health check
  python collection_cli.py health
  
  # View collection history
  python collection_cli.py history --days 7
  
  # List available sources
  python collection_cli.py sources --verbose
  
  # Clean up old data
  python collection_cli.py cleanup --days 30
        """
    )
    
    parser.add_argument('--json', action='store_true',
                       help='Output in JSON format')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')
    parser.add_argument('--log-level', default='INFO',
                       choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                       help='Set logging level')
    parser.add_argument('--log-file',
                       help='Log to file instead of console')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Collect command
    collect_parser = subparsers.add_parser('collect', help='Run threat intelligence collection')
    collect_parser.add_argument('--date', help='Date to collect (YYYY-MM-DD), defaults to today')
    collect_parser.add_argument('--source', help='Specific source to collect from')
    collect_parser.add_argument('--force', action='store_true',
                               help='Force collection even if cached')
    collect_parser.add_argument('--max-concurrent', type=int, default=4,
                               help='Maximum concurrent collections')
    collect_parser.add_argument('--timeout', type=int, default=30,
                               help='Timeout per source in minutes')
    
    # Status command
    status_parser = subparsers.add_parser('status', help='Show collection status')
    status_parser.add_argument('--date', help='Date to check status for (YYYY-MM-DD)')
    
    # Health command
    health_parser = subparsers.add_parser('health', help='Run health check on all sources')
    
    # History command
    history_parser = subparsers.add_parser('history', help='Show collection history')
    history_parser.add_argument('--source', help='Filter by specific source')
    history_parser.add_argument('--days', type=int, default=7,
                               help='Number of days of history to show')
    
    # Sources command
    sources_parser = subparsers.add_parser('sources', help='List available sources')
    
    # Cleanup command
    cleanup_parser = subparsers.add_parser('cleanup', help='Clean up old collection data')
    cleanup_parser.add_argument('--days', type=int, default=30,
                               help='Keep data newer than this many days')
    cleanup_parser.add_argument('--yes', action='store_true',
                               help='Skip confirmation prompt')
    
    # Normalize command
    normalize_parser = subparsers.add_parser('normalize', help='Normalize collected threat intelligence data')
    normalize_parser.add_argument('--source', help='Specific source to normalize')
    normalize_parser.add_argument('--date', help='Specific date to normalize (YYYY-MM-DD)')
    normalize_parser.add_argument('--validate', action='store_true', help='Validate normalized data')
    normalize_parser.add_argument('--config-dir', default='config', help='Configuration directory')
    
    # Enrichment command
    enrich_parser = subparsers.add_parser('enrich', help='Enrich normalized threat intelligence data')
    enrich_parser.add_argument('--source', help='Specific source to enrich')
    enrich_parser.add_argument('--date', help='Specific date to enrich (YYYY-MM-DD)')
    enrich_parser.add_argument('--validate', action='store_true', help='Validate enrichment services')
    enrich_parser.add_argument('--config-dir', default='config', help='Configuration directory')
    
    # Pipeline command for end-to-end processing
    pipeline_parser = subparsers.add_parser('pipeline', help='Run end-to-end data pipeline')
    pipeline_parser.add_argument('--sources', nargs='+', help='Sources to collect and normalize')
    pipeline_parser.add_argument('--skip-collection', action='store_true', help='Skip collection, normalize only')
    pipeline_parser.add_argument('--skip-normalization', action='store_true', help='Skip normalization, collect only')
    pipeline_parser.add_argument('--skip-enrichment', action='store_true', help='Skip enrichment, process only')
    pipeline_parser.add_argument('--config-dir', default='config', help='Configuration directory')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    # Setup logging
    setup_logging(args.log_level, args.log_file)
    
    try:
        # Initialize orchestrator
        orchestrator = EnhancedCollectionOrchestrator()
        
        # Dispatch to command handlers
        if args.command == 'collect':
            return cmd_collect(args, orchestrator)
        elif args.command == 'status':
            return cmd_status(args, orchestrator)
        elif args.command == 'health':
            return cmd_health(args, orchestrator)
        elif args.command == 'history':
            return cmd_history(args, orchestrator)
        elif args.command == 'sources':
            return cmd_sources(args, orchestrator)
        elif args.command == 'cleanup':
            return cmd_cleanup(args, orchestrator)
        elif args.command == 'normalize':
            return cmd_normalize(args)
        elif args.command == 'enrich':
            return cmd_enrich(args)
        elif args.command == 'pipeline':
            return cmd_pipeline(args, orchestrator)
        else:
            print(f"Unknown command: {args.command}")
            return 1
            
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        return 1
    except Exception as e:
        logging.error(f"Command failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())