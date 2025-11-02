"""
Collection orchestration system for managing multiple threat intelligence sources.

This module provides the main collection runner that manages multiple sources
concurrently, handles scheduling, caching, and coordination between collectors.
"""

import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..utils.env import load
from .example_public import ExamplePublicCollector
from .virustotal import VirusTotalCollector
from .abuse_ch import URLhausCollector, MalwareBazaarCollector, ThreatFoxCollector
from .otx_shodan import OTXCollector, ShodanCollector

logger = logging.getLogger(__name__)


class CollectionOrchestrator:
    """Orchestrates collection from multiple threat intelligence sources."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the collection orchestrator.
        
        Args:
            config: Optional configuration override
        """
        self.config = config or load()
        self.collectors = self._initialize_collectors()
        
        # Set up output tracking
        self.results_dir = Path("data/raw")
        self.results_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Initialized orchestrator with {len(self.collectors)} collectors")
    
    def _initialize_collectors(self) -> Dict[str, Any]:
        """Initialize all available collectors."""
        collectors = {}
        
        # Get sources configuration - handle both list and dict formats
        sources_config = self.config.get('sources', [])
        if isinstance(sources_config, list):
            # Convert list format to dict format for easier access
            sources_dict = {source['key']: source for source in sources_config}
        else:
            sources_dict = sources_config
        
        # Initialize each collector type
        collector_classes = [
            ('example_public', ExamplePublicCollector),
            ('virustotal_intel', VirusTotalCollector),  # Match config key
            ('urlhaus_recent', URLhausCollector),       # Match config key
            ('malwarebazaar_recent', MalwareBazaarCollector),  # Match config key
            ('threatfox', ThreatFoxCollector),          # Keep as-is (no config needed)
            ('otx_indicators', OTXCollector),           # Match config key
            ('shodan_honeypot', ShodanCollector),       # Match config key
        ]
        
        for source_name, collector_class in collector_classes:
            try:
                # Check if source is enabled in config
                source_config = sources_dict.get(source_name, {})
                if not source_config.get('enabled', True):
                    logger.info(f"Skipping disabled source: {source_name}")
                    continue
                
                # Initialize collector
                collector = collector_class(self.config)
                
                # Check if collector is available (has required config/keys)
                if collector.is_available():
                    collectors[source_name] = collector
                    logger.info(f"Initialized collector: {source_name}")
                else:
                    logger.warning(f"Collector not available: {source_name} (check configuration)")
                    
            except Exception as e:
                logger.error(f"Failed to initialize collector {source_name}: {e}")
        
        return collectors
    
    def run_all_sources(self, date: Optional[str] = None, 
                       concurrent: bool = True) -> Dict[str, str]:
        """
        Run collection for all available sources.
        
        Args:
            date: Date string in YYYY-MM-DD format, defaults to today
            concurrent: Whether to run sources concurrently
            
        Returns:
            Dictionary mapping source names to output file paths
        """
        if date is None:
            date = datetime.now().strftime("%Y-%m-%d")
        
        logger.info(f"Starting collection run for {date} (concurrent={concurrent})")
        
        results = {}
        
        if concurrent and len(self.collectors) > 1:
            results = self._run_concurrent_collection(date)
        else:
            results = self._run_sequential_collection(date)
        
        # Log summary
        successful = sum(1 for path in results.values() if Path(path).exists())
        logger.info(f"Collection complete: {successful}/{len(results)} sources successful")
        
        return results
    
    def _run_concurrent_collection(self, date: str) -> Dict[str, str]:
        """Run collection concurrently using ThreadPoolExecutor."""
        results = {}
        
        with ThreadPoolExecutor(max_workers=4) as executor:
            # Submit collection tasks
            future_to_source = {
                executor.submit(collector.collect, date): source_name
                for source_name, collector in self.collectors.items()
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_source):
                source_name = future_to_source[future]
                try:
                    output_path = future.result(timeout=300)  # 5 minute timeout per source
                    results[source_name] = output_path
                    logger.info(f"Completed collection for {source_name}: {output_path}")
                except Exception as e:
                    logger.error(f"Collection failed for {source_name}: {e}")
                    results[source_name] = str(self.results_dir / source_name / f"{date}.jsonl")
        
        return results
    
    def _run_sequential_collection(self, date: str) -> Dict[str, str]:
        """Run collection sequentially."""
        results = {}
        
        for source_name, collector in self.collectors.items():
            try:
                logger.info(f"Starting collection for {source_name}")
                output_path = collector.collect(date)
                results[source_name] = output_path
                logger.info(f"Completed collection for {source_name}: {output_path}")
            except Exception as e:
                logger.error(f"Collection failed for {source_name}: {e}")
                results[source_name] = str(self.results_dir / source_name / f"{date}.jsonl")
        
        return results
    
    def run_single_source(self, source_name: str, 
                         date: Optional[str] = None) -> Optional[str]:
        """
        Run collection for a single source.
        
        Args:
            source_name: Name of the source to collect
            date: Date string in YYYY-MM-DD format
            
        Returns:
            Output file path or None if failed
        """
        if source_name not in self.collectors:
            logger.error(f"Unknown source: {source_name}")
            logger.info(f"Available sources: {list(self.collectors.keys())}")
            return None
        
        try:
            collector = self.collectors[source_name]
            output_path = collector.collect(date)
            logger.info(f"Collection complete for {source_name}: {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"Collection failed for {source_name}: {e}")
            return None
    
    def get_collection_status(self, date: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
        """
        Get status of collection files for the given date.
        
        Args:
            date: Date string in YYYY-MM-DD format
            
        Returns:
            Dictionary with status information for each source
        """
        if date is None:
            date = datetime.now().strftime("%Y-%m-%d")
        
        status = {}
        
        for source_name in self.collectors:
            source_dir = self.results_dir / source_name
            output_file = source_dir / f"{date}.jsonl"
            
            source_status = {
                'file_exists': output_file.exists(),
                'file_path': str(output_file),
                'file_size': output_file.stat().st_size if output_file.exists() else 0,
                'line_count': self._count_lines(output_file) if output_file.exists() else 0
            }
            
            if output_file.exists():
                source_status['last_modified'] = datetime.fromtimestamp(
                    output_file.stat().st_mtime
                ).isoformat()
            
            status[source_name] = source_status
        
        return status
    
    def _count_lines(self, file_path: Path) -> int:
        """Count lines in a JSONL file."""
        try:
            with open(file_path, 'r') as f:
                return sum(1 for line in f if line.strip())
        except Exception:
            return 0
    
    def list_available_sources(self) -> Dict[str, Dict[str, Any]]:
        """List all available sources and their status."""
        sources = {}
        
        for source_name, collector in self.collectors.items():
            sources[source_name] = {
                'available': collector.is_available(),
                'class': collector.__class__.__name__,
                'source_config': collector.source_config
            }
        
        return sources


def main():
    """Main entry point for running collection."""
    import argparse
    import sys
    
    parser = argparse.ArgumentParser(description='Run threat intelligence collection')
    parser.add_argument('--date', help='Date to collect (YYYY-MM-DD), defaults to today')
    parser.add_argument('--source', help='Specific source to collect from')
    parser.add_argument('--sequential', action='store_true', 
                       help='Run sources sequentially instead of concurrently')
    parser.add_argument('--status', action='store_true', 
                       help='Show collection status for date')
    parser.add_argument('--list-sources', action='store_true', 
                       help='List available sources')
    
    args = parser.parse_args()
    
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    try:
        orchestrator = CollectionOrchestrator()
        
        if args.list_sources:
            sources = orchestrator.list_available_sources()
            print("\nAvailable sources:")
            for source_name, info in sources.items():
                status = "✓" if info['available'] else "✗"
                print(f"  {status} {source_name} ({info['class']})")
            return
        
        if args.status:
            status = orchestrator.get_collection_status(args.date)
            print(f"\nCollection status for {args.date or 'today'}:")
            for source_name, info in status.items():
                exists = "✓" if info['file_exists'] else "✗"
                count = info['line_count']
                print(f"  {exists} {source_name}: {count} indicators")
            return
        
        if args.source:
            # Run single source
            result = orchestrator.run_single_source(args.source, args.date)
            if result:
                print(f"Collection complete: {result}")
            else:
                print(f"Collection failed for {args.source}")
                sys.exit(1)
        else:
            # Run all sources
            results = orchestrator.run_all_sources(args.date, not args.sequential)
            
            print(f"\nCollection Results:")
            for source_name, output_path in results.items():
                exists = "✓" if Path(output_path).exists() else "✗"
                print(f"  {exists} {source_name}: {output_path}")
    
    except Exception as e:
        logger.error(f"Collection failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()