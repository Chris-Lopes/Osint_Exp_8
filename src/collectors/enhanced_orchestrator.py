"""
Enhanced collection orchestration with scheduling, caching, and monitoring.

This module provides the main orchestration system that integrates scheduling,
caching, monitoring, and advanced collection management capabilities.
"""

import asyncio
import logging
import signal
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .scheduler import CollectionCache, CollectionScheduler
from .run_all import CollectionOrchestrator

logger = logging.getLogger(__name__)


class EnhancedCollectionOrchestrator:
    """Enhanced orchestration system with scheduling and caching."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the enhanced orchestrator.
        
        Args:
            config: Optional configuration override
        """
        self.base_orchestrator = CollectionOrchestrator(config)
        self.cache = CollectionCache()
        self.scheduler = CollectionScheduler(self.cache)
        
        # Monitoring and control
        self.is_running = False
        self.current_collections = {}  # source_name -> run_id
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        logger.info("Initialized enhanced collection orchestrator")
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully."""
        logger.info(f"Received signal {signum}, initiating graceful shutdown...")
        self.is_running = False
    
    def run_scheduled_collection(self, date: Optional[str] = None, 
                                force: bool = False,
                                max_concurrent: int = 4,
                                timeout_minutes: int = 30) -> Dict[str, Any]:
        """
        Run a scheduled collection with intelligent planning and monitoring.
        
        Args:
            date: Date to collect for (defaults to today)
            force: Force collection even if cached
            max_concurrent: Maximum concurrent collections
            timeout_minutes: Timeout per source in minutes
            
        Returns:
            Collection results and statistics
        """
        if date is None:
            date = datetime.now().strftime("%Y-%m-%d")
        
        start_time = datetime.now()
        logger.info(f"Starting scheduled collection for {date}")
        
        # Get available sources
        available_sources = list(self.base_orchestrator.collectors.keys())
        
        # Create collection plan
        plan = self.scheduler.create_collection_plan(available_sources, date, force)
        
        if not plan:
            logger.info("No sources need collection")
            return {
                'date': date,
                'status': 'skipped',
                'message': 'No sources need collection',
                'sources': {},
                'start_time': start_time.isoformat(),
                'end_time': datetime.now().isoformat(),
                'duration_seconds': 0
            }
        
        # Estimate collection time
        estimated_time = self.scheduler.estimate_collection_time(
            plan, concurrent=True, max_workers=max_concurrent
        )
        logger.info(f"Planning to collect {len(plan)} sources (estimated {estimated_time:.1f}s)")
        
        # Execute collection plan
        results = self._execute_collection_plan(
            plan, date, max_concurrent, timeout_minutes
        )
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        # Calculate statistics
        successful = sum(1 for r in results.values() if r.get('status') == 'success')
        failed = len(results) - successful
        total_indicators = sum(r.get('indicator_count', 0) for r in results.values())
        
        summary = {
            'date': date,
            'status': 'completed',
            'sources_planned': len(plan),
            'sources_attempted': len(results),
            'sources_successful': successful,
            'sources_failed': failed,
            'total_indicators': total_indicators,
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'duration_seconds': duration,
            'estimated_seconds': estimated_time,
            'sources': results
        }
        
        # Save collection state
        self.scheduler.save_collection_state(summary)
        
        logger.info(f"Collection complete: {successful}/{len(results)} sources successful, "
                   f"{total_indicators} indicators, {duration:.1f}s")
        
        return summary
    
    def _execute_collection_plan(self, plan: Dict[str, Dict[str, Any]], 
                                date: str, max_concurrent: int,
                                timeout_minutes: int) -> Dict[str, Dict[str, Any]]:
        """Execute the collection plan with monitoring."""
        results = {}
        self.is_running = True
        
        # Group sources by priority for batch execution
        priority_groups = {}
        for source_name, info in plan.items():
            priority = info['priority']
            if priority not in priority_groups:
                priority_groups[priority] = []
            priority_groups[priority].append(source_name)
        
        # Execute in priority order
        for priority in sorted(priority_groups.keys()):
            if not self.is_running:
                logger.info("Stopping collection due to shutdown signal")
                break
            
            sources_batch = priority_groups[priority]
            batch_results = self._run_concurrent_batch(
                sources_batch, date, max_concurrent, timeout_minutes
            )
            results.update(batch_results)
        
        return results
    
    def _run_concurrent_batch(self, sources: List[str], date: str,
                             max_concurrent: int, timeout_minutes: int) -> Dict[str, Dict[str, Any]]:
        """Run a batch of sources concurrently."""
        results = {}
        timeout_seconds = timeout_minutes * 60
        
        with ThreadPoolExecutor(max_workers=max_concurrent) as executor:
            # Submit collection tasks
            future_to_source = {}
            for source_name in sources:
                if not self.is_running:
                    break
                
                # Check rate limiting
                collector = self.base_orchestrator.collectors.get(source_name)
                if collector:
                    rate_limit = getattr(collector, 'rate_limit', 60)
                    if not self.cache.can_make_request(source_name, rate_limit):
                        logger.warning(f"Rate limit exceeded for {source_name}, skipping")
                        continue
                
                # Start collection run in cache
                run_id = self.cache.start_collection(source_name, date)
                self.current_collections[source_name] = run_id
                
                # Submit task
                future = executor.submit(
                    self._collect_with_monitoring, source_name, date, run_id
                )
                future_to_source[future] = source_name
            
            # Collect results as they complete
            for future in as_completed(future_to_source, timeout=timeout_seconds):
                source_name = future_to_source[future]
                
                try:
                    result = future.result(timeout=30)  # 30s timeout for result retrieval
                    results[source_name] = result
                    
                    if source_name in self.current_collections:
                        del self.current_collections[source_name]
                    
                    logger.info(f"Batch collection completed for {source_name}: "
                              f"{result.get('status', 'unknown')}")
                    
                except Exception as e:
                    logger.error(f"Batch collection failed for {source_name}: {e}")
                    
                    # Mark as failed in cache
                    if source_name in self.current_collections:
                        run_id = self.current_collections[source_name]
                        self.cache.finish_collection(run_id, 'failed', 0, str(e))
                        del self.current_collections[source_name]
                    
                    results[source_name] = {
                        'status': 'failed',
                        'error': str(e),
                        'indicator_count': 0,
                        'output_file': None
                    }
        
        return results
    
    def _collect_with_monitoring(self, source_name: str, date: str, 
                                run_id: int) -> Dict[str, Any]:
        """Collect from a single source with monitoring and caching."""
        try:
            collector = self.base_orchestrator.collectors.get(source_name)
            if not collector:
                raise ValueError(f"Collector not found: {source_name}")
            
            logger.info(f"Starting monitored collection for {source_name}")
            start_time = datetime.now()
            
            # Run collection
            output_file = collector.collect(date)
            
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            # Count indicators in output file
            indicator_count = self._count_indicators(output_file)
            
            # Update cache with success
            self.cache.finish_collection(
                run_id, 'success', indicator_count, None, output_file
            )
            
            return {
                'status': 'success',
                'indicator_count': indicator_count,
                'output_file': output_file,
                'duration_seconds': duration,
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat()
            }
            
        except Exception as e:
            logger.error(f"Monitored collection failed for {source_name}: {e}")
            
            # Update cache with failure
            self.cache.finish_collection(run_id, 'failed', 0, str(e))
            
            return {
                'status': 'failed',
                'error': str(e),
                'indicator_count': 0,
                'output_file': None
            }
    
    def _count_indicators(self, output_file: str) -> int:
        """Count indicators in a JSONL output file."""
        try:
            output_path = Path(output_file)
            if not output_path.exists():
                return 0
            
            with open(output_path, 'r') as f:
                return sum(1 for line in f if line.strip())
        except Exception as e:
            logger.error(f"Error counting indicators in {output_file}: {e}")
            return 0
    
    def get_collection_status(self, date: Optional[str] = None) -> Dict[str, Any]:
        """
        Get comprehensive collection status.
        
        Args:
            date: Date to check status for
            
        Returns:
            Detailed status information
        """
        if date is None:
            date = datetime.now().strftime("%Y-%m-%d")
        
        # Get base status from orchestrator
        base_status = self.base_orchestrator.get_collection_status(date)
        
        # Get enhanced status from cache
        source_stats = self.cache.get_source_stats()
        collection_history = self.cache.get_collection_history(days=1)
        
        # Combine information
        enhanced_status = {}
        for source_name, base_info in base_status.items():
            stats = source_stats.get(source_name, {})
            
            # Find today's collection attempts
            today_runs = [
                run for run in collection_history
                if run['source_name'] == source_name and run['collection_date'] == date
            ]
            
            enhanced_status[source_name] = {
                **base_info,
                'health_status': stats.get('status', 'unknown'),
                'consecutive_failures': stats.get('consecutive_failures', 0),
                'total_indicators_ever': stats.get('total_indicators', 0),
                'avg_runtime_seconds': stats.get('avg_runtime_seconds', 0),
                'last_successful_run': stats.get('last_successful_run'),
                'todays_attempts': len(today_runs),
                'latest_attempt': today_runs[0] if today_runs else None,
                'currently_running': source_name in self.current_collections
            }
        
        return {
            'date': date,
            'sources': enhanced_status,
            'overall': {
                'total_sources': len(enhanced_status),
                'healthy_sources': sum(1 for s in enhanced_status.values() 
                                     if s['health_status'] == 'healthy'),
                'failing_sources': sum(1 for s in enhanced_status.values() 
                                     if s['health_status'] == 'failing'),
                'disabled_sources': sum(1 for s in enhanced_status.values() 
                                      if s['health_status'] == 'disabled'),
                'currently_running': len(self.current_collections),
                'files_exist_today': sum(1 for s in enhanced_status.values() 
                                       if s['file_exists']),
                'total_indicators_today': sum(s['line_count'] for s in enhanced_status.values())
            }
        }
    
    def run_health_check(self) -> Dict[str, Any]:
        """Run a comprehensive health check of all sources."""
        logger.info("Running health check for all sources")
        
        health_results = {}
        available_sources = self.base_orchestrator.list_available_sources()
        
        for source_name, source_info in available_sources.items():
            try:
                collector = self.base_orchestrator.collectors.get(source_name)
                if not collector:
                    health_results[source_name] = {
                        'status': 'error',
                        'message': 'Collector not initialized'
                    }
                    continue
                
                # Test availability
                is_available = collector.is_available()
                
                # Get cache stats
                stats = self.cache.get_source_stats().get(source_name, {})
                
                health_results[source_name] = {
                    'status': 'healthy' if is_available else 'unhealthy',
                    'available': is_available,
                    'configured': source_info['available'],
                    'consecutive_failures': stats.get('consecutive_failures', 0),
                    'last_successful_run': stats.get('last_successful_run'),
                    'total_indicators': stats.get('total_indicators', 0),
                    'avg_runtime': stats.get('avg_runtime_seconds', 0)
                }
                
            except Exception as e:
                health_results[source_name] = {
                    'status': 'error',
                    'message': str(e)
                }
        
        # Calculate overall health
        healthy_count = sum(1 for r in health_results.values() if r.get('status') == 'healthy')
        total_count = len(health_results)
        
        overall_health = {
            'status': 'healthy' if healthy_count == total_count else 'degraded' if healthy_count > 0 else 'unhealthy',
            'healthy_sources': healthy_count,
            'total_sources': total_count,
            'health_percentage': (healthy_count / total_count * 100) if total_count > 0 else 0
        }
        
        return {
            'overall': overall_health,
            'sources': health_results,
            'timestamp': datetime.now().isoformat()
        }
    
    def cleanup_old_data(self, days_to_keep: int = 30) -> Dict[str, int]:
        """
        Clean up old collection data and cache entries.
        
        Args:
            days_to_keep: Number of days of data to retain
            
        Returns:
            Cleanup statistics
        """
        cutoff_date = datetime.now() - timedelta(days=days_to_keep)
        cutoff_str = cutoff_date.strftime("%Y-%m-%d")
        
        logger.info(f"Cleaning up data older than {cutoff_str}")
        
        cleaned_files = 0
        cleaned_size = 0
        
        # Clean up raw data files
        raw_dir = Path("data/raw")
        if raw_dir.exists():
            for source_dir in raw_dir.iterdir():
                if not source_dir.is_dir():
                    continue
                
                for file_path in source_dir.glob("*.jsonl"):
                    try:
                        # Extract date from filename
                        date_str = file_path.stem  # e.g., "2025-09-15"
                        file_date = datetime.strptime(date_str, "%Y-%m-%d")
                        
                        if file_date < cutoff_date:
                            file_size = file_path.stat().st_size
                            file_path.unlink()
                            cleaned_files += 1
                            cleaned_size += file_size
                            logger.debug(f"Deleted old file: {file_path}")
                            
                    except (ValueError, OSError) as e:
                        logger.warning(f"Error processing file {file_path}: {e}")
        
        # Clean up cache database (keep the schema, just old records)
        # This would require additional SQL to clean old entries
        
        logger.info(f"Cleanup complete: {cleaned_files} files, {cleaned_size / 1024 / 1024:.1f} MB")
        
        return {
            'files_deleted': cleaned_files,
            'bytes_freed': cleaned_size,
            'cutoff_date': cutoff_str
        }