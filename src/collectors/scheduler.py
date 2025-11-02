"""
Collection scheduling and caching system for threat intelligence sources.

This module provides advanced scheduling capabilities, intelligent caching,
and state management for the threat intelligence collection pipeline.
"""

import json
import logging
import sqlite3
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class CollectionCache:
    """Manages caching and state for threat intelligence collections."""
    
    def __init__(self, cache_dir: str = "data/.cache"):
        """
        Initialize the collection cache.
        
        Args:
            cache_dir: Directory to store cache files
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize SQLite database for metadata
        self.db_path = self.cache_dir / "collection_state.db"
        self._init_database()
        
        logger.info(f"Initialized collection cache at {self.cache_dir}")
    
    def _init_database(self):
        """Initialize the cache database schema."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS collection_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_name TEXT NOT NULL,
                    collection_date TEXT NOT NULL,
                    start_time TEXT NOT NULL,
                    end_time TEXT,
                    status TEXT NOT NULL DEFAULT 'running',
                    indicator_count INTEGER DEFAULT 0,
                    error_message TEXT,
                    output_file TEXT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(source_name, collection_date)
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS source_metadata (
                    source_name TEXT PRIMARY KEY,
                    last_successful_run TEXT,
                    consecutive_failures INTEGER DEFAULT 0,
                    total_indicators INTEGER DEFAULT 0,
                    avg_runtime_seconds REAL DEFAULT 0,
                    enabled BOOLEAN DEFAULT 1,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS rate_limits (
                    source_name TEXT PRIMARY KEY,
                    last_request_time REAL NOT NULL,
                    request_count INTEGER DEFAULT 1,
                    window_start REAL NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.commit()
    
    def start_collection(self, source_name: str, date: str) -> int:
        """
        Record the start of a collection run.
        
        Args:
            source_name: Name of the source being collected
            date: Collection date in YYYY-MM-DD format
            
        Returns:
            Run ID for tracking this collection
        """
        start_time = datetime.now().isoformat()
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                INSERT OR REPLACE INTO collection_runs 
                (source_name, collection_date, start_time, status)
                VALUES (?, ?, ?, 'running')
            """, (source_name, date, start_time))
            
            run_id = cursor.lastrowid
            conn.commit()
        
        logger.info(f"Started collection run {run_id} for {source_name} on {date}")
        return run_id
    
    def finish_collection(self, run_id: int, status: str, indicator_count: int = 0,
                         error_message: Optional[str] = None, 
                         output_file: Optional[str] = None):
        """
        Record the completion of a collection run.
        
        Args:
            run_id: ID of the collection run
            status: Final status ('success' or 'failed')
            indicator_count: Number of indicators collected
            error_message: Error message if failed
            output_file: Path to output file
        """
        end_time = datetime.now().isoformat()
        
        with sqlite3.connect(self.db_path) as conn:
            # Update collection run
            conn.execute("""
                UPDATE collection_runs 
                SET end_time = ?, status = ?, indicator_count = ?, 
                    error_message = ?, output_file = ?
                WHERE id = ?
            """, (end_time, status, indicator_count, error_message, output_file, run_id))
            
            # Get source name for metadata update
            cursor = conn.execute("""
                SELECT source_name, start_time FROM collection_runs WHERE id = ?
            """, (run_id,))
            row = cursor.fetchone()
            
            if row:
                source_name, start_time = row
                start_dt = datetime.fromisoformat(start_time)
                end_dt = datetime.fromisoformat(end_time)
                runtime_seconds = (end_dt - start_dt).total_seconds()
                
                # Update source metadata
                if status == 'success':
                    conn.execute("""
                        INSERT OR REPLACE INTO source_metadata 
                        (source_name, last_successful_run, consecutive_failures, 
                         total_indicators, avg_runtime_seconds, updated_at)
                        VALUES (?, ?, 0, 
                               COALESCE((SELECT total_indicators FROM source_metadata WHERE source_name = ?), 0) + ?,
                               ?, ?)
                    """, (source_name, end_time, source_name, indicator_count, runtime_seconds, end_time))
                else:
                    conn.execute("""
                        INSERT OR REPLACE INTO source_metadata 
                        (source_name, last_successful_run, consecutive_failures,
                         total_indicators, avg_runtime_seconds, updated_at)
                        VALUES (?, 
                               COALESCE((SELECT last_successful_run FROM source_metadata WHERE source_name = ?), ''),
                               COALESCE((SELECT consecutive_failures FROM source_metadata WHERE source_name = ?), 0) + 1,
                               COALESCE((SELECT total_indicators FROM source_metadata WHERE source_name = ?), 0),
                               COALESCE((SELECT avg_runtime_seconds FROM source_metadata WHERE source_name = ?), 0),
                               ?)
                    """, (source_name, source_name, source_name, source_name, source_name, end_time))
            
            conn.commit()
        
        logger.info(f"Finished collection run {run_id}: {status} ({indicator_count} indicators)")
    
    def should_run_collection(self, source_name: str, date: str, 
                             force_refresh: bool = False) -> bool:
        """
        Check if a collection should be run based on cache and failure history.
        
        Args:
            source_name: Name of the source
            date: Collection date
            force_refresh: Force collection even if cached
            
        Returns:
            True if collection should run
        """
        if force_refresh:
            return True
        
        with sqlite3.connect(self.db_path) as conn:
            # Check if already collected successfully today
            cursor = conn.execute("""
                SELECT status, indicator_count FROM collection_runs 
                WHERE source_name = ? AND collection_date = ? AND status = 'success'
            """, (source_name, date))
            
            if cursor.fetchone():
                logger.info(f"Skipping {source_name} for {date} - already collected successfully")
                return False
            
            # Check consecutive failure count
            cursor = conn.execute("""
                SELECT consecutive_failures FROM source_metadata WHERE source_name = ?
            """, (source_name,))
            row = cursor.fetchone()
            
            if row and row[0] >= 5:
                logger.warning(f"Skipping {source_name} - too many consecutive failures ({row[0]})")
                return False
        
        return True
    
    def can_make_request(self, source_name: str, rate_limit_per_minute: int = 60) -> bool:
        """
        Check if a request can be made based on rate limits.
        
        Args:
            source_name: Name of the source
            rate_limit_per_minute: Rate limit for this source
            
        Returns:
            True if request can be made
        """
        now = time.time()
        window_seconds = 60  # 1 minute window
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT last_request_time, request_count, window_start 
                FROM rate_limits WHERE source_name = ?
            """, (source_name,))
            
            row = cursor.fetchone()
            
            if not row:
                # First request for this source
                conn.execute("""
                    INSERT INTO rate_limits (source_name, last_request_time, request_count, window_start)
                    VALUES (?, ?, 1, ?)
                """, (source_name, now, now))
                conn.commit()
                return True
            
            last_request_time, request_count, window_start = row
            
            # Check if we need to reset the window
            if now - window_start >= window_seconds:
                # Reset window
                conn.execute("""
                    UPDATE rate_limits 
                    SET last_request_time = ?, request_count = 1, window_start = ?, updated_at = ?
                    WHERE source_name = ?
                """, (now, now, datetime.now().isoformat(), source_name))
                conn.commit()
                return True
            
            # Check if we're under the rate limit
            if request_count < rate_limit_per_minute:
                # Increment counter
                conn.execute("""
                    UPDATE rate_limits 
                    SET last_request_time = ?, request_count = request_count + 1, updated_at = ?
                    WHERE source_name = ?
                """, (now, datetime.now().isoformat(), source_name))
                conn.commit()
                return True
            
            # Rate limit exceeded
            wait_time = window_seconds - (now - window_start)
            logger.warning(f"Rate limit exceeded for {source_name}, wait {wait_time:.1f}s")
            return False
    
    def get_collection_history(self, source_name: Optional[str] = None, 
                              days: int = 7) -> List[Dict[str, Any]]:
        """
        Get collection history for analysis.
        
        Args:
            source_name: Optional source to filter by
            days: Number of days of history to retrieve
            
        Returns:
            List of collection run records
        """
        since_date = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
        
        with sqlite3.connect(self.db_path) as conn:
            if source_name:
                cursor = conn.execute("""
                    SELECT source_name, collection_date, start_time, end_time, 
                           status, indicator_count, error_message, output_file
                    FROM collection_runs 
                    WHERE source_name = ? AND collection_date >= ?
                    ORDER BY start_time DESC
                """, (source_name, since_date))
            else:
                cursor = conn.execute("""
                    SELECT source_name, collection_date, start_time, end_time, 
                           status, indicator_count, error_message, output_file
                    FROM collection_runs 
                    WHERE collection_date >= ?
                    ORDER BY start_time DESC
                """, (since_date,))
            
            columns = ['source_name', 'collection_date', 'start_time', 'end_time',
                      'status', 'indicator_count', 'error_message', 'output_file']
            
            return [dict(zip(columns, row)) for row in cursor.fetchall()]
    
    def get_source_stats(self) -> Dict[str, Dict[str, Any]]:
        """Get statistics for all sources."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT source_name, last_successful_run, consecutive_failures,
                       total_indicators, avg_runtime_seconds, enabled
                FROM source_metadata
            """)
            
            stats = {}
            for row in cursor.fetchall():
                source_name, last_run, failures, total, avg_runtime, enabled = row
                stats[source_name] = {
                    'last_successful_run': last_run,
                    'consecutive_failures': failures,
                    'total_indicators': total,
                    'avg_runtime_seconds': avg_runtime,
                    'enabled': bool(enabled),
                    'status': 'healthy' if failures == 0 else 'failing' if failures < 3 else 'disabled'
                }
            
            return stats


class CollectionScheduler:
    """Manages scheduling and coordination of collection runs."""
    
    def __init__(self, cache: Optional[CollectionCache] = None):
        """
        Initialize the collection scheduler.
        
        Args:
            cache: Optional cache instance
        """
        self.cache = cache or CollectionCache()
        
        # State directory for tracking schedules
        self.state_dir = Path("data/.state")
        self.state_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info("Initialized collection scheduler")
    
    def should_collect_source(self, source_name: str, date: Optional[str] = None,
                             force: bool = False) -> bool:
        """
        Determine if a source should be collected based on various factors.
        
        Args:
            source_name: Name of the source
            date: Date to collect for (defaults to today)
            force: Force collection regardless of cache/history
            
        Returns:
            True if source should be collected
        """
        if date is None:
            date = datetime.now().strftime("%Y-%m-%d")
        
        # Check cache and failure history
        if not self.cache.should_run_collection(source_name, date, force):
            return False
        
        # Check if source is enabled
        stats = self.cache.get_source_stats()
        source_stats = stats.get(source_name, {})
        
        if not source_stats.get('enabled', True):
            logger.info(f"Skipping disabled source: {source_name}")
            return False
        
        # Check if too many consecutive failures
        if source_stats.get('consecutive_failures', 0) >= 5:
            logger.warning(f"Skipping source with too many failures: {source_name}")
            return False
        
        return True
    
    def create_collection_plan(self, sources: List[str], date: Optional[str] = None,
                              force: bool = False) -> Dict[str, Dict[str, Any]]:
        """
        Create an execution plan for collecting from multiple sources.
        
        Args:
            sources: List of source names to collect
            date: Date to collect for
            force: Force collection regardless of cache
            
        Returns:
            Collection plan with priorities and dependencies
        """
        if date is None:
            date = datetime.now().strftime("%Y-%m-%d")
        
        plan = {}
        
        # Get source statistics for prioritization
        stats = self.cache.get_source_stats()
        
        for source_name in sources:
            if not self.should_collect_source(source_name, date, force):
                continue
            
            source_stats = stats.get(source_name, {})
            
            # Calculate priority (lower number = higher priority)
            priority = 100  # Base priority
            
            # Boost priority for sources with no recent failures
            if source_stats.get('consecutive_failures', 0) == 0:
                priority -= 20
            
            # Boost priority for sources with high indicator counts
            total_indicators = source_stats.get('total_indicators', 0)
            if total_indicators > 1000:
                priority -= 10
            elif total_indicators > 100:
                priority -= 5
            
            # Lower priority for slower sources
            avg_runtime = source_stats.get('avg_runtime_seconds', 0)
            if avg_runtime > 300:  # 5 minutes
                priority += 20
            elif avg_runtime > 60:  # 1 minute
                priority += 10
            
            plan[source_name] = {
                'priority': priority,
                'estimated_runtime': avg_runtime,
                'last_success': source_stats.get('last_successful_run'),
                'failure_count': source_stats.get('consecutive_failures', 0),
                'should_run': True
            }
        
        # Sort by priority
        sorted_sources = sorted(plan.items(), key=lambda x: x[1]['priority'])
        
        logger.info(f"Created collection plan for {len(sorted_sources)} sources")
        return dict(sorted_sources)
    
    def estimate_collection_time(self, plan: Dict[str, Dict[str, Any]], 
                                concurrent: bool = True, max_workers: int = 4) -> float:
        """
        Estimate total collection time based on the plan.
        
        Args:
            plan: Collection plan from create_collection_plan()
            concurrent: Whether collections will run concurrently
            max_workers: Maximum concurrent workers
            
        Returns:
            Estimated time in seconds
        """
        if not plan:
            return 0.0
        
        runtimes = [info.get('estimated_runtime', 60) for info in plan.values()]
        
        if concurrent and len(runtimes) > 1:
            # Estimate concurrent execution time
            # Divide sources into batches of max_workers
            batches = [runtimes[i:i + max_workers] for i in range(0, len(runtimes), max_workers)]
            total_time = sum(max(batch) for batch in batches)
        else:
            # Sequential execution
            total_time = sum(runtimes)
        
        return total_time
    
    def save_collection_state(self, state: Dict[str, Any]):
        """Save collection state to disk."""
        state_file = self.state_dir / "last_collection.json"
        with open(state_file, 'w') as f:
            json.dump({
                'timestamp': datetime.now().isoformat(),
                'state': state
            }, f, indent=2)
    
    def load_collection_state(self) -> Optional[Dict[str, Any]]:
        """Load last collection state from disk."""
        state_file = self.state_dir / "last_collection.json"
        if not state_file.exists():
            return None
        
        try:
            with open(state_file, 'r') as f:
                data = json.load(f)
                return data.get('state')
        except Exception as e:
            logger.error(f"Error loading collection state: {e}")
            return None