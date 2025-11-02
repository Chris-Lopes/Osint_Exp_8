#!/usr/bin/env python3
"""
Enhanced Collection System - Production Execution

This script runs the complete threat intelligence data collection pipeline
from multiple sources and stores the results in the standard data directory.
"""

import sys
from pathlib import Path
from datetime import datetime
import logging

# Add the project root to the path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def run_collection():
    """Run the enhanced collection system."""
    try:
        logger.info("🚀 Starting enhanced collection system (orchestrator)...")

        # Use the full collection orchestrator to run all configured sources
        from src.collectors.run_all import CollectionOrchestrator

        orchestrator = CollectionOrchestrator()
        results = orchestrator.run_all_sources()

        # Log results and return a summary path or None
        successful = [k for k, v in results.items() if v and Path(v).exists()]
        logger.info(f"Collection results: {len(successful)}/{len(results)} sources produced files")

        # Return a JSON summary path in data/raw/ for easy checking
        summary_path = Path('data/raw/collection_summary.json')
        summary = {
            'timestamp': datetime.now().isoformat(),
            'requested_sources': list(results.keys()),
            'successful_sources': successful,
            'results': results
        }
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        with open(summary_path, 'w') as f:
            import json
            json.dump(summary, f, indent=2)

        logger.info(f"✓ Collection summary written to {summary_path}")
        return str(summary_path)
        
    except Exception as e:
        logger.error(f"✗ Collection error: {e}")
        import traceback
        traceback.print_exc()
        return None

def run_cache_operations():
    """Run cache system operations."""
    try:
        logger.info("Testing cache system...")
        
        from src.collectors.scheduler import CollectionCache
        
        cache = CollectionCache()
        logger.info("✓ Cache initialized")
        
        # Start a collection run
        run_id = cache.start_collection("example_public", datetime.now().strftime("%Y-%m-%d"))
        logger.info(f"✓ Started collection run: {run_id}")
        
        # Finish the collection run
        cache.finish_collection(run_id, "success", 1, None, "data/raw/example_public/2025-10-05.jsonl")
        logger.info(f"✓ Finished collection run: {run_id}")
        
        # Get stats
        stats = cache.get_source_stats()
        logger.info(f"✓ Retrieved source stats: {len(stats)} sources")
        
        logger.info("✅ Cache system operations completed!")
        return True
        
    except Exception as e:
        logger.error(f"✗ Cache error: {e}")
        import traceback
        traceback.print_exc()
        return False

def run_scheduler_operations():
    """Run scheduler operations."""
    try:
        logger.info("Running scheduler operations...")
        
        from src.collectors.scheduler import CollectionScheduler
        
        scheduler = CollectionScheduler()
        logger.info("✓ Scheduler initialized")
        
        # Create collection plan
        plan = scheduler.create_collection_plan(["example_public"], force=True)
        logger.info(f"✓ Created collection plan: {len(plan)} sources")
        
        # Estimate time
        estimated_time = scheduler.estimate_collection_time(plan)
        logger.info(f"✓ Estimated collection time: {estimated_time:.1f}s")
        
        logger.info("✅ Scheduler operations completed!")
        return True
        
    except Exception as e:
        logger.error(f"✗ Scheduler error: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Main execution function."""
    print("🚀 Enhanced Collection System - Production Execution\n")
    
    # Run collection (orchestrator)
    result = run_collection()
    
    # Run cache operations
    cache_success = run_cache_operations()
    
    # Run scheduler operations
    scheduler_success = run_scheduler_operations()
    
    if result:
        print(f"\n✅ Collection completed successfully! Output: {result}")
        print("🎉 Enhanced collection system execution finished.")
        return 0
    else:
        print("\n❌ Collection failed. Check the errors above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())