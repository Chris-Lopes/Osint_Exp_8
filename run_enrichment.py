#!/usr/bin/env python3
"""
Simple enrichment runner for processed threat intelligence data.
"""

import sys
import json
import logging
from pathlib import Path
from datetime import datetime

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.enrichment.orchestrator import EnrichmentOrchestrator

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def main():
    """Run enrichment on processed data."""
    print("🚀 Running Enrichment on Processed Data")
    print("=" * 50)

    try:
        # Initialize orchestrator
        orchestrator = EnrichmentOrchestrator()

        # Find processed files
        processed_dir = Path("data/processed")
        if not processed_dir.exists():
            print("❌ No processed data directory found")
            return 1

        # Process all JSONL files
        for source_dir in processed_dir.iterdir():
            if not source_dir.is_dir():
                continue

            source_name = source_dir.name
            print(f"\n📊 Processing source: {source_name}")

            for jsonl_file in source_dir.glob("*.jsonl"):
                print(f"  Enriching {jsonl_file.name}...")

                # Define output file
                enriched_dir = Path("data/enriched") / source_name
                enriched_file = enriched_dir / jsonl_file.name

                # Run enrichment
                results = orchestrator.enrich_from_file(jsonl_file, enriched_file)

                # Report results
                success_rate = results['enriched_successfully'] / max(results['total_indicators'], 1) * 100
                print(f"    ✓ {results['enriched_successfully']}/{results['total_indicators']} indicators enriched ({success_rate:.1f}%)")
                print(f"    ⏱️  Processing time: {results['processing_time']:.1f}s")

                if results['enrichment_sources_used']:
                    print(f"    🔧 Services used: {', '.join(results['enrichment_sources_used'])}")

        print("\n✅ Enrichment complete!")
        return 0

    except Exception as e:
        print(f"❌ Enrichment failed: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())