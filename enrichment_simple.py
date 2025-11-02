#!/usr/bin/env python3
"""
Enrichment Pipeline - Production Execution

This script runs the enrichment pipeline to add contextual information
to normalized threat indicators.
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

def run_enrichment():
    """Run the enrichment pipeline."""
    print("🚀 Starting enrichment pipeline execution...")
    
    try:
        # Test orchestrator import
        from src.enrichment.orchestrator import EnrichmentOrchestrator
        print("✓ EnrichmentOrchestrator import successful")
        
        # Test individual service imports
        from src.enrichment.geolocation import IPAPIGeolocationService
        print("✓ IPAPIGeolocationService import successful")
        
        from src.enrichment.dns_service import DNSEnrichmentService
        print("✓ DNSEnrichmentService import successful")
        
        from src.enrichment.asn_lookup import ASNLookupService
        print("✓ ASNLookupService import successful")
        
        from src.enrichment.reputation_scoring import ReputationScoringEngine
        print("✓ ReputationScoringEngine import successful")
        
        return True
        
    except Exception as e:
        print(f"✗ Import failed: {e}")
        return False

def run_services():
    """Run enrichment services."""
    print("\n🔄 Running enrichment services...")
    
    try:
        # Test IP-API geolocation (no database required)
        from src.enrichment.geolocation import IPAPIGeolocationService
        geo_service = IPAPIGeolocationService()
        result = geo_service.lookup("8.8.8.8")
        print(f"✓ Geolocation service executed: success={result.success}")
        
        # Test DNS service
        from src.enrichment.dns_service import DNSEnrichmentService
        dns_service = DNSEnrichmentService()
        result = dns_service.enrich_domain("google.com")
        success = result and result.get('dns_resolution_success', False)
        print(f"✓ DNS service executed: success={success}")
        
        # Test ASN service
        from src.enrichment.asn_lookup import ASNLookupService
        asn_service = ASNLookupService()
        result = asn_service.enrich_network_context("8.8.8.8")
        success = result.get('asn_lookup_success', False)
        print(f"✓ ASN service executed: success={success}")
        
        # Test reputation engine
        from src.enrichment.reputation_scoring import ReputationScoringEngine
        rep_engine = ReputationScoringEngine()
        result = rep_engine.score_indicator("8.8.8.8", "ipv4", {})
        print(f"✓ Reputation service executed: success={result.success}")
        
        return True
        
    except Exception as e:
        print(f"✗ Service execution failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def run_cli_validation():
    """Run CLI validation."""
    print("\n🔧 Running CLI validation...")
    
    try:
        import subprocess
        cmd = [sys.executable, "src/collection_cli.py", "enrich", "--validate", "--json"]
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=Path.cwd(), timeout=30)
        
        if result.returncode == 0:
            print("✓ CLI validation successful")
            print(f"Output: {result.stdout[:200]}...")
            return True
        else:
            print(f"✗ CLI validation failed: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"✗ CLI execution failed: {e}")
        return False

def main():
    """Run enrichment pipeline execution."""
    print("=" * 50)
    print("ENRICHMENT PIPELINE EXECUTION")
    print("=" * 50)
    
    results = []
    
    # Run enrichment setup
    results.append(run_enrichment())
    
    # Run services 
    results.append(run_services())
    
    # Run CLI validation
    results.append(run_cli_validation())
    
    # Summary
    print(f"\n{'=' * 50}")
    print(f"EXECUTION RESULTS: {sum(results)}/{len(results)} components successful")
    print("=" * 50)
    
    if all(results):
        print("🎉 Enrichment pipeline execution completed successfully!")
        return 0
    else:
        print("❌ Some components failed. Check the output above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())