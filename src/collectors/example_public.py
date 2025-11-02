"""
Example public collector for smoke testing and connectivity verification.

This collector makes a simple HTTP request to a benign endpoint to verify
that the basic infrastructure is working properly.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterator, Optional

logger = logging.getLogger(__name__)


class ExamplePublicCollector:
    """Simple collector for smoke testing connectivity."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize example collector."""
        from ..utils.env import load
        
        self.source_name = "example_public"
        self.config = config or load()
        
        # Set up output directory
        self.output_dir = Path("data/raw") / self.source_name
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info("Initialized example public collector")
    
    def collect(self, date: Optional[str] = None) -> str:
        """
        Collect example data for smoke testing.
        
        Args:
            date: Date string in YYYY-MM-DD format
            
        Returns:
            Path to output file
        """
        output_file = self._get_output_file(date)
        
        logger.info(f"Starting example collection for {date or 'today'}")
        
        indicators = self._collect_example_data()
        count = self._write_indicators(indicators, output_file)
        
        logger.info(f"Example collection complete: {count} indicators")
        return str(output_file)
    
    def is_available(self) -> bool:
        """Check if the example endpoint is available."""
        try:
            from ..utils.http import get
            response = get("https://httpbin.org/json", timeout=10)
            return response is not None
        except Exception:
            return False
    
    def _get_output_file(self, date: Optional[str] = None) -> Path:
        """Get the output file path for the given date."""
        if date is None:
            date = datetime.now().strftime("%Y-%m-%d")
        return self.output_dir / f"{date}.jsonl"
    
    def _collect_example_data(self) -> Iterator[Dict[str, Any]]:
        """Collect example data from httpbin."""
        try:
            from ..utils.http import get
            
            # Make test request to httpbin
            response = get("https://httpbin.org/json")
            if response:
                # Extract JSON data from response
                response_data = response if isinstance(response, dict) else {}
                
                # Create a mock indicator from the response
                indicator = {
                    'type': 'test_data',
                    'value': 'httpbin.org',
                    'context': {
                        'response_data': response_data,
                        'test_endpoint': 'https://httpbin.org/json',
                        'status': 'success'
                    },
                    'confidence': 100,
                    'severity': 'info',
                    'source_url': 'https://httpbin.org/',
                    'tags': ['test', 'smoke_test', 'connectivity']
                }
                yield indicator
                
        except Exception as e:
            logger.error(f"Error collecting example data: {e}")
    
    def _write_indicators(self, indicators: Iterator[Dict[str, Any]], 
                         output_file: Path) -> int:
        """
        Write indicators to JSONL file.
        
        Args:
            indicators: Iterator of indicator dictionaries
            output_file: Path to output file
            
        Returns:
            Number of indicators written
        """
        count = 0
        with open(output_file, 'w') as f:
            for indicator in indicators:
                # Add metadata
                indicator['_source'] = self.source_name
                indicator['_collected_at'] = datetime.now().isoformat()
                
                f.write(json.dumps(indicator) + '\n')
                count += 1
        
        logger.info(f"Wrote {count} indicators to {output_file}")
        return count


def run():
    """Legacy function for backward compatibility."""
    collector = ExamplePublicCollector()
    return collector.collect()


if __name__ == "__main__":
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    print(run())