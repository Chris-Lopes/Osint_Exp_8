"""Threat intelligence collectors package."""

from .base import BaseCollector, RestApiCollector, CsvCollector, TaxiiCollector
from .example_public import ExamplePublicCollector

try:
    from .virustotal import VirusTotalCollector
except ImportError:
    VirusTotalCollector = None

try:
    from .abuse_ch import URLhausCollector, MalwareBazaarCollector, ThreatFoxCollector
except ImportError:
    URLhausCollector = MalwareBazaarCollector = ThreatFoxCollector = None

try:
    from .otx_shodan import OTXCollector, ShodanCollector
except ImportError:
    OTXCollector = ShodanCollector = None

__all__ = [
    'BaseCollector', 'RestApiCollector', 'CsvCollector', 'TaxiiCollector',
    'ExamplePublicCollector', 'VirusTotalCollector', 
    'URLhausCollector', 'MalwareBazaarCollector', 'ThreatFoxCollector',
    'OTXCollector', 'ShodanCollector'
]