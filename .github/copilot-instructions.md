# Threat Aggregation Lab - AI Coding Assistant Instructions

## Project Overview
This is a comprehensive threat intelligence aggregation pipeline that simulates a real-world SOC environment. The system collects threat data from 12+ sources, normalizes it into STIX-like schema, enriches with context, correlates relationships, scores threats, generates detections, and provides automated reporting.

## Architecture & Data Flow
**Pipeline Stages**: Collection → Normalization → Enrichment → Merging → Correlation → Scoring → Detection → Reporting

**Data Layers**:
- `data/raw/`: Immutable source data organized by source/date
- `data/processed/`: Normalized indicators in common schema
- `data/processed_enriched/`: Indicators with added context
- `data/merged/`: Deduplicated authoritative indicators
- `data/graph/`: Knowledge graph exports (GraphML, JSON)
- `data/scored/`: Priority-ranked indicators with P1-P4 bands
- `data/rules/`: Generated detection rules
- `data/reports/`: Summary statistics, charts, and PDF reports

## Key Components & Patterns

### Collector Pattern
All threat intelligence collectors inherit from `BaseCollector` in `src/collectors/base.py`:
- `RestApiCollector`: For REST API sources (AlienVault OTX, VirusTotal)
- `CsvCollector`: For CSV/feed sources (URLhaus, MalwareBazaar)
- Output format: JSONL with `_source` and `_collected_at` metadata fields

### Collector Types and API Sources

#### REST API Collectors (`generic_rest`)
Used for authenticated API sources with structured endpoints:
- **Authentication types**: `header`, `query`, or `none`
- **Environment variables**: `API_KEY_{SOURCE_NAME}` (e.g., `API_KEY_OTX`, `API_KEY_VIRUSTOTAL`)
- **Rate limiting**: Configurable requests per minute
- **Examples**:
  - AlienVault OTX: Header auth, 10 req/min, indicators export endpoint
  - VirusTotal: Query auth, 4 req/min, file/domain search endpoints
  - AbuseIPDB: Header auth, 60 req/min, blacklist endpoint
  - Shodan: Query auth, 60 req/min, host search endpoint
  - GreyNoise: Header auth, 60 req/min, community endpoint

#### Feed Collectors
No authentication required, direct URL access:
- **feed_csv**: CSV feeds (URLhaus, PhishTank, Spamhaus DROP)
- **feed_json**: JSON feeds (MalwareBazaar, MITRE ATT&CK, CISA KEV)
- **feed_xml**: XML feeds (CWE data)
- **Configuration**: URL, headers, delimiters, lookback days

#### Key API Source Details
- **Public feeds (no API key)**: URLhaus, MalwareBazaar, PhishTank, Spamhaus, MITRE ATT&CK, NVD CVE, CWE, CISA KEV
- **API sources (require keys)**: AlienVault OTX, VirusTotal, AbuseIPDB, Shodan, GreyNoise
- **Rate limits vary**: 4-60 requests per minute depending on source
- **Default lookback**: 1-30 days depending on source update frequency
- **Authentication patterns**: Header-based (most common), query-based (VirusTotal/Shodan), or none

### Configuration-Driven Design
- `config/config.yaml`: Defines sources, enrichers, merge policy, correlation rules, scoring weights
- `config/normalization_rules.yaml`: Jinja2 templates for transforming heterogeneous data
- Environment variables for API keys (prefixed with `API_KEY_`)

### Modular Analysis Components
- `src/analysis/`: Attribution, clustering, correlation, reporting, risk_scoring, timeline_analysis
- `src/correlation/`: Graph-based relationship analysis with configurable node/edge types
- `src/detection/`: Sigma rule generation from high-priority indicators

## Critical Developer Workflows

### Primary Execution Methods
```bash
# Web interface (recommended for beginners)
streamlit run app.py

# Complete pipeline execution
python run_lab_analysis.py

# Individual stages via Makefile
make daily              # Full pipeline
make collect           # Data collection only
make normalize         # Normalization only
make enrich           # Enrichment only
```

### CLI Tool for Advanced Operations
```bash
# Health checks and monitoring
python src/collection_cli.py health
python src/collection_cli.py status --verbose

# Source-specific operations
python src/collection_cli.py collect --source virustotal
python src/collection_cli.py pipeline --sources malware_bazaar urlhaus
```

### Testing & Validation
```bash
# Component validation (now uses real data from pipeline)
python validate_analysis_simple.py    # Full pipeline test on real enriched data
python validate_enrichment.py         # Enrichment validation
python validate_analysis.py          # Analysis validation

# Individual component testing
python enhanced_collection.py        # Collection test
python normalization.py             # Normalization test
python enrichment_simple.py         # Enrichment test
```

## Project-Specific Conventions

### Data Formats
- **JSONL**: All intermediate data storage (one JSON object per line)
- **STIX-like schema**: Normalized indicator format with consistent field names
- **GraphML/JSON**: Correlation graph exports for network analysis

### Naming Patterns
- Source keys: `snake_case` (e.g., `alienvault_otx`, `malware_bazaar`)
- File paths: `data/{layer}/{source}/{date}.jsonl`
- Environment variables: `API_KEY_{SOURCE_NAME}` (e.g., `API_KEY_VIRUSTOTAL`)

### Error Handling
- Graceful degradation: Continue pipeline if individual sources fail
- Logging levels: INFO for normal operations, ERROR for failures
- Validation functions: Return boolean success indicators

### Dependencies & Environment
- Python 3.10+ required
- Virtual environment: `.venv/` (activated with `source .venv/bin/activate`)
- **Always activate virtual environment**: Run `source .venv/bin/activate` before executing any Python commands
- API keys stored in `.env` file (never committed)
- Rate limiting: Built into collectors with configurable delays

## Integration Points

### External Threat Intelligence Sources
- **Public feeds**: URLhaus, MalwareBazaar, PhishTank, MITRE ATT&CK, NVD CVE
- **API sources**: AlienVault OTX, VirusTotal, AbuseIPDB, Shodan, GreyNoise
- **Authentication**: API key headers, query parameters, or none for public feeds

### Enrichment Services
- **Geolocation**: MaxMind GeoIP2 for IP geolocation
- **Reputation**: VirusTotal, AbuseIPDB for threat scores
- **DNS resolution**: Custom DNS service for domain lookups
- **ASN lookup**: IP to ASN mapping services

### Output Integrations
- **SIEM**: Sigma rule generation for Splunk/Elastic
- **Reporting**: PDF reports with charts and executive summaries
- **Visualization**: Matplotlib/Pandas for data analysis charts

## Common Patterns & Anti-Patterns

### DOs
- **Inherit from base classes**: All collectors extend `BaseCollector`
- **Use configuration over code**: Source definitions in YAML, not hardcoded
- **Handle rate limits**: Implement delays between API calls
- **Add metadata**: Include `_source` and timestamps in all data
- **Validate inputs**: Check API key availability before collection
- **Log operations**: Use logging module for debugging and monitoring

### DON'Ts
- **Don't hardcode API keys**: Always use environment variables
- **Don't modify raw data**: Raw data is immutable, transformations create new files
- **Don't skip error handling**: Network requests and file operations can fail
- **Don't ignore rate limits**: Respect source API limits to avoid bans
- **Don't commit sensitive data**: .env files and raw data are gitignored
- **Don't use dummy data**: Never use dummy/test data in actual production code

## Key Files for Understanding

### Architecture
- `app.py`: Streamlit web interface and main execution flow
- `run_lab_analysis.py`: Complete pipeline runner script
- `src/collectors/base.py`: Abstract collector base class
- `config/config.yaml`: System configuration and source definitions

### Data Processing
- `config/normalization_rules.yaml`: Data transformation templates
- `src/normalizers/`: Normalization pipeline components
- `src/enrichment/`: Context enrichment services
- `src/correlation/`: Relationship analysis engine

### Analysis & Output
- `src/analysis/`: Core analysis components (scoring, attribution, etc.)
- `src/detection/`: Detection rule generation
- `src/reporting/`: Report generation and visualization
- `Makefile`: Build and execution targets

## Debugging & Troubleshooting

### Common Issues
- **Import errors**: Ensure running from project root, virtualenv activated
- **API failures**: Check .env file for correct API keys
- **Permission errors**: Verify write access to data/ directory
- **Rate limiting**: Add delays or reduce collection frequency

### Validation Commands
```bash
# Check system health
python src/collection_cli.py health

# Validate configuration
python -c "from src.utils.env import load; print('Config OK:', bool(load()))"

# Test individual components
python validate_analysis_simple.py
```

### Logging & Monitoring
- Logs written to console with timestamps
- Use `--verbose` flags for detailed output
- Check `data/.state/` for pipeline state information

## Extension Patterns

### Adding New Collectors
1. Create class inheriting from appropriate base (`RestApiCollector`, `CsvCollector`)
2. Add configuration to `config/config.yaml` sources section
3. Implement `collect()` method following JSONL output format
4. Add normalization rules to `config/normalization_rules.yaml`

### Adding New Analysis Components
1. Create module in appropriate `src/` subdirectory
2. Follow existing patterns (configuration-driven, logging, error handling)
3. Add to main pipeline in `run_lab_analysis.py` or orchestration modules
4. Include validation tests

### Custom Enrichment Services
1. Add configuration to `config/config.yaml` enrichers section
2. Implement enrichment logic in `src/enrichment/`
3. Define field mappings for enriched data
4. Handle API failures gracefully with fallbacks