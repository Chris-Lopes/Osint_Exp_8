# Threat Aggregation Lab (End-to-End SOC Pipeline)

This lab builds a comprehensive threat intelligence aggregation and analysis pipeline that simulates a real-world SOC environment. The system collects threat data from 12+ reputable sources, normalizes it into a common schema, enriches with context, correlates relationships, scores threats, generates detections, and provides automated reporting.

## Features

- **Multi-Source Collection**: Integrates with 12+ threat intelligence sources including AlienVault OTX, MITRE ATT&CK, NVD, URLhaus, MalwareBazaar, PhishTank, and more
- **Normalization Pipeline**: Converts heterogeneous data into a consistent STIX-like schema
- **Enrichment System**: Adds reputation scores, geographic data, ASN information, and malware family classifications
- **Deduplication & Merging**: Handles overlapping indicators with transparent lineage tracking
- **Knowledge Graph**: Creates correlation graphs showing relationships between indicators, techniques, CVEs, and infrastructure
- **Risk Scoring**: Multi-factor scoring system with P1-P4 priority bands
- **Detection Generation**: Automatically creates Sigma rules from high-priority indicators
- **Reporting & Visualization**: Generates charts, summaries, and PDF reports
- **Orchestration**: Automated daily pipeline execution with SOAR-like playbooks
- **Validation**: Adversary simulation and coverage testing

## Quick Start

1. **Environment Setup**
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

2. **Configuration**
```bash
cp .env.example .env
# Fill in API keys for sources you want to use
```

3. **Smoke Test**
```bash
python -m src.collectors.example_public
```

4. **Full Pipeline** (after configuring sources)
```bash
make daily
```

## Architecture

The pipeline follows a modular design with clear data flow:

```
Collection → Normalization → Enrichment → Merging → Correlation → Scoring → Detection → Reporting
```

### Data Layers

- `data/raw/`: Immutable source data organized by source and date
- `data/processed/`: Normalized indicators in common schema  
- `data/processed_enriched/`: Indicators with added context
- `data/merged/`: Deduplicated authoritative indicators
- `data/graph/`: Knowledge graph exports (GraphML, JSON)
- `data/scored/`: Priority-ranked indicators with P1-P4 bands
- `data/rules/`: Generated detection rules
- `data/reports/`: Summary statistics, charts, and PDF reports

## Configuration

The system is driven by `config/config.yaml` which defines:

- **Sources**: API endpoints, authentication, rate limits
- **Enrichers**: Context providers and field mappings  
- **Merge Policy**: Deduplication rules and precedence
- **Scoring**: Weights, decay factors, and band thresholds
- **Correlation**: Graph node types and relationship rules

## Threat Intelligence Sources

The lab supports multiple source types:

### Public Feeds (No API Key Required)
- URLhaus - Malicious URL feed
- MalwareBazaar - Malware sample hashes
- PhishTank - Phishing URL database  
- Spamhaus DROP - Netblock blacklist
- MITRE ATT&CK - Tactics, techniques & procedures
- NVD CVE - Vulnerability database
- CISA KEV - Known exploited vulnerabilities

### API-Based Sources (Require Registration)
- AlienVault OTX - Open threat exchange
- VirusTotal - File/URL reputation
- AbuseIPDB - IP reputation database
- Shodan - Internet-connected devices
- GreyNoise - Internet background noise
- IBM X-Force - Threat intelligence

## Usage Examples

### Individual Module Execution
```bash
# Collection from all enabled sources
python -m src.collectors.run_all

# Normalize raw data to common schema
python -m src.normalizers.normalize_run

# Enrich with context providers
# Run enrichment on processed data
python run_enrichment.py

# Run comprehensive enrichment testing
python enrichment.py

# Merge and deduplicate
python -m src.merge.run_merge

# Build correlation graph
python -m src.correlation.run_correlate

# Score and prioritize
python -m src.scoring.run_scoring

# Generate detection rules
make gen-detect DATE=2025-09-22

# Create reports
make report DATE=2025-09-22
```

### Makefile Targets
```bash
make daily              # Run full pipeline for today
make normalize          # Normalize all raw data
make enrich             # Run enrichment pipeline
make merge              # Merge and deduplicate
make correlate          # Build knowledge graph
make score              # Score and prioritize threats
make report             # Generate visualizations and PDF
```

## Data Flow

1. **Collection**: Fetch raw threat data from configured sources
2. **Normalization**: Convert to standard schema with field mapping
3. **Enrichment**: Add reputation, geolocation, ASN, malware families
4. **Merging**: Resolve duplicates with confidence scoring and lineage
5. **Correlation**: Build knowledge graph of relationships
6. **Scoring**: Apply multi-factor risk scoring with decay
7. **Detection**: Generate Sigma rules for high-priority indicators  
8. **Reporting**: Create summaries, charts, and executive reports
9. **Orchestration**: Automate daily execution with playbooks
10. **Validation**: Test coverage with adversary simulations

## Key Concepts

- **Indicators**: Canonicalized IOCs (IPs, domains, hashes, URLs)
- **Enrichment**: Added context from reputation providers
- **Lineage**: Provenance tracking for audit and debugging
- **Confidence**: Trust scoring from source precedence and freshness
- **Bands**: P1 (Critical) → P4 (Low) priority classification
- **Graph**: Network relationships between threats, techniques, infrastructure
- **Simulation**: Benign adversary testing for validation

## Requirements

- Python 3.10+
- Internet connectivity for source collection
- ~500MB disk space for typical daily volumes
- Optional: API keys for commercial threat feeds

## Safety & Ethics

- Uses only public/legitimate threat intelligence sources
- No live malware execution or dangerous payloads
- Respects API rate limits and terms of service
- Simulations use synthetic/benign test data only

## Lab Structure

The project follows academic lab requirements with:
- Git repository with complete source history
- Reproducible environment with pinned dependencies  
- Documentation explaining setup and execution
- Sample data demonstrating successful pipeline runs
- Generated reports showing detection capabilities

## Deliverables

1. **Git Repository**: Complete source code and configuration
2. **Lab Report**: Documentation of execution and results  
3. **Generated Reports**: PDF reports showing pipeline outputs
4. **Sample Data**: At least one successful end-to-end run

## Notes

- Keep raw data out of git as configured in `.gitignore`
- Respect each source's ToS and legal constraints
- API keys stored in `.env` (never committed)
- Cache directories improve re-run performance
- Makefile provides consistent command interface

## Advanced Extensions

- Integration with real SIEM platforms (Splunk, Elastic)
- Additional detection formats (YARA, Suricata)  
- Cloud-native deployment (Docker, Kubernetes)
- Machine learning for adaptive scoring
- Live dashboard integration (Grafana, Kibana)

This lab provides hands-on experience with the complete threat intelligence lifecycle used in modern Security Operations Centers.
