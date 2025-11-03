# 🛡️ Threat Aggregation Lab

### End-to-End Security Operations Center (SOC) Intelligence Pipeline

> A comprehensive threat intelligence aggregation and analysis system that simulates real-world SOC environments. Automates the complete lifecycle: collection → normalization → enrichment → correlation → detection → reporting.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Getting Started](#getting-started)
- [Core Capabilities](#core-capabilities)
- [Pipeline Architecture](#pipeline-architecture)
- [Data Sources](#data-sources)
- [Usage Guide](#usage-guide)
- [Project Structure](#project-structure)
- [Advanced Topics](#advanced-topics)
- [Contributing & Safety](#contributing--safety)

---

## 🎯 Overview

This lab provides hands-on experience with enterprise-grade threat intelligence operations. The system integrates 12+ threat intelligence sources, processes indicators through a multi-stage pipeline, and generates actionable security detections.

**Key Highlights:**

- ✅ Real-world SOC simulation with production-ready components
- ✅ STIX-like data normalization for standardized processing
- ✅ Automated enrichment with geolocation, reputation, and ASN data
- ✅ Knowledge graph correlation showing threat relationships
- ✅ Multi-factor risk scoring with priority bands (P1-P4)
- ✅ Sigma rule generation for SIEM integration
- ✅ Comprehensive reporting with visualizations and PDFs

---

## 🚀 Getting Started

### Prerequisites

- Python 3.10 or higher
- ~500MB disk space for typical daily data
- Internet connectivity for threat feed collection
- (Optional) API keys for commercial threat intelligence sources

**Step 1: Clone and Setup Environment**
**Step 1: Clone and Setup Environment**

```bash
git clone https://github.com/Chris-Lopes/Osint_Exp_8.git
cd Osint_Exp_8
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

**Step 2: Configure API Keys** (Optional but recommended)

```bash
cp .env.example .env
# Edit .env and add your API keys for threat intelligence sources
```

**Step 3: Run Your First Collection**

```bash
# Smoke test with public sources (no API keys needed)
python -m src.collectors.example_public

# Or run the full pipeline
make daily
```

### Quick Validation

After running the pipeline, check that data was collected:

```bash
ls -la data/raw/       # Source data
ls -la data/processed/ # Normalized indicators
ls -la data/reports/   # Generated reports
```

---

## 💡 Core Capabilities

### 🔍 Multi-Source Intelligence Collection

Integrates with 12+ reputable threat intelligence providers:

- Public feeds (URLhaus, MalwareBazaar, PhishTank, MITRE ATT&CK, NVD)
- API-based sources (AlienVault OTX, VirusTotal, AbuseIPDB, Shodan, GreyNoise)
- Configurable rate limiting and authentication

### 🔄 Data Normalization

Converts heterogeneous data formats into a consistent STIX-like schema:

- Jinja2-based transformation templates
- Field mapping and type coercion
- Metadata preservation with source lineage

### 📈 Context Enrichment

Adds critical context to raw indicators:

- **Reputation Scoring**: VirusTotal, AbuseIPDB integration
- **Geolocation**: MaxMind GeoIP2 for IP addresses
- **ASN Lookup**: Autonomous system number mapping
- **DNS Resolution**: Domain to IP resolution
- **Malware Classification**: Family and category tagging

### 🔗 Relationship Correlation

Builds knowledge graphs showing threat connections:

- Node types: IPs, domains, hashes, CVEs, ATT&CK techniques
- Edge types: Communicates-with, exploits, uses, targets
- GraphML and JSON export formats
- Configurable correlation rules

### 🎯 Risk Scoring & Prioritization

Multi-factor scoring engine with priority bands:

- **P1 (Critical)**: Active threats requiring immediate action
- **P2 (High)**: Significant threats needing prompt investigation
- **P3 (Medium)**: Moderate threats for routine analysis
- **P4 (Low)**: Informational indicators for awareness

Scoring factors include:

- Source confidence and freshness
- Reputation scores from enrichment
- Correlation with known campaigns
- Historical threat context

### 🚨 Detection Rule Generation

Automatically creates detection content:

- **Sigma rules**: Universal SIEM detection format
- **YARA rules**: Malware pattern matching (optional)
- High-priority indicator focus
- Compatible with Splunk, Elastic, QRadar

### 📊 Reporting & Visualization

Comprehensive output formats:

- Executive summary PDFs
- Statistical charts (Matplotlib/Pandas)
- JSON structured reports
- Interactive web dashboards

---

## 🏗️ Pipeline Architecture

The system follows a modular, sequential pipeline design:

The system follows a modular, sequential pipeline design:

```
┌─────────────┐   ┌──────────────┐   ┌─────────────┐   ┌─────────┐
│ Collection  │──▶│Normalization │──▶│ Enrichment  │──▶│ Merging │
└─────────────┘   └──────────────┘   └─────────────┘   └─────────┘
                                                              │
┌─────────────┐   ┌──────────────┐   ┌─────────────┐        │
│  Reporting  │◀──│  Detection   │◀──│   Scoring   │◀───────┘
└─────────────┘   └──────────────┘   └─────────────┘
                                            ▲
                                            │
                                    ┌───────────────┐
                                    │  Correlation  │
                                    └───────────────┘
```

### Data Layer Organization

The pipeline maintains clear data separation across processing stages:

| Layer         | Directory                  | Description                                    | Format         |
| ------------- | -------------------------- | ---------------------------------------------- | -------------- |
| **Raw**       | `data/raw/`                | Immutable source data organized by source/date | JSONL          |
| **Processed** | `data/processed/`          | Normalized indicators in common schema         | JSONL          |
| **Enriched**  | `data/processed_enriched/` | Indicators with added context                  | JSONL          |
| **Merged**    | `data/merged/`             | Deduplicated authoritative indicators          | JSONL          |
| **Graph**     | `data/graph/`              | Knowledge graph exports                        | GraphML, JSON  |
| **Scored**    | `data/scored/`             | Priority-ranked indicators (P1-P4)             | JSONL          |
| **Rules**     | `data/rules/`              | Generated detection rules                      | Sigma YAML     |
| **Reports**   | `data/reports/`            | Charts, summaries, PDFs                        | PDF, PNG, JSON |

### Configuration-Driven Design

All pipeline behavior is controlled through `config/config.yaml`:

```yaml
sources: # API endpoints, authentication, rate limits
enrichers: # Context providers and field mappings
merge_policy: # Deduplication rules and precedence
scoring: # Weights, decay factors, band thresholds
correlation: # Graph node types and relationship rules
```

---

## 🌐 Data Sources

### Public Feeds (No Authentication Required)

| Source            | Type            | Description                      | Update Frequency |
| ----------------- | --------------- | -------------------------------- | ---------------- |
| **URLhaus**       | URLs            | Malicious URL distribution sites | Hourly           |
| **MalwareBazaar** | Hashes          | Malware sample database          | Daily            |
| **PhishTank**     | URLs            | Phishing URL database            | Hourly           |
| **Spamhaus DROP** | IPs             | Netblock blacklist               | Daily            |
| **MITRE ATT&CK**  | TTPs            | Adversary tactics & techniques   | Monthly          |
| **NVD CVE**       | Vulnerabilities | CVE database                     | Daily            |
| **CWE**           | Weaknesses      | Common weakness enumeration      | Monthly          |
| **CISA KEV**      | Vulnerabilities | Known exploited vulnerabilities  | Weekly           |

### API-Based Sources (Require Registration)

| Source             | Type        | Description                | Rate Limit | Key Required |
| ------------------ | ----------- | -------------------------- | ---------- | ------------ |
| **AlienVault OTX** | Multi       | Open threat exchange       | 10/min     | Yes          |
| **VirusTotal**     | Hashes/URLs | File/URL reputation        | 4/min      | Yes          |
| **AbuseIPDB**      | IPs         | IP reputation database     | 60/min     | Yes          |
| **Shodan**         | IPs         | Internet-connected devices | 60/min     | Yes          |
| **GreyNoise**      | IPs         | Internet background noise  | 60/min     | Yes          |

**API Key Setup**: Store keys in `.env` file with format `API_KEY_{SOURCE_NAME}` (e.g., `API_KEY_VIRUSTOTAL`)

---

## 📖 Usage Guide

### Web Interface (Recommended for Beginners)

```bash
streamlit run app.py
# Opens browser interface for visual pipeline control
```

### Command-Line Execution

**Full Pipeline Run**

```bash
make daily              # Complete pipeline for today's data
python run_lab_analysis.py  # Alternative full run
```

**Individual Pipeline Stages**

```bash
make collect           # Data collection only
make normalize         # Normalization only
make enrich           # Enrichment only
make merge            # Deduplication
make correlate        # Build knowledge graph
make score            # Risk scoring
make gen-detect       # Generate detection rules
make report           # Create visualizations
```

### Advanced CLI Operations

**Health Checks & Monitoring**

```bash
python src/collection_cli.py health          # Check system status
python src/collection_cli.py status --verbose # Detailed diagnostics
```

**Source-Specific Collection**

```bash
python src/collection_cli.py collect --source virustotal
python src/collection_cli.py pipeline --sources malware_bazaar urlhaus
```

### Testing & Validation

```bash
# Component validation (uses real pipeline data)
python validate_analysis_simple.py    # Full pipeline test
python validate_enrichment.py         # Enrichment validation
python validate_analysis.py          # Analysis validation

# Individual component tests
python enhanced_collection.py        # Collection test
python normalization.py             # Normalization test
python enrichment_simple.py         # Enrichment test
```

---

## 📂 Project Structure

```
threat-aggregation-lab-osint/
├── 🔧 Configuration
│   ├── config/
│   │   ├── config.yaml              # Main system configuration
│   │   └── normalization_rules.yaml # Data transformation templates
│   └── .env                          # API keys (not in git)
│
├── 📊 Data Layers
│   └── data/
│       ├── raw/                      # Source data
│       ├── processed/                # Normalized indicators
│       ├── processed_enriched/       # Enriched data
│       ├── merged/                   # Deduplicated data
│       ├── graph/                    # Correlation graphs
│       ├── scored/                   # Risk-scored indicators
│       ├── rules/                    # Detection rules
│       └── reports/                  # Generated reports
│
├── 🧩 Source Code
│   └── src/
│       ├── collectors/               # Data collection
│       ├── normalizers/              # Data normalization
│       ├── enrichment/               # Context enrichment
│       ├── merge/                    # Deduplication
│       ├── correlation/              # Relationship analysis
│       ├── scoring/                  # Risk scoring
│       ├── detection/                # Rule generation
│       ├── analysis/                 # Advanced analytics
│       └── utils/                    # Helper functions
│
├── 🚀 Execution Scripts
│   ├── app.py                        # Streamlit web interface
│   ├── run_lab_analysis.py          # Full pipeline runner
│   ├── validate_*.py                # Validation scripts
│   └── Makefile                      # Build targets
│
└── 📚 Documentation
    ├── README.md                     # This file
    └── MEMORY_OPTIMIZATION.md       # Performance tuning
```

---

## 🔬 Advanced Topics

### Custom Collector Development

All collectors inherit from base classes in `src/collectors/base.py`:

```python
from src.collectors.base import RestApiCollector

class MyCollector(RestApiCollector):
    def collect(self):
        # Implement collection logic
        # Return JSONL with _source and _collected_at metadata
        pass
```

**Steps to add new sources:**

1. Create collector class extending appropriate base
2. Add configuration to `config/config.yaml`
3. Implement normalization rules in `config/normalization_rules.yaml`
4. Test with validation scripts

### Custom Enrichment Services

Add enrichers to `config/config.yaml`:

```yaml
enrichers:
  my_enricher:
    enabled: true
    endpoint: "https://api.example.com/enrich"
    api_key_env: "API_KEY_MY_ENRICHER"
    fields:
      - ip.address
      - domain.name
```

Implement enrichment logic in `src/enrichment/`:

```python
async def enrich_indicator(indicator):
    # Add context
    # Handle failures gracefully
    return enriched_indicator
```

### Integration with SIEM Platforms

Generated Sigma rules are compatible with:

- **Splunk**: Use Sigma → Splunk converter
- **Elastic Security**: Import Sigma detection rules
- **QRadar**: Convert to custom rules
- **Chronicle**: Use Sigma rule format

Export correlation graphs to:

- **Maltego**: Import GraphML format
- **Neo4j**: Load JSON relationships
- **Custom visualizations**: Parse JSON exports

### Performance Optimization

For large-scale deployments:

- Enable caching with Redis/Memcached
- Use parallel collection with worker pools
- Implement incremental processing
- Archive old data to cold storage
- See `MEMORY_OPTIMIZATION.md` for details

---

## 🤝 Contributing & Safety

### Ethical Guidelines

✅ **DO:**

- Use legitimate public threat intelligence sources
- Respect API rate limits and terms of service
- Keep API keys secure and never commit to git
- Use synthetic/benign data for testing
- Document all changes and configurations

❌ **DON'T:**

- Execute live malware or dangerous payloads
- Violate source provider terms of service
- Share or publish sensitive API keys
- Use for malicious purposes
- Ignore rate limiting constraints

### Security Best Practices

- **API Keys**: Store in `.env`, never hardcode
- **Data Privacy**: Raw data is gitignored
- **Access Control**: Limit who can run collection
- **Logging**: Monitor for suspicious activity
- **Updates**: Keep dependencies current

### Lab Requirements Compliance

This project fulfills academic lab requirements with:

- ✅ Complete Git repository with history
- ✅ Reproducible environment (requirements.txt)
- ✅ Comprehensive documentation
- ✅ Sample data demonstrating pipeline runs
- ✅ Generated reports showing capabilities

---

## 📝 Troubleshooting

### Common Issues

**Import Errors**

```bash
# Ensure virtual environment is activated
source .venv/bin/activate
# Run from project root
cd /path/to/threat-aggregation-lab-osint
```

**API Authentication Failures**

```bash
# Verify .env file exists and contains keys
cat .env | grep API_KEY
# Test specific source
python src/collection_cli.py collect --source otx
```

**Rate Limiting**

- Adjust `requests_per_minute` in `config/config.yaml`
- Add delays between calls
- Use public feeds for testing

**Permission Errors**

```bash
# Ensure write access to data directory
chmod -R u+w data/
```

### Debug Mode

Enable verbose logging:

```bash
export LOG_LEVEL=DEBUG
python run_lab_analysis.py
```

---

## 📜 License & Attribution

This is an educational project for cybersecurity training. All threat intelligence sources are properly attributed and used within their respective terms of service.

**Acknowledgments:**

- AlienVault OTX, abuse.ch, PhishTank, MITRE for threat data
- STIX/TAXII for data exchange standards
- Sigma project for detection rule format

---

## 🎓 Learning Outcomes

By completing this lab, you will gain hands-on experience with:

- **Threat Intelligence Operations**: Real-world SOC workflows
- **Data Engineering**: ETL pipelines for security data
- **API Integration**: Working with multiple threat feeds
- **Detection Engineering**: Creating actionable security rules
- **Automation**: Orchestrating complex security workflows
- **Reporting**: Communicating threat intelligence findings
- **Graph Analysis**: Understanding threat relationships

---

**Last Updated**: November 2025  
**Repository**: [github.com/Chris-Lopes/Osint_Exp_8](https://github.com/Chris-Lopes/Osint_Exp_8)  
**Maintainer**: Chris Lopes
