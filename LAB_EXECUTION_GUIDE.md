# LAB ASSIGNMENT EXECUTION GUIDE

## Quick Start - Complete Lab Run

**To run the entire system and collect all data for your lab assignment:**

### Option 1: Web Interface (Recommended for Beginners)
```bash
# Make sure you're in the lab directory
cd /media/vanessa-rodrigues/Data/Projects/Ubuntu/lab8/threat-aggregation-lab

# Activate Python environment (if not already active)
source .venv/bin/activate

# Launch the interactive web interface
streamlit run app.py
```

The web interface will open in your browser. Click "🚀 Start Complete Lab Run" to execute the full pipeline and view results with interactive visualizations.

### Option 2: Command Line (Advanced Users)
```bash
# Make sure you're in the lab directory
cd /media/vanessa-rodrigues/Data/Projects/Ubuntu/lab8/threat-aggregation-lab

# Activate Python environment (if not already active)
source .venv/bin/activate

# Run the complete lab analysis
python run_lab_analysis.py
```

This single command will:
1. ✅ Collect threat intelligence data from multiple sources
2. ✅ Normalize and enrich the data
3. ✅ Run correlation analysis  
4. ✅ Perform risk scoring and prioritization
5. ✅ Generate timeline analysis
6. ✅ Create detection rules
7. ✅ Generate comprehensive reports for your assignment

## Individual Component Testing

If you want to run components separately:

### Using the Web Interface
- Launch with `streamlit run app.py`
- The interface provides guided execution and real-time progress monitoring

### Using the Command Line Interface (CLI)
```bash
# Test data collection with health monitoring
python src/collection_cli.py health
python src/collection_cli.py collect --source example_public

# Test normalization
python src/collection_cli.py normalize --validate
python src/collection_cli.py normalize

# Test enrichment
python src/collection_cli.py enrich --validate
python src/collection_cli.py enrich

# Run end-to-end pipeline for specific sources
python src/collection_cli.py pipeline --sources example_public
```

### Legacy Testing Scripts
```bash
# Test data collection
python enhanced_collection.py

# Test normalization
python normalization.py  

# Test enrichment
python enrichment_simple.py

# Run comprehensive enrichment testing
python enrichment.py

# Test complete analysis pipeline
python validate_analysis_simple.py
```

## Troubleshooting

If you encounter issues:

### Web Interface Issues
```bash
# If Streamlit doesn't start
streamlit --version
pip install --upgrade streamlit

# Clear Streamlit cache
rm -rf ~/.streamlit/
```

### CLI and Collection Issues
```bash
# Check system validation
python validate_analysis_simple.py

# Check collection health
python src/collection_cli.py health

# View detailed status
python src/collection_cli.py status --verbose --json

# Check Python environment
python --version
pip list | grep -E "(pandas|requests|pydantic|streamlit)"

# Check data directories
ls -la data/

# View logs for detailed error information
tail -f *.log
```

### Common Issues
- **Streamlit not found**: Run `pip install streamlit` in your virtual environment
- **Collection failures**: Check API keys in `.env` file and network connectivity
- **Import errors**: Ensure you're running from the project root directory
- **Permission errors**: Check write permissions for the `data/` directory
```

## Generated Output Files

After running the lab, you'll find these files for your report:

### Main Lab Reports
- `data/reports/lab_execution_report.json` - Detailed technical data
- `data/reports/lab_insights_analysis.json` - Analysis and insights  
- `data/reports/lab_summary.txt` - Executive summary (easy to read)

### Web Interface Outputs
- `output-json/run_summary_*.json` - JSON summaries of each web interface run
- Interactive visualizations in the browser (risk score distributions, indicator types, confidence analysis)

### Data Files for Analysis
- `data/processed/` - Normalized threat intelligence data
- `data/enriched/` - Enhanced data with context
- `data/analysis/` - Correlation and analysis results

## Key Lab Assignment Elements

### 1. System Architecture
**What to document:**
- Multi-source data collection pipeline
- Normalization to STIX-like schema
- Enrichment with reputation/geolocation data
- Correlation analysis engine
- Risk scoring and prioritization
- Detection rule generation

### 2. Data Analysis Results
**What to include in your report:**
- Number of threat indicators processed
- Correlation relationships discovered
- Risk score distributions and priority bands
- Timeline analysis findings
- Attribution analysis results

### 3. Insights and Inferences
**What to analyze:**
- Threat landscape patterns
- Most common indicator types
- Geographic distribution of threats
- Temporal patterns in threat activity
- Effectiveness of correlation techniques
- Quality of risk scoring

### 4. Security Recommendations
**Based on your analysis:**
- Priority threats to monitor
- Detection strategies to implement
- Data sources providing highest value
- Process improvements for SOC operations

## Lab Report Structure Suggestion

1. **Executive Summary**
   - Purpose and scope of the analysis
   - Key findings and recommendations

2. **System Architecture**
   - Pipeline components and data flow
   - Integration capabilities demonstrated

3. **Data Analysis**
   - Sources and volumes processed
   - Correlation and scoring results
   - Statistical summaries

4. **Threat Intelligence Findings**
   - Threat landscape insights
   - Patterns and trends identified
   - High-priority indicators discovered

5. **Security Recommendations**
   - Operational improvements
   - Detection strategy recommendations
   - Future enhancement opportunities

6. **Conclusion**
   - System effectiveness assessment
   - Learning outcomes achieved
   - Practical applications for SOC operations

## Advanced CLI Tool

The system includes a comprehensive command-line interface for advanced users and automation:

### Collection Management
```bash
# Check system health and source status
python src/collection_cli.py health

# View collection status and statistics
python src/collection_cli.py status --verbose

# Collect from specific sources
python src/collection_cli.py collect --source virustotal --date 2025-10-05

# View collection history
python src/collection_cli.py history --days 7

# List all available sources
python src/collection_cli.py sources --verbose

# Clean up old data
python src/collection_cli.py cleanup --days 30
```

### Data Processing Pipeline
```bash
# Validate normalized data integrity
python src/collection_cli.py normalize --validate

# Normalize data for specific sources
python src/collection_cli.py normalize --source malware_bazaar

# Check enrichment service availability
python src/collection_cli.py enrich --validate

# Run end-to-end pipeline
python src/collection_cli.py pipeline --sources virustotal malware_bazaar
```

### Monitoring and Troubleshooting
```bash
# Get detailed status in JSON format
python src/collection_cli.py status --json

# Enable verbose logging
python src/collection_cli.py collect --verbose --log-level DEBUG

# Log to file for analysis
python src/collection_cli.py collect --log-file collection.log
```

## Screenshots to Capture

For your lab report, capture:

### Web Interface Screenshots
1. **Main dashboard** - Initial screen with "Start Complete Lab Run" button
2. **Progress monitoring** - Real-time execution progress and status updates
3. **Execution results** - Successful completion message and timing
4. **Analysis results** - JSON reports displayed in expandable sections
5. **Interactive visualizations** - Risk score distribution histograms, indicator type charts, confidence scatter plots
6. **Summary display** - Executive summary text area content

### Terminal/Command Line Screenshots
1. Terminal output showing successful pipeline execution
2. CLI tool status and health check results
3. Collection history and source statistics

### Data and Reports
4. Generated report files and their contents
5. Data visualization outputs (if any)
6. System validation success messages
7. File directory structure showing generated data

## Web Interface Features

The Streamlit-based web interface provides:

### Interactive Execution
- **One-click execution** of the complete threat intelligence pipeline
- **Real-time progress monitoring** with status updates and timing
- **Automatic error handling** with detailed error messages

### Rich Visualizations
- **Risk score distributions** - Histograms showing threat prioritization
- **Indicator type analysis** - Bar charts of different threat categories
- **Confidence vs Risk scatter plots** - Correlation analysis visualizations
- **Summary statistics** - Key metrics and counts

### Comprehensive Reporting
- **JSON report viewers** - Expandable sections for detailed technical data
- **Executive summaries** - Easy-to-read text summaries for lab reports
- **Run summaries** - JSON exports saved to `output-json/` folder
- **Detection rule previews** - Sample Sigma rules generated by the system

### User-Friendly Design
- **No command-line knowledge required** - Point-and-click interface
- **Progress indicators** - Visual feedback during long-running operations
- **Expandable sections** - Organized display of complex data
- **Export capabilities** - JSON summaries for further analysis

## Quick Command Reference

### Primary Execution Methods
```bash
# Web interface (recommended)
streamlit run app.py

# Command line execution
python run_lab_analysis.py
```

### CLI Tool Commands
```bash
# Health and status
python src/collection_cli.py health
python src/collection_cli.py status --verbose
python src/collection_cli.py history --days 7

# Collection operations
python src/collection_cli.py collect
python src/collection_cli.py collect --source virustotal

# Data processing
python src/collection_cli.py normalize
python src/collection_cli.py enrich
python src/collection_cli.py pipeline

# Legacy validation
python validate_analysis_simple.py
```

### Output and Results
```bash
# View lab summary
cat data/reports/lab_summary.txt

# Check system status
python -c "import src; print('System ready')"

# View latest run summary
ls -la output-json/
cat output-json/run_summary_*.json | tail -1
```

## Important Notes

- The system uses simulated/synthetic threat data for safety
- All sources are legitimate threat intelligence feeds
- No live malware or dangerous content is processed
- Results demonstrate SOC pipeline capabilities without security risks
- The web interface provides the same results as command-line execution
- CLI tools offer advanced monitoring and management capabilities
- Both execution methods generate identical reports and data