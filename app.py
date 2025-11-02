import streamlit as st
import subprocess
import sys
import time
import json
import os
import base64
import logging
from pathlib import Path
from datetime import datetime
import pandas as pd
# Try to import matplotlib; Streamlit apps can be started with different interpreters
try:
    import matplotlib.pyplot as plt
    _HAS_MATPLOTLIB = True
except Exception:
    _HAS_MATPLOTLIB = False

# Try to import reportlab for PDF generation
try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle, Image
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    import io
    _HAS_REPORTLAB = True
except Exception:
    _HAS_REPORTLAB = False

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def generate_threat_report():
    """
    Generate a comprehensive PDF threat intelligence report.
    Returns: (pdf_buffer, filename)
    """
    if not _HAS_REPORTLAB:
        raise ImportError("ReportLab is required for PDF generation. Install with: pip install reportlab")
    
    if not _HAS_MATPLOTLIB:
        raise ImportError("Matplotlib is required for chart generation. Install with: pip install matplotlib")
    
    # Create a buffer to hold the PDF
    buffer = io.BytesIO()
    
    # Create the PDF document
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=72, leftMargin=72,
                           topMargin=72, bottomMargin=18)
    
    # Container for the 'Flowable' objects
    elements = []
    
    # Define styles
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#1f77b4'),
        spaceAfter=30,
        alignment=TA_CENTER
    )
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=16,
        textColor=colors.HexColor('#2c3e50'),
        spaceAfter=12,
        spaceBefore=12
    )
    
    # Title
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    title = Paragraph(f"Threat Intelligence Report<br/>{timestamp}", title_style)
    elements.append(title)
    elements.append(Spacer(1, 12))
    
    # Executive Summary Section
    elements.append(Paragraph("Executive Summary", heading_style))
    
    # Load summary data
    summary_file = Path("data/reports/lab_summary.txt")
    if summary_file.exists():
        with open(summary_file) as f:
            summary_text = f.read()
        elements.append(Paragraph(summary_text.replace('\n', '<br/>'), styles['Normal']))
    else:
        elements.append(Paragraph("No summary data available.", styles['Normal']))
    
    elements.append(Spacer(1, 20))
    
    # System Tasks Performed Section
    elements.append(Paragraph("System Tasks Performed", heading_style))
    
    report_file = Path("data/reports/lab_execution_report.json")
    if report_file.exists():
        with open(report_file) as f:
            report_data = json.load(f)
        
        if 'lab_execution' in report_data and 'components_tested' in report_data['lab_execution']:
            tasks_data = [[Paragraph("<b>Component</b>", styles['Normal'])]]
            for component in report_data['lab_execution']['components_tested']:
                tasks_data.append([Paragraph(component, styles['Normal'])])
            
            tasks_table = Table(tasks_data, colWidths=[4.5*inch])
            tasks_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            elements.append(tasks_table)
    else:
        elements.append(Paragraph("No execution data available.", styles['Normal']))
    
    elements.append(Spacer(1, 20))
    
    # Threat IOCs Collected Section
    elements.append(Paragraph("Threat Indicators of Compromise (IOCs)", heading_style))
    
    # Load and analyze scored data
    scored_dir = Path("data/scored")
    ioc_stats = {
        'total_iocs': 0,
        'by_type': {},
        'high_risk': 0,
        'medium_risk': 0,
        'low_risk': 0
    }
    
    if scored_dir.exists():
        scored_files = list(scored_dir.glob("*.jsonl"))
        all_scored = []
        
        for file in scored_files:
            try:
                with open(file) as f:
                    for line in f:
                        all_scored.append(json.loads(line))
            except Exception as e:
                logger.warning(f"Error reading {file}: {e}")
        
        if all_scored:
            df = pd.DataFrame(all_scored)
            ioc_stats['total_iocs'] = len(df)
            
            if 'indicator_type' in df.columns:
                ioc_stats['by_type'] = df['indicator_type'].value_counts().to_dict()
            
            if 'risk_score' in df.columns:
                ioc_stats['high_risk'] = len(df[df['risk_score'] >= 7])
                ioc_stats['medium_risk'] = len(df[(df['risk_score'] >= 4) & (df['risk_score'] < 7)])
                ioc_stats['low_risk'] = len(df[df['risk_score'] < 4])
    
    # IOC Statistics Table
    ioc_data = [
        [Paragraph("<b>Metric</b>", styles['Normal']), Paragraph("<b>Count</b>", styles['Normal'])],
        [Paragraph("Total IOCs Collected", styles['Normal']), Paragraph(str(ioc_stats['total_iocs']), styles['Normal'])],
        [Paragraph("High Risk (Score ≥ 7)", styles['Normal']), Paragraph(str(ioc_stats['high_risk']), styles['Normal'])],
        [Paragraph("Medium Risk (Score 4-7)", styles['Normal']), Paragraph(str(ioc_stats['medium_risk']), styles['Normal'])],
        [Paragraph("Low Risk (Score < 4)", styles['Normal']), Paragraph(str(ioc_stats['low_risk']), styles['Normal'])]
    ]
    
    ioc_table = Table(ioc_data, colWidths=[3*inch, 1.5*inch])
    ioc_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    elements.append(ioc_table)
    elements.append(Spacer(1, 20))
    
    # IOC Types Distribution
    if ioc_stats['by_type']:
        elements.append(Paragraph("IOC Types Distribution", heading_style))
        type_data = [[Paragraph("<b>IOC Type</b>", styles['Normal']), Paragraph("<b>Count</b>", styles['Normal'])]]
        for ioc_type, count in list(ioc_stats['by_type'].items())[:10]:  # Top 10
            type_data.append([Paragraph(str(ioc_type), styles['Normal']), Paragraph(str(count), styles['Normal'])])
        
        type_table = Table(type_data, colWidths=[3*inch, 1.5*inch])
        type_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        elements.append(type_table)
    
    elements.append(PageBreak())
    
    # Visualizations Section
    elements.append(Paragraph("Threat Data Visualizations", heading_style))
    
    # Generate charts if data is available
    if scored_dir.exists() and all_scored:
        try:
            # Risk Score Distribution Chart
            fig, ax = plt.subplots(figsize=(6, 4))
            if 'risk_score' in df.columns:
                ax.hist(df['risk_score'], bins=20, alpha=0.7, color='#e74c3c', edgecolor='black')
                ax.set_title("Risk Score Distribution", fontsize=14, fontweight='bold')
                ax.set_xlabel("Risk Score")
                ax.set_ylabel("Frequency")
                ax.grid(True, alpha=0.3)
                
                # Save to buffer
                img_buffer = io.BytesIO()
                plt.savefig(img_buffer, format='png', dpi=150, bbox_inches='tight')
                img_buffer.seek(0)
                plt.close()
                
                # Add to PDF
                img = Image(img_buffer, width=5*inch, height=3.5*inch)
                elements.append(img)
                elements.append(Spacer(1, 12))
            
            # IOC Types Bar Chart
            if 'indicator_type' in df.columns and len(ioc_stats['by_type']) > 0:
                fig, ax = plt.subplots(figsize=(6, 4))
                type_counts = pd.Series(ioc_stats['by_type']).head(10)
                type_counts.plot(kind='bar', ax=ax, color='#3498db', edgecolor='black')
                ax.set_title("Top 10 IOC Types", fontsize=14, fontweight='bold')
                ax.set_xlabel("IOC Type")
                ax.set_ylabel("Count")
                ax.grid(True, alpha=0.3, axis='y')
                plt.xticks(rotation=45, ha='right')
                
                # Save to buffer
                img_buffer = io.BytesIO()
                plt.savefig(img_buffer, format='png', dpi=150, bbox_inches='tight')
                img_buffer.seek(0)
                plt.close()
                
                # Add to PDF
                img = Image(img_buffer, width=5*inch, height=3.5*inch)
                elements.append(img)
        
        except Exception as e:
            logger.warning(f"Error generating charts: {e}")
            elements.append(Paragraph(f"Chart generation error: {str(e)}", styles['Normal']))
    else:
        elements.append(Paragraph("No data available for visualizations.", styles['Normal']))
    
    elements.append(PageBreak())
    
    # Conclusion Section
    elements.append(Paragraph("Conclusion and Recommendations", heading_style))
    
    insights_file = Path("data/reports/lab_insights_analysis.json")
    if insights_file.exists():
        with open(insights_file) as f:
            insights_data = json.load(f)
        
        if 'insights_for_lab' in insights_data and 'recommendations' in insights_data['insights_for_lab']:
            recommendations = insights_data['insights_for_lab']['recommendations']
            for i, rec in enumerate(recommendations, 1):
                elements.append(Paragraph(f"{i}. {rec}", styles['Normal']))
                elements.append(Spacer(1, 6))
        else:
            elements.append(Paragraph("No specific recommendations available.", styles['Normal']))
    else:
        conclusion_text = f"""
        This threat intelligence report analyzed {ioc_stats['total_iocs']} indicators of compromise 
        collected from multiple sources. The analysis identified {ioc_stats['high_risk']} high-risk threats 
        that require immediate attention. The system successfully processed data through all pipeline stages 
        including collection, normalization, enrichment, correlation, and risk scoring.
        <br/><br/>
        Key takeaways:
        <br/>• Continue monitoring high-risk indicators
        <br/>• Review and implement generated detection rules
        <br/>• Maintain regular threat intelligence updates
        <br/>• Correlate findings with existing security infrastructure
        """
        elements.append(Paragraph(conclusion_text, styles['Normal']))
    
    elements.append(Spacer(1, 20))
    
    # Footer with metadata
    elements.append(Paragraph("_" * 80, styles['Normal']))
    elements.append(Spacer(1, 6))
    footer_text = f"<i>Report generated on {timestamp}<br/>Threat Aggregation Lab - SOC Intelligence Pipeline</i>"
    elements.append(Paragraph(footer_text, styles['Normal']))
    
    # Build PDF
    doc.build(elements)
    
    # Get PDF data
    pdf_data = buffer.getvalue()
    buffer.close()
    
    # Generate filename
    filename = f"threat_intelligence_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    
    return pdf_data, filename


st.set_page_config(page_title="Threat Aggregation Lab GUI", layout="wide", initial_sidebar_state="expanded")

st.title("🎓 Threat Intelligence Aggregation Lab")
st.markdown("A comprehensive threat intelligence pipeline for SOC operations")

# Sidebar for navigation and controls
st.sidebar.header("Navigation")
page = st.sidebar.radio("Select Page", ["🏠 Dashboard", "📊 Lab Execution", "📄 Report Generation"])

st.sidebar.header("Lab Controls")

if st.sidebar.button("🚀 Start Complete Lab Run", type="primary"):
    st.session_state.run_started = True
    st.session_state.start_time = time.time()
    st.session_state.progress = 0
    st.session_state.status = "Initializing..."
    st.rerun()

# ===== PAGE: Dashboard =====
if page == "🏠 Dashboard":
    st.header("ℹ️ About This Lab")
    st.markdown("""
    This application runs a comprehensive threat intelligence aggregation pipeline that:
    
    1. **Collects** threat data from multiple open sources
    2. **Normalizes** heterogeneous data into a consistent format  
    3. **Enriches** indicators with reputation, geolocation, and context
    4. **Correlates** related indicators and identifies patterns
    5. **Scores** threats by risk level and prioritizes them
    6. **Generates** detection rules and actionable insights
    
    The results include scoring visualizations, detection content, and comprehensive reports for SOC operations.
    """)
    
    st.header("📁 Expected Outputs")
    st.markdown("""
    After a successful run, the following will be generated:
    - **JSON Reports**: Detailed execution data and analysis insights
    - **Risk Scores**: Prioritized threat indicators with scoring breakdowns
    - **Detection Rules**: Sigma-style rules for SIEM integration
    - **Visualizations**: Charts showing threat distributions and patterns
    - **Run Summary**: JSON summary saved to `output-json/` folder
    """)

# ===== PAGE: Lab Execution =====
elif page == "📊 Lab Execution":
    if 'run_started' in st.session_state and st.session_state.run_started:
        # Progress section
        st.header("📊 Run Progress")
        
        progress_bar = st.progress(0)
        status_text = st.empty()
        timer_text = st.empty()
        
        # Run the lab analysis
        try:
            status_text.text("🚀 Starting lab execution...")
            progress_bar.progress(10)
            
            # Run the analysis script
            result = subprocess.run([
                sys.executable, 'run_lab_analysis.py'
            ], capture_output=True, text=True, cwd=Path.cwd())
            
            progress_bar.progress(100)
            status_text.text("✅ Lab execution completed!")
            
            # Calculate duration
            duration = time.time() - st.session_state.start_time
            timer_text.text(f"⏱️ Execution time: {duration:.2f} seconds")
            
            # Display results
            st.header("📋 Execution Results")
            
            if result.returncode == 0:
                st.success("Lab run completed successfully!")
                
                # Display stdout
                with st.expander("📄 Detailed Output"):
                    st.code(result.stdout, language="text")
            else:
                st.error("Lab run encountered errors")
                with st.expander("❌ Error Details"):
                    st.code(result.stderr, language="text")
            
            # Load and display reports
            st.header("📊 Analysis Results")
            
            col1, col2 = st.columns(2)
            
            # Lab execution report
            with col1:
                st.subheader("📈 Lab Execution Report")
                report_file = Path("data/reports/lab_execution_report.json")
                if report_file.exists():
                    with open(report_file) as f:
                        report_data = json.load(f)
                    
                    st.json(report_data)
                else:
                    st.warning("Execution report not found")
            
            # Insights analysis
            with col2:
                st.subheader("🎯 Lab Insights & Analysis")
                insights_file = Path("data/reports/lab_insights_analysis.json")
                if insights_file.exists():
                    with open(insights_file) as f:
                        insights_data = json.load(f)
                    
                    st.json(insights_data)
                else:
                    st.warning("Insights report not found")
            
            # Summary text
            st.subheader("📝 Executive Summary")
            summary_file = Path("data/reports/lab_summary.txt")
            if summary_file.exists():
                with open(summary_file) as f:
                    summary = f.read()
                st.text_area("Summary", summary, height=300)
            else:
                st.warning("Summary file not found")
            
            # Scoring and Detection
            st.header("🔍 Scoring & Detection Results")
            
            # Look for scored data
            scored_dir = Path("data/scored")
            if scored_dir.exists():
                scored_files = list(scored_dir.glob("*.jsonl"))
                if scored_files:
                    st.subheader("📊 Risk Scoring Results")
                    
                    # Load all scored data
                    all_scored = []
                    for file in scored_files:
                        with open(file) as f:
                            for line in f:
                                all_scored.append(json.loads(line))
                    
                    if all_scored:
                        df = pd.DataFrame(all_scored)
                        
                        # Display data table
                        st.dataframe(df.head(20))  # Show first 20 rows
                        
                        # Visualizations
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            if 'risk_score' in df.columns:
                                if _HAS_MATPLOTLIB:
                                    fig, ax = plt.subplots(figsize=(8, 6))
                                    ax.hist(df['risk_score'], bins=20, alpha=0.7, color='red')
                                    ax.set_title("Risk Score Distribution")
                                    ax.set_xlabel("Risk Score")
                                    ax.set_ylabel("Frequency")
                                    st.pyplot(fig)
                                else:
                                    st.warning("matplotlib is not available in this Python environment — visualizations are disabled. Install matplotlib and restart the app to enable plots.")
                        
                        with col2:
                            if 'indicator_type' in df.columns:
                                if _HAS_MATPLOTLIB:
                                    type_counts = df['indicator_type'].value_counts()
                                    fig, ax = plt.subplots(figsize=(8, 6))
                                    type_counts.plot(kind='bar', ax=ax, color='blue')
                                    ax.set_title("Indicator Types Distribution")
                                    ax.set_xlabel("Indicator Type")
                                    ax.set_ylabel("Count")
                                    plt.xticks(rotation=45)
                                    st.pyplot(fig)
                                else:
                                    st.warning("matplotlib is not available in this Python environment — visualizations are disabled. Install matplotlib and restart the app to enable plots.")
                        
                        # Additional visualizations
                        if 'confidence' in df.columns:
                            if _HAS_MATPLOTLIB:
                                fig, ax = plt.subplots(figsize=(8, 6))
                                ax.scatter(df['confidence'], df['risk_score'], alpha=0.6, color='green')
                                ax.set_title("Confidence vs Risk Score")
                                ax.set_xlabel("Confidence")
                                ax.set_ylabel("Risk Score")
                                st.pyplot(fig)
                            else:
                                st.warning("matplotlib is not available in this Python environment — visualizations are disabled. Install matplotlib and restart the app to enable plots.")
                        
                        # Summary statistics
                        st.subheader("📈 Scoring Statistics")
                        col1, col2, col3 = st.columns(3)
                        
                        with col1:
                            st.metric("Total Indicators", len(df))
                        
                        with col2:
                            if 'risk_score' in df.columns:
                                st.metric("Avg Risk Score", f"{df['risk_score'].mean():.2f}")
                        
                        with col3:
                            if 'indicator_type' in df.columns:
                                st.metric("Unique Types", df['indicator_type'].nunique())
                else:
                    st.info("No scored data found yet")
            
            # Detection rules
            rules_dir = Path("data/rules")
            if rules_dir.exists():
                rules_files = list(rules_dir.glob("**/*.yaml"))
                if rules_files:
                    st.subheader("🛡️ Generated Detection Rules")
                    st.write(f"Found {len(rules_files)} detection rule files")
                    
                    # Show first rule
                    with open(rules_files[0]) as f:
                        rule_content = f.read()
                    st.code(rule_content, language="yaml")
            
            # Create JSON summary for output-json folder
            st.header("💾 Saving Run Summary")
            
            output_dir = Path("output-json")
            output_dir.mkdir(exist_ok=True)
            
            run_summary = {
                "run_timestamp": datetime.now().isoformat(),
                "execution_duration_seconds": duration,
                "success": result.returncode == 0,
                "reports_generated": {
                    "execution_report": report_file.exists(),
                    "insights_report": insights_file.exists(),
                    "summary_text": summary_file.exists()
                },
                "data_processed": {
                    "scored_files": len(list(scored_dir.glob("*.jsonl"))) if scored_dir.exists() else 0,
                    "rules_generated": len(list(rules_dir.glob("**/*.yaml"))) if rules_dir.exists() else 0
                },
                "key_metrics": {
                    "total_execution_time": f"{duration:.2f}",
                    "pipeline_steps_completed": 6 if result.returncode == 0 else 0
                }
            }
            
            summary_path = output_dir / f"run_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(summary_path, 'w') as f:
                json.dump(run_summary, f, indent=2)
            
            st.success(f"✅ Run summary saved to: {summary_path}")
            st.json(run_summary)
            
        except Exception as e:
            st.error(f"Error during execution: {str(e)}")
            st.session_state.run_started = False

    else:
        st.info("👆 Click 'Start Complete Lab Run' in the sidebar to begin the threat intelligence analysis pipeline.")

# ===== PAGE: Report Generation =====
elif page == "📄 Report Generation":
    st.header("📄 Threat Intelligence Report Generation")
    st.markdown("""
    Generate comprehensive PDF reports containing:
    - **Executive Summary**: Overview of tasks performed and key findings
    - **Threat IOCs**: Collected indicators of compromise with statistics
    - **Visualizations**: Charts and graphs of threat data
    - **Conclusion**: Key insights and recommendations
    """)
    
    # Initialize session state for PDF storage
    if 'generated_pdf' not in st.session_state:
        st.session_state.generated_pdf = None
    if 'pdf_filename' not in st.session_state:
        st.session_state.pdf_filename = None
    
    # Report generation controls
    st.subheader("📊 Report Controls")
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("🔄 Generate Report", type="primary", use_container_width=True):
            with st.spinner("Generating comprehensive threat intelligence report..."):
                try:
                    # Generate the PDF report
                    pdf_buffer, filename = generate_threat_report()
                    st.session_state.generated_pdf = pdf_buffer
                    st.session_state.pdf_filename = filename
                    st.success("✅ Report generated successfully!")
                except Exception as e:
                    st.error(f"❌ Error generating report: {str(e)}")
                    logger.error(f"Report generation error: {str(e)}", exc_info=True)
    
    with col2:
        if st.session_state.generated_pdf:
            st.download_button(
                label="⬇️ Download PDF Report",
                data=st.session_state.generated_pdf,
                file_name=st.session_state.pdf_filename,
                mime="application/pdf",
                use_container_width=True
            )
        else:
            st.button("⬇️ Download PDF Report", disabled=True, use_container_width=True)
    
    # PDF Viewer
    if st.session_state.generated_pdf:
        st.subheader("📄 Report Preview")
        
        # Display PDF using iframe
        base64_pdf = base64.b64encode(st.session_state.generated_pdf).decode('utf-8')
        pdf_display = f'<iframe src="data:application/pdf;base64,{base64_pdf}" width="100%" height="800px" type="application/pdf"></iframe>'
        st.markdown(pdf_display, unsafe_allow_html=True)
    else:
        st.info("👆 Click 'Generate Report' to create a new threat intelligence report")
    
    # Report metadata section
    st.subheader("📋 Available Data for Report")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        # Check raw data
        raw_dir = Path("data/raw")
        if raw_dir.exists():
            raw_files = list(raw_dir.glob("**/*.jsonl"))
            st.metric("Raw Data Files", len(raw_files))
    
    with col2:
        # Check processed data
        processed_dir = Path("data/processed")
        if processed_dir.exists():
            processed_files = list(processed_dir.glob("**/*.jsonl"))
            st.metric("Processed Files", len(processed_files))
    
    with col3:
        # Check scored data
        scored_dir = Path("data/scored")
        if scored_dir.exists():
            scored_files = list(scored_dir.glob("*.jsonl"))
            st.metric("Scored Files", len(scored_files))

# Footer
st.markdown("---")
st.markdown("*Threat Intelligence Aggregation Lab - End-to-End SOC Pipeline*")