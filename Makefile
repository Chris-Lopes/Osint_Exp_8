.PHONY: help venv install clean test smoke daily normalize enrich merge correlate score detect report
SHELL := /bin/bash

# Default target
help:
	@echo "Threat Aggregation Lab - Available targets:"
	@echo "  setup     - Create venv and install dependencies"
	@echo "  smoke     - Run smoke test"
	@echo "  daily     - Execute full pipeline for today"
	@echo "  collect   - Run all collectors"
	@echo "  normalize - Normalize all raw data"
	@echo "  enrich    - Run enrichment pipeline" 
	@echo "  merge     - Merge and deduplicate"
	@echo "  correlate - Build correlation graph"
	@echo "  score     - Score and prioritize"
	@echo "  detect    - Generate detection rules"
	@echo "  report    - Create reports and visualizations"
	@echo "  test      - Run validation tests"
	@echo "  clean     - Clean generated data"

# Environment setup
venv:
	python3 -m venv .venv

install: venv
	. .venv/bin/activate && pip install -r requirements.txt

setup: install
	cp .env.example .env
	@echo "Setup complete! Edit .env with your API keys"

# Testing and validation
smoke:
	. .venv/bin/activate && python -m src.collectors.example_public

test:
	. .venv/bin/activate && python -m pytest tests/ -v

# Individual pipeline stages
collect:
	. .venv/bin/activate && python -m src.collectors.run_all

collect-enhanced:
	. .venv/bin/activate && python src/collection_cli.py collect

collect-source:
	. .venv/bin/activate && python src/collection_cli.py collect --source $(SOURCE)

collection-status:
	. .venv/bin/activate && python src/collection_cli.py status --verbose

collection-health:
	. .venv/bin/activate && python src/collection_cli.py health

normalize:
	. .venv/bin/activate && python -m src.normalizers.normalize_run

normalize-date:
	. .venv/bin/activate && python -m src.normalizers.normalize_run $(DATE)

enrich:
	. .venv/bin/activate && python run_enrichment.py

enrich-date:
	. .venv/bin/activate && python run_enrichment.py $(DATE)

merge:
	. .venv/bin/activate && python -m src.merge.run_merge

merge-date:
	. .venv/bin/activate && python -m src.merge.run_merge $(DATE)

correlate:
	. .venv/bin/activate && python -m src.correlation.run_correlate

correlate-date:
	. .venv/bin/activate && python -m src.correlation.run_correlate $(DATE)

score:
	. .venv/bin/activate && python -m src.scoring.run_scoring

score-date:
	. .venv/bin/activate && python -m src.scoring.run_scoring $(DATE)

# Detection and reporting
gen-detect:
	. .venv/bin/activate && python -m src.detection.gen_sigma data/scored/$(DATE).jsonl data/rules/$(DATE)

mock-detect:
	. .venv/bin/activate && python -m src.detection.mock_engine data/rules/$(DATE) data/simlogs/$(DATE).jsonl data/alerts/$(DATE).json

summary:
	. .venv/bin/activate && python -m src.reporting.summary data/scored/$(DATE).jsonl data/feedback/$(DATE).json > data/reports/$(DATE).summary.json

charts:
	. .venv/bin/activate && python -m src.reporting.charts band_bar data/scored/$(DATE).jsonl data/reports/$(DATE).bands.png

report:
	. .venv/bin/activate && python -m src.reporting.pdf_report data/reports/$(DATE).summary.json data/reports/$(DATE).bands.png data/reports/$(DATE).daily.pdf

# Orchestration
daily:
	. .venv/bin/activate && python -m src.orchestration.daily_run

playbook:
	. .venv/bin/activate && python -m src.orchestration.playbook data/alerts/$(DATE).json data/tickets/$(DATE).json

# Simulation and validation
simulate:
	. .venv/bin/activate && python -m src.simulation.replay data/rules/$(DATE) data/simulations/$(DATE).jsonl data/alerts/$(DATE).sim.json

coverage:
	. .venv/bin/activate && python -m src.simulation.coverage data/alerts/$(DATE).sim.json data/simulations/$(DATE).jsonl

# Utilities
clean:
	rm -rf data/raw/* data/processed/* data/processed_enriched/* data/merged/* 
	rm -rf data/graph/* data/scored/* data/rules/* data/alerts/* data/reports/*
	rm -rf data/tickets/* data/.state/* data/.cache/*

clean-cache:
	rm -rf data/.cache/* data/.state/*

status:
	@echo "=== Pipeline Status ==="
	@echo "Raw files: $$(find data/raw -name '*.jsonl' 2>/dev/null | wc -l)"
	@echo "Processed files: $$(find data/processed -name '*.jsonl' 2>/dev/null | wc -l)"
	@echo "Scored files: $$(find data/scored -name '*.jsonl' 2>/dev/null | wc -l)"
	@echo "Graph files: $$(find data/graph -name '*.graphml' 2>/dev/null | wc -l)"
	@echo "Reports: $$(find data/reports -name '*.pdf' 2>/dev/null | wc -l)"

# Run major pipeline modules in parallel (collect, normalize, enrich, merge, correlate, score)
.PHONY: all-parallel
DATE ?= $(shell date +%F)
all-parallel:
	@mkdir -p logs
	@echo "Starting collection, normalization, enrichment, merge, correlation and scoring in parallel (logs in logs/)..."
	@(. .venv/bin/activate && python -m src.collectors.run_all > logs/collect.log 2>&1) & echo "collect: $$!" > logs/collect.pid; \
	(. .venv/bin/activate && python -m src.normalizers.normalize_run > logs/normalize.log 2>&1) & echo "normalize: $$!" > logs/normalize.pid; \
	(. .venv/bin/activate && python run_enrichment.py > logs/enrich.log 2>&1) & echo "enrich: $$!" > logs/enrich.pid; \
	(. .venv/bin/activate && python -m src.merge.run_merge > logs/merge.log 2>&1) & echo "merge: $$!" > logs/merge.pid; \
	(. .venv/bin/activate && python -m src.correlation.run_correlate > logs/correlate.log 2>&1) & echo "correlate: $$!" > logs/correlate.pid; \
	(. .venv/bin/activate && python -m src.scoring.run_scoring > logs/score.log 2>&1) & echo "score: $$!" > logs/score.pid; \
	# Wait for all background jobs to finish
	wait
	@echo "All modules finished. Generating reports from produced data..."
	# Run lightweight report generation functions that use produced outputs
	@. .venv/bin/activate && python -c 'from run_lab_analysis import generate_lab_report_data, generate_insights_and_analysis; generate_lab_report_data(); generate_insights_and_analysis(); print("Reports generation completed")'
	@echo "Logs are available in logs/; collection summary at data/raw/collection_summary.json (if produced)"

# Development helpers
lint:
	. .venv/bin/activate && python -m flake8 src/ --max-line-length=100

format:
	. .venv/bin/activate && python -m black src/

check:
	. .venv/bin/activate && python -c "from src.utils.env import load; print('Config OK:', bool(load()))"