.PHONY: help install test validate clean

# Default target
help:
	@echo "AgentSecurity Development Makefile"
	@echo ""
	@echo "Usage:"
	@echo "  make install    Install the agentsec package in development mode"
	@echo "  make test       Run all unit tests"
	@echo "  make validate   Validate all AGENTSECURITY.md templates"
	@echo "  make clean      Remove build artifacts and Python cache files"
	@echo ""

install:
	python3 -m pip install -e "./packages/agentsec[dev]"

test:
	python3 -m pytest packages/agentsec/tests/ -v --tb=short

validate:
	@for dir in templates/*/; do \
		echo "Validating $$dir..."; \
		PYTHONPATH=packages/agentsec/src python3 -m agentsec.cli validate "$$dir/AGENTSECURITY.md"; \
	done

clean:
	rm -rf packages/agentsec/dist/
	rm -rf packages/agentsec/src/agentsec.egg-info/
	rm -rf packages/agentsec/.pytest_cache/
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
