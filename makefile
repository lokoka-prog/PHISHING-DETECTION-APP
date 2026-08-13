# Variables
PYTHON = python
DOCKER_COMPOSE = docker-compose
APP_NAME = phishing-detector

.PHONY: help test run-local build up down logs clean

# Default command when running 'make'
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  test        Run unit and integration tests using pytest"
	@echo "  run-local   Launch Streamlit app locally"
	@echo "  build       Build Docker image"
	@echo "  up          Start container via docker-compose"
	@echo "  down        Stop container and remove resources"
	@echo "  logs        View container logs in real time"
	@echo "  clean       Remove temporary cache and database test files"

# Run pytest test suite
test:
	$(PYTHON) -m pytest test_app.py -v

# Run app locally via Streamlit
run-local:
	streamlit run app.py

# Build Docker image
build:
	$(DOCKER_COMPOSE) build

# Spin up application in detached mode
up:
	$(DOCKER_COMPOSE) up -d

# Stop and remove containers
down:
	$(DOCKER_COMPOSE) down

# Tail container logs
logs:
	$(DOCKER_COMPOSE) logs -f

# Clean Python bytecode cache and test artifacts
clean:
	rm -rf .pytest_cache __pycache__
	find . -type d -name "__pycache__" -exec rm -rf {} +