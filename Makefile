PROJECT_NAME := fuzzydoo
DOCS_DIR := $(abspath ./docs)
DOCS_SRC_DIR := $(DOCS_DIR)/template
DOCS_PUB_DIR := $(DOCS_DIR)/public
PROJECT_FILES := $(shell find $(PROJECT_NAME) -name "*.py" -o -name "*.proto")

.PHONY: all build clean docs dev-install install install-no-agents help

# installs dependencies and generates gRPC files
all: install

dist/*.whl: $(PROJECT_FILES)
	poetry build -q

# build the package
build: dist/*.whl

# clean files and directories generated from the build process
clean:
	rm -rf ./build ./dist ./$(PROJECT_NAME)/agents/grpc_agent/generated
	rm -f ./setup.py

# generate the documentation
docs: build
	poetry install --no-root --all-extras -q
	rm -rf $(DOCS_PUB_DIR)
	pdoc -d google $(PROJECT_NAME) -t $(DOCS_SRC_DIR) -o $(DOCS_PUB_DIR) --logo ./logo.svg

# install the package in dev mode
dev-install:
	poetry install --all-extras -q

# install the package
install: build
	for number in ./dist/*.whl; do \
		pip install "$${number}[network-sniffer,network-proxy,network-function-proxy]" ; \
	done

# install the package without agents dependencies
install-no-agents: build
	for number in ./dist/*.whl; do \
		pip install "$${number}" ; \
	done

# help command to list available commands
help:
	@echo "Available make commands:"
	@echo "  make                     - Install build dependencies and build the package"
	@echo "  make build               - Build the package"
	@echo "  make dev-install         - Install the package in the current python environment in development mode"
	@echo "  make install             - Install the package in the current python environment"
	@echo "  make install-no-agents   - Install the package in the current python environment without additional dependencies for the agents"
	@echo "  make clean               - Clean files and directories generated from the build process"
	@echo "  make docs                - Generate the documentation"

