PROJECT_NAME := fuzzydoo
DOCS_DIR := $(abspath ./docs)

# installs dependencies and generates gRPC files
all: install-deps build

.PHONY: all build clean docs dev-install help

# install python dependencies using Poetry
install-deps:
	poetry install --only build --no-root -q

# build the package
build: install-deps
	poetry build -q

# clean files and directories generated from the build process
clean:
	rm -rf ./build ./dist ./$(PROJECT_NAME)/agents/grpc_agent/generated
	rm -f ./setup.py

# generate the documentation
docs: build
	poetry install --with docs --no-root -q
	pdoc -d google $(PROJECT_NAME) -o $(DOCS_DIR)

# install the package
dev-install:
	poetry install --with build -q

# help command to list available commands
help:
	@echo "Available make commands:"
	@echo "  make               - Install build dependencies and build the package"
	@echo "  make build         - Build the package"
	@echo "  make dev-install   - Install the package in the current python environment in development mode"
	@echo "  make clean         - Clean files and directories generated from the build process"
	@echo "  make docs          - Generate the documentation"

