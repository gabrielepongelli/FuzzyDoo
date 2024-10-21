PROJECT_NAME := fuzzydoo
PROTO_DIR := $(PROJECT_NAME)/agents/grpc_agent
GENERATED_DIR := $(PROJECT_NAME)/agents/grpc_agent/generated
PROTO_FILES := $(wildcard $(PROTO_DIR)/*.proto)

# installs dependencies and generates gRPC files
all: install-deps generate-grpc

.PHONY: all install-deps generate-grpc clean run help

# install python dependencies using Poetry
install-deps:
	poetry install

# generate gRPC files from .proto definitions
generate-grpc: $(PROTO_FILES)
	mkdir -p $(GENERATED_DIR)
	touch $(GENERATED_DIR)/__init__.py
	poetry run python -m grpc_tools.protoc \
		-I=$(PROTO_DIR) \
		--python_out=$(GENERATED_DIR) \
		--grpc_python_out=$(GENERATED_DIR) \
		$(PROTO_FILES)
	find $(GENERATED_DIR) -name '*.py' -exec sed -i \
		-e 's/^import \(.*_pb2\)/from . import \1/' {} \;

# clean generated gRPC python files
clean:
	rm -rf $(GENERATED_DIR)
	poetry uninstall

# run the application
run:
	poetry run python main.py

# generate the documentation
docs:
	poetry install --with docs
	pdoc -d google $(PROJECT_NAME)

# help command to list available commands
help:
	@echo "Available make commands:"
	@echo "  make all           - Install dependencies and generate gRPC files"
	@echo "  make install-deps  - Install dependencies using Poetry"
	@echo "  make generate-grpc - Generate gRPC files from .proto files"
	@echo "  make clean         - Clean generated gRPC files"
	@echo "  make run           - Run the application"
	@echo "  make docs          - Generate the documentation"

