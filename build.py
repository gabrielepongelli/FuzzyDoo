from __future__ import annotations

import os
import subprocess
import glob
import re
from pathlib import Path
from typing import Any


def matcher(match: re.Match) -> str:
    res = f"from . import {match.group(1)}"
    if match.group(2):
        res += f" as {match.group(2)}"
    return res


def build(setup_kwargs: dict[str, Any]):

    # directory where .proto files are located
    PROTO_DIR = Path(__file__).parent / \
        setup_kwargs["name"] / "agents" / "grpc_agent"

    # all the proto files
    PROTO_FILES = glob.glob(os.path.join(PROTO_DIR, "*.proto"))

    # directory where the generated files will go
    GENERATED_DIR = Path(
        __file__).parent / setup_kwargs["name"] / "agents" / "grpc_agent" / "generated"

    os.makedirs(GENERATED_DIR, exist_ok=True)

    # create __init__.py to make it a package
    init_file_path = Path(GENERATED_DIR) / '__init__.py'
    init_file_path.touch()

    # run the grpc_tools.protoc command
    grpc_command = [
        "python", "-m", "grpc_tools.protoc",
        f"-I={PROTO_DIR}",
        f"--python_out={GENERATED_DIR}",
        f"--grpc_python_out={GENERATED_DIR}"
    ] + PROTO_FILES
    subprocess.run(grpc_command, check=True)

    pattern = re.compile(r'^import ([^_\n]*_pb2)(?: as (.*))?', re.MULTILINE)

    # replace imports in the generated files
    for py_file in glob.glob(os.path.join(GENERATED_DIR, "*.py")):
        with open(py_file, 'r', encoding='utf-8') as file:
            content = file.read()

        new_content = pattern.sub(matcher, content)
        if new_content != content:
            with open(py_file, 'w', encoding='utf-8') as file:
                file.write(new_content)

    # add the generated package to the packages to include in the build
    setup_kwargs['packages'].append('fuzzydoo.agents.grpc_agent.generated')
