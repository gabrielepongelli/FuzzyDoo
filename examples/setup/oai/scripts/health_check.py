#!/usr/bin/env python3

import logging
import argparse
import subprocess
from pathlib import Path
import sys

import yaml


def is_healthy(container: str) -> bool:
    result = subprocess.run(
        ["docker", "inspect", "--format", "{{.State.Health.Status}}", container],
        capture_output=True, text=True, check=True
    )

    return result.stdout.strip() == 'healthy'


def main():
    logging.basicConfig(level=logging.DEBUG, format="[%(levelname)s] - %(message)s")

    parser = argparse.ArgumentParser(description='Script to check the healthness of OAI 5G Core Network.')
    parser.add_argument('compose-file', type=Path, help='The path to the docker compose file to check.')

    args = parser.parse_args()
    compose_file = getattr(args, 'compose-file')

    with open(compose_file, "r", encoding='utf8') as f:
        compose = yaml.safe_load(f)

    containers = set(service['container_name'] for service in compose['services'].values())
    logging.info('Checking healthness of %s', ', '.join(containers))

    try:
        while containers:
            to_remove = set()
            for c in containers:
                if is_healthy(c):
                    logging.info('%s is healthy', c)
                    to_remove.add(c)
            containers -= to_remove
    except Exception as e:
        logging.exception('%s', e)
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
