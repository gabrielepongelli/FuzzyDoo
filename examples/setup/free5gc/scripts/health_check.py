#!/usr/bin/env python3

import argparse
import subprocess
import logging
import sys
from pathlib import Path

import yaml


def is_healthy(container: str, keyword: str) -> bool:
    try:
        result = subprocess.run(
            ["docker", "logs", container],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=True
        )

        return keyword in result.stdout
    except Exception as e:
        logging.exception(e)
        return None


def main():
    logging.basicConfig(level=logging.DEBUG, format="[%(levelname)s] - %(message)s")

    parser = argparse.ArgumentParser(description='Script to check the healthness of free5gc 5G Core Network.')
    parser.add_argument('compose-file', type=Path, help='The path to the docker compose file to check.')

    args = parser.parse_args()
    compose_file = getattr(args, 'compose-file')

    with open(compose_file, "r", encoding='utf8') as f:
        compose = yaml.safe_load(f)

    containers = set(service['container_name'] for service in compose['services'].values())
    containers -= {'mongodb', 'n3iwf', 'tngf', 'webui', 'n3iwue'}
    logging.info('Checking healthness of %s', ', '.join(containers))

    keywords = {
        'upf': "New node",
        'nrf': "SBI server started",
        "amf": "Start SBI server",
        "ausf": "Start SBI server",
        "nssf": "Starting server",
        "pcf": "Start SBI server",
        "smf": "Start SBI server",
        "udm": "Start SBI server",
        "udr": "Starting server",
        "chf": "Start SBI server",
        "nef": "Start SBI server",
    }

    try:
        while containers:
            to_remove = set()
            for c in containers:
                if is_healthy(c, keywords[c]):
                    logging.info('%s is healthy', c)
                    to_remove.add(c)
            containers -= to_remove
    except Exception as e:
        logging.exception('%s', e)
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
