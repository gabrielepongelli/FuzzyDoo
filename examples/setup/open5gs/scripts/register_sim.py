#!/usr/bin/env python3

import logging
import sys
import time
import argparse
import requests


def is_on(base_url: str) -> bool:
    try:
        requests.get(base_url + '/')
    except requests.exceptions.RequestException:
        return False

    return True


def get_session_cookie(s: requests.Session, base_url: str) -> bool:
    res = s.get(base_url + '/_next/1742555032713/page/')
    if res.status_code != 200:
        return False

    return 'connect.sid' in res.cookies


def get_csrf_token(s: requests.Session, base_url: str) -> str | None:
    res = s.get(base_url + '/api/auth/csrf', headers={'X-CSRF-TOKEN': 'undefined'})
    if res.status_code != 200:
        return None

    try:
        data = res.json()
        return data.get('csrfToken', None)
    except requests.exceptions.JSONDecodeError:
        return None


def login(s: requests.Session, base_url: str, user: str, pwd: str, csrf: str) -> bool:
    res = s.post(
        base_url + '/api/auth/login',
        headers={
            'X-CSRF-TOKEN': csrf
        },
        json={
            'username': user,
            'password': pwd
        }
    )

    return res.status_code == 200


def get_session_data(s: requests.Session, base_url: str) -> dict | None:
    res = s.get(base_url + '/api/auth/session', headers={'X-CSRF-TOKEN': 'undefined'})
    if res.status_code != 200:
        return None

    try:
        return res.json()
    except requests.exceptions.JSONDecodeError:
        return None


def subscribe(s: requests.Session, base_url: str, sim: dict, session_data: dict) -> bool:
    data = {
        "imsi": sim['supi'],
        "security": {
            "k": sim['key'],
            "amf": sim['amf'],
            "op_type": 1 if sim['op_type'] == "OP" else 0,
            "op_value": sim['op'],
            "op": sim['op'] if sim['op_type'] == "OP" else None,
            "opc": sim['op'] if sim['op_type'] == "OPc" else None
        },
        "ambr": {
            "downlink": {"value": 1, "unit": 3},
            "uplink": {"value": 1, "unit": 3}
        },
        "subscriber_status": 0,
        "operator_determined_barring": 0,
        "slice": [
            {
                "sst": 1,
                "default_indicator": True,
                "session": [
                    {
                        "name": "internet",
                        "type": 3,
                        "ambr": {
                            "downlink": {"value": 1, "unit": 3},
                            "uplink": {"value": 1, "unit": 3}
                        },
                        "qos": {
                            "index": 9,
                            "arp": {
                                "priority_level": 8,
                                "pre_emption_capability": 1,
                                "pre_emption_vulnerability": 1
                            }
                        }
                    }
                ]
            }
        ]
    }

    res = s.post(
        base_url + '/api/db/Subscriber',
        headers={
            'X-CSRF-TOKEN': session_data['csrfToken'],
            'Authorization': f'Bearer {session_data["authToken"]}'
        },
        json=data
    )

    return res.status_code == 201


def main():
    logging.basicConfig(level=logging.DEBUG, format="[%(levelname)s] - %(message)s")

    parser = argparse.ArgumentParser(description='Script to subscribe a new SIM record into open5gs Core Network.')
    parser.add_argument('host', type=str, help='Host address:port where the web interface is listening')
    parser.add_argument('user', type=str, help='Username to use for authentication')
    parser.add_argument('pwd', type=str, help='Password to use for authentication')
    parser.add_argument('supi', type=str, help='SUPI code of the UE')
    parser.add_argument('key', type=str, help='Permanent subscription key of the UE')
    parser.add_argument('op-type', type=str, choices=['OP', 'OPc'], help='Operator code type ("OP" or "OPc")')
    parser.add_argument('op', type=str, help='Operator code (OP or OPC) of the UE')
    parser.add_argument('--amf', type=int,
                        help='Authentication Management Field (AMF) value. Defaults to 8000.', default=8000)

    args = parser.parse_args()
    base_url = f"http://{args.host}"
    sim = {
        "supi": args.supi,
        "key": args.key,
        "op_type": getattr(args, 'op-type'),
        "op": args.op,
        "amf": str(args.amf)
    }

    s = requests.Session()
    logging.info('Waiting for the website to go online...')
    while not is_on(base_url):
        time.sleep(1)
    logging.info('Website online')

    if not get_session_cookie(s, base_url):
        logging.error('An error occurred while getting the session cookies')
        sys.exit(1)

    csrf_token = get_csrf_token(s, base_url)
    if not csrf_token:
        logging.error('An error occurred while acquiring the CSRF token')
        sys.exit(1)

    if not login(s, base_url, args.user, args.pwd, csrf_token):
        logging.error('An error occurred while logging in')
        sys.exit(1)

    session_data = get_session_data(s, base_url)
    if not session_data:
        logging.error('An error occurred while obtaining the authentication token')
        sys.exit(1)

    if not subscribe(s, base_url, sim, session_data):
        logging.error('An error occurred while subscribing a new SIM record')
        sys.exit(1)

    logging.info('Successfully subscribed a new SIM record')


if __name__ == "__main__":
    main()
