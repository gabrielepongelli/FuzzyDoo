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


def login(s: requests.Session, base_url: str, user: str, pwd: str) -> str | None:
    res = s.post(
        base_url + '/api/login',
        json={
            'username': user,
            'password': pwd
        }
    )

    if res.status_code != 200:
        return None

    try:
        data = res.json()
        return data.get('access_token', None)
    except requests.exceptions.JSONDecodeError:
        return None


def subscribe(s: requests.Session, base_url: str, sim: dict, access_token: str) -> bool:
    imsi = sim['supi'] if sim['supi'].startswith('imsi-') else f"imsi-{sim['supi']}"
    data = {
        "userNumber": 1,
        "ueId": imsi,
        "plmnID": sim['plmn'],
        "AuthenticationSubscription": {
            "authenticationMethod": "5G_AKA",
            "permanentKey": {
                "permanentKeyValue": sim['key'],
                "encryptionKey": 0,
                "encryptionAlgorithm": 0
            },
            "sequenceNumber": "000000000023",
            "authenticationManagementField": sim['amf'],
            "milenage": {
                "op": {
                    "opValue": sim['op'] if sim['op_type'] == "OP" else "",
                    "encryptionKey": 0,
                    "encryptionAlgorithm": 0
                }
            },
            "opc": {
                "opcValue": sim['op'] if sim['op_type'] == "OPc" else "",
                "encryptionKey": 0,
                "encryptionAlgorithm": 0
            }
        },
        "AccessAndMobilitySubscriptionData": {
            "gpsis": ["msisdn-"],
            "subscribedUeAmbr": {"uplink": "1 Gbps", "downlink": "2 Gbps"},
            "nssai": {
                "defaultSingleNssais": [{"sst": 1, "sd": "010203"}],
                "singleNssais": [{"sst": 1, "sd": "112233"}]
            }
        },
        "SessionManagementSubscriptionData": [
            {
                "singleNssai": {"sst": 1, "sd": "010203"},
                "dnnConfigurations": {
                    "internet": {
                        "pduSessionTypes": {
                            "defaultSessionType": "IPV4",
                            "allowedSessionTypes": ["IPV4"]
                        },
                        "sscModes": {
                            "defaultSscMode": "SSC_MODE_1",
                            "allowedSscModes": ["SSC_MODE_2", "SSC_MODE_3"]
                        },
                        "5gQosProfile": {
                            "5qi": 9,
                            "arp": {"priorityLevel": 8, "preemptCap": "", "preemptVuln": ""},
                            "priorityLevel": 8
                        },
                        "sessionAmbr": {"uplink": "1000 Mbps", "downlink": "1000 Mbps"},
                        "staticIpAddress": []
                    }
                }
            },
            {
                "singleNssai": {"sst": 1, "sd": "112233"},
                "dnnConfigurations": {
                    "internet": {
                        "pduSessionTypes": {
                            "defaultSessionType": "IPV4",
                            "allowedSessionTypes": ["IPV4"]
                        },
                        "sscModes": {
                            "defaultSscMode": "SSC_MODE_1",
                            "allowedSscModes": ["SSC_MODE_2", "SSC_MODE_3"]
                        },
                        "5gQosProfile": {
                            "5qi": 8,
                            "arp": {"priorityLevel": 8, "preemptCap": "", "preemptVuln": ""},
                            "priorityLevel": 8
                        },
                        "sessionAmbr": {"uplink": "1000 Mbps", "downlink": "1000 Mbps"},
                        "staticIpAddress": []
                    }
                }
            }
        ],
        "SmfSelectionSubscriptionData": {
            "subscribedSnssaiInfos": {
                "01010203": {"dnnInfos": [{"dnn": "internet"}]},
                "01112233": {"dnnInfos": [{"dnn": "internet"}]}
            }
        },
        "AmPolicyData": {"subscCats": ["free5gc"]},
        "SmPolicyData": {
            "smPolicySnssaiData": {
                "01010203": {
                    "snssai": {"sst": 1, "sd": "010203"},
                    "smPolicyDnnData": {"internet": {"dnn": "internet"}}
                },
                "01112233": {
                    "snssai": {"sst": 1, "sd": "112233"},
                    "smPolicyDnnData": {"internet": {"dnn": "internet"}}
                }
            }
        },
        "FlowRules": [
            {
                "filter": "1.1.1.1/32",
                "precedence": 128,
                "snssai": "01010203",
                "dnn": "internet",
                "qosRef": 1
            },
            {
                "filter": "1.1.1.1/32",
                "precedence": 127,
                "snssai": "01112233",
                "dnn": "internet",
                "qosRef": 2
            }
        ],
        "QosFlows": [
            {
                "snssai": "01010203",
                "dnn": "internet",
                "qosRef": 1,
                "5qi": 8,
                "mbrUL": "208 Mbps",
                "mbrDL": "208 Mbps",
                "gbrUL": "108 Mbps",
                "gbrDL": "108 Mbps"
            },
            {
                "snssai": "01112233",
                "dnn": "internet",
                "qosRef": 2,
                "5qi": 7,
                "mbrUL": "407 Mbps",
                "mbrDL": "407 Mbps",
                "gbrUL": "207 Mbps",
                "gbrDL": "207 Mbps"
            }
        ],
        "ChargingDatas": [
            {
                "chargingMethod": "Offline",
                "quota": "100000",
                "unitCost": "1",
                "snssai": "01010203",
                "dnn": "",
                "filter": ""
            },
            {
                "chargingMethod": "Offline",
                "quota": "100000",
                "unitCost": "1",
                "snssai": "01010203",
                "dnn": "internet",
                "filter": "1.1.1.1/32",
                "qosRef": 1
            },
            {
                "chargingMethod": "Online",
                "quota": "100000",
                "unitCost": "1",
                "snssai": "01112233",
                "dnn": "",
                "filter": ""
            },
            {
                "chargingMethod": "Online",
                "quota": "5000",
                "unitCost": "1",
                "snssai": "01112233",
                "dnn": "internet",
                "filter": "1.1.1.1/32",
                "qosRef": 2
            }
        ]
    }

    res = s.post(
        base_url + f'/api/subscriber/{imsi}/{sim['plmn']}',
        headers={'Token': access_token},
        json=data
    )

    return res.status_code == 201


def main():
    logging.basicConfig(level=logging.DEBUG, format="[%(levelname)s] - %(message)s")

    parser = argparse.ArgumentParser(description='Script to subscribe a new SIM record into free5gc Core Network.')
    parser.add_argument('host', type=str, help='Host address:port where the web interface is listening')
    parser.add_argument('user', type=str, help='Username to use for authentication')
    parser.add_argument('pwd', type=str, help='Password to use for authentication')
    parser.add_argument('supi', type=str, help='SUPI code of the UE')
    parser.add_argument('key', type=str, help='Permanent subscription key of the UE')
    parser.add_argument('op-type', type=str, choices=['OP', 'OPc'], help='Operator code type ("OP" or "OPc")')
    parser.add_argument('op', type=str, help='Operator code (OP or OPC) of the UE')
    parser.add_argument('--amf', type=int,
                        help='Authentication Management Field (AMF) value. Defaults to 8000.', default=8000)
    parser.add_argument('--plmn', type=int,
                        help='Public Land Mobile Network (PLMN) value. Defaults to 20893.', default=20893)

    args = parser.parse_args()
    base_url = f"http://{args.host}"
    sim = {
        "supi": args.supi,
        "key": args.key,
        "op_type": getattr(args, 'op-type'),
        "op": args.op,
        "amf": str(args.amf),
        "plmn": str(args.plmn)
    }

    logging.info('Waiting for the website to go online...')
    while not is_on(base_url):
        time.sleep(1)
    logging.info('Website online')

    s = requests.Session()
    access_token = login(s, base_url, args.user, args.pwd)
    if not access_token:
        logging.error('An error occurred while logging in')
        sys.exit(1)

    if not subscribe(s, base_url, sim, access_token):
        logging.error('An error occurred while subscribing a new SIM record')
        sys.exit(1)

    logging.info('Successfully subscribed a new SIM record')


if __name__ == "__main__":
    main()
