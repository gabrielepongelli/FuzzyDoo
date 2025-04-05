# Examples Directory

This directory contains configuration examples for different 5G Core Network implementations tested within this project, along with additional scripts used during the tests.

## Common Setup

The testing setup for these examples requires 2 virtual machines:

### Core Network VM

- **Purpose:** Hosts the 5G Core Network under test.
- **Specifications:**
  - Ubuntu Server 20.04.6
  - IP address: `192.168.56.101`
  - Python 3.13
  - Docker 27.5.1 with `docker compose` command enabled
  - All required files to run the 5G Core Network via Docker
  - `fuzzydoo` with all the agent dependencies

### Fuzzer & Emulation VM

- **Purpose:** Hosts the fuzzer and UERANSIM tools (UE and gNB).
- **Specifications:**
  - Ubuntu Server 20.04.6
  - IP address: `192.168.56.102`
  - Python 3.13
  - UERANSIM 3.2.6
  - `fuzzydoo` with all the agent dependencies

Each example directory provides specific scripts, configuration files, and instructions tailored to the corresponding 5G Core Network. Refer to each subdirectory for details on setting up and running tests.
