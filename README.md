<div style="text-align:center">
    <img alt="FuzzyDoo Logo" src="./logo.svg" width="50%" height="auto" />
</div>
<br><br>

# FuzzyDoo: Your Fuzzer for 5G Core Networks

![Python 3.13](https://img.shields.io/badge/python-3.13-blue.svg)
![GitHub License](https://img.shields.io/github/license/gabrielepongelli/FuzzyDoo)

## Overview

FuzzyDoo is a **Mutation-Based Structure-Aware Fuzzer** designed for testing the 5G core network's robustness and security. By leveraging mutation strategies and structure-awareness, it systematically generates inputs for various 5G core protocols (e.g., NGAP, NAS) to uncover vulnerabilities in protocol implementations.

Key features include:

- **Protocol-Specific Fuzzing**: Targets 5G-specific protocols like NGAP and NAS.
- **Agent-Based Architecture**: Utilizes agents for managing network sniffing, container monitoring, and protocol simulation.
- **Flexible Configuration**: Supports customizable test configurations via YAML files.
- **Widely Extensible**: Allows users to add new mutation strategies, integrate additional agents, or extend protocol support.

The choice of the name reflects the fuzzer’s purpose: to "unmask" hidden bugs and weaknesses, much like Scooby-Doo and the gang uncover hidden truths behind seemingly impenetrable mysteries.

---

## Dependencies

### General Requirements

- **Python**: Make sure Python 3.13 or later is installed.
- **Poetry**: Used for dependency management. Install it via:

    ```sh
    pip install poetry
    ```

### Additional Requirements

#### NetworkProxy Agent  

The `NetworkProxy` agent requires `libsctp-dev` and `python3-dev`. On Debian/Ubuntu they can be installed with:

```sh
sudo apt install libsctp-dev python3-dev
```

#### NetworkFunctionProxy Agent

The `NetworkFunctionProxy` agent requires the `br-netfilter` kernel module for network operations. To verify if it is already loaded run:

```sh
lsmod | grep br_netfilter
```

If no output appears, load it with:

```sh
sudo modprobe br-netfilter
```

#### UERANSIMController Agent

The `UERANSIMController` agent requires the UERANSIM simulator. Installation instructions can be found in the [UERANSIM GitHub Repository](https://github.com/aligungr/UERANSIM/wiki/Installation).

---

## Installation

> **Note**: It is recommended to run this project inside a Python virtual environment.

1. **Clone the Repository**:

    ```sh
    git clone https://github.com/gabrielepongelli/FuzzyDoo
    cd FuzzyDoo
    ```

2. **Build and Install**: Use the `Makefile` to build and install the project in the current python environment:

    ```sh
    make install
    ```

    This installs the package along with **all the agent dependencies**. If you only need the core functionality, use:

    ```sh
    make install-no-agents
    ```

    To see all available installation options, run:

    ```sh
    make help
    ```

---

## Usage

To start fuzzing with a given configuration file (`config.yaml`):

```sh
fuzzydoo fuzz config.yaml
```

If a vulnerability is detected for instance in run `1`, epoch `7`, test case `14` with an epoch seed of `0xaabbccddeeff0011`, you can replay the exact test case without rerunning the entire process:

```sh
fuzzydoo replay config.yaml 0xaabbccddeeff0011 1 --epoch 7 --test-case 14
```

For a complete list of commands and options, run:

```sh
fuzzydoo --help
```

## License

This project is licensed under the terms specified in the `LICENSE` file.

## Contributions

Contributions are welcome! Please open an issue or submit a pull request for any improvements or fixes.
