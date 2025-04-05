# Open5gs Setup

This setup was used to test **Open5gs v2.7.2-131-g04ec945** taken from [here](https://github.com/free5gc/free5gc-compose), with additional modifications applied using the `changes.patch` file.

## Directory Structure

```text
free5gc/
 |-- README.md # This documentation file
 |-- config.yaml # Configuration for the fuzzer and agents
 |-- changes.patch # Patch applied to modify the core network setup
 |-- scripts/ # Custom scripts used in this setup
 | |-- register_sim.py
 |-- UERANSIM/ # Configuration files for UERANSIM
 | |-- gnb.yaml
 | |-- gnb_w_proxy.yaml
 | |-- ue.yaml
```

Follow the instructions provided in this document and in `config.yaml` to correctly set up and run the tests.

## Custom Scripts

A single custom script is provided:

- `register_sim.py` registers a new SIM record inside the Core Network.

For instructions on how to use this script run `./register_sim.py --help`.

## Agents Setup

The agents are configured as specified in `config.yaml`, with the following setup:

### **VM 1 (Core Network)**

- The `NetworkFunctionProxy` agent listening on `192.168.56.101:9000`.
- The `ComposeRestart` agent listening on `192.168.56.101:9001`.
- The `ContainerMonitor` agent listening on `192.168.56.101:9002`.
- The `CommandExec` agent listening on `192.168.56.101:9004`.

### **VM 2 (Fuzzer & UERANSIM)**

- The `NetworkSniffer` agent listening on `127.0.0.1:9003`.
- The `NetworkProxy` agent listening on `127.0.0.1:9005`.
- The `UERANSIMController` agent listening on `127.0.0.1:9006`.
