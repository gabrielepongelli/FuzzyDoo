# Free5gc Setup

This setup was used to test **Free5gc 4.0.0** taken from [here](https://github.com/free5gc/free5gc-compose), with additional modifications applied using the `changes.patch` file.

## Directory Structure

```text
free5gc/
 |-- README.md # This documentation file
 |-- config.yaml # Configuration for the fuzzer and agents
 |-- changes.patch # Patch applied to modify the core network setup
 |-- scripts/ # Custom scripts used in this setup
 | |-- health_check.py
 | |-- register_sim.py
 |-- UERANSIM/ # Configuration files for UERANSIM
 | |-- gnb.yaml
 | |-- gnb_w_proxy.yaml
 | |-- ue.yaml
```

Follow the instructions provided in this document and in `config.yaml` to correctly set up and run the tests.

## Additional Requirements

For the **VM 1** (Core Network), the following additional requirement is needed for Free5GC:

- `gtp5g` kernel module version 0.9.13 (see [here](https://github.com/free5gc/gtp5g)).

## Custom Scripts

Two custom scripts are provided:

- `health_check.py` checks that the containers of the deployment are ready to interact with gNBs and UEs.
- `register_sim.py` registers a new SIM record inside the Core Network.

For instructions on how to use these scripts run `./health_check.py --help` and `./register_sim.py --help`.

## Agents Setup

The agents are configured as specified in `config.yaml`, with the following setup:

### **VM 1 (Core Network)**

- The `NetworkFunctionProxy` agent listening on `192.168.56.101:9000`.
- The `ComposeRestart` agent listening on `192.168.56.101:9001`.
- The `ContainerMonitor` agent listening on `192.168.56.101:9002`.
- Two instances of the `CommandExec` agent listening on `192.168.56.101:9004` and `192.168.56.101:9005`.

### **VM 2 (Fuzzer & UERANSIM)**

- The `NetworkSniffer` agent listening on `127.0.0.1:9003`.
- The `NetworkProxy` agent listening on `127.0.0.1:9006`.
- The `UERANSIMController` agent listening on `127.0.0.1:9007`.
