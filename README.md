# blerpc-protocol

Container and command protocol layers for bleRPC — available as both a Python package and a C library.

Part of the [bleRPC](https://blerpc.net) project.

## Overview

This library implements the binary protocol used by bleRPC:

- **Container layer** — MTU-aware fragmentation and reassembly of payloads, control messages (timeout, stream end, capabilities, error)
- **Command layer** — request/response encoding with command name routing and protobuf data

The Python and C implementations are fully compatible and share the same wire format.

## Installation

```
pip install blerpc-protocol
```

Requires Python 3.11+.

## Usage

```python
from blerpc_protocol import ContainerSplitter, ContainerAssembler, CommandPacket, CommandType

# Encode a command
packet = CommandPacket(CommandType.REQUEST, "Echo", protobuf_bytes)
payload = packet.serialize()

# Split into BLE-sized containers
splitter = ContainerSplitter(mtu=247)
containers = splitter.split(payload)

# Send containers over BLE, then reassemble on the other side
assembler = ContainerAssembler()
for container in received_containers:
    result = assembler.feed(container)
    if result is not None:
        response = CommandPacket.deserialize(result)
```

## C Library

The C implementation is a Zephyr module with zero external dependencies. Add it to your `west.yml` manifest:

```yaml
- name: blerpc-protocol
  url: https://github.com/tdaira/blerpc-protocol
  revision: main
  path: modules/lib/blerpc-protocol
```

Headers are in `c/include/blerpc_protocol/`. See [container.h](c/include/blerpc_protocol/container.h) and [command.h](c/include/blerpc_protocol/command.h) for the API.

## License

[LGPL-3.0](LICENSE) with [Static Linking Exception](LICENSING_EXCEPTION)
