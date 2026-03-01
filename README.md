# blerpc-protocol

BLE RPC protocol library for Python and C.

Part of the [bleRPC](https://blerpc.net) project.

## Overview

Python and C implementation of the bleRPC binary protocol:

- Container fragmentation and reassembly with MTU-aware splitting
- Command packet encoding/decoding with protobuf payload support
- Control messages (timeout, stream end, capabilities, error)
- **Encryption layer** — E2E encryption with X25519 key exchange, Ed25519 signatures, and AES-128-GCM

The Python and C implementations are fully compatible and share the same wire format.

## Installation

```
pip install blerpc-protocol
```

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

## Encryption

The library provides E2E encryption using a 4-step key exchange protocol (X25519 ECDH + Ed25519 signatures) and AES-128-GCM session encryption.

```python
from blerpc_protocol.crypto import central_perform_key_exchange, BlerpcCryptoSession

# Perform key exchange (central side)
session = await central_perform_key_exchange(send=ble_send, receive=ble_receive)

# Encrypt outgoing commands
ciphertext = session.encrypt(plaintext)

# Decrypt incoming commands
plaintext = session.decrypt(ciphertext)
```

## C Library

The C implementation is a Zephyr module with zero external dependencies. Add it to your `west.yml` manifest:

```yaml
- name: blerpc-protocol
  url: https://github.com/tdaira/blerpc-protocol
  revision: main
  path: modules/lib/blerpc-protocol
```

Headers are in `c/include/blerpc_protocol/`. See [container.h](c/include/blerpc_protocol/container.h), [command.h](c/include/blerpc_protocol/command.h), and [crypto.h](c/include/blerpc_protocol/crypto.h) for the API.

## Requirements

- Python 3.11+

## License

[LGPL-3.0](LICENSE) with [Static Linking Exception](LICENSING_EXCEPTION)
