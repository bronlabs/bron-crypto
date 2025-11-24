# Serde

Serialization and deserialization utilities using CBOR (Concise Binary Object Representation) format.

## Features

- **CBOR Encoding/Decoding** - Generic functions for marshaling and unmarshaling data
- **Type Registration** - Register types with CBOR tags for deterministic serialization
- **Tagged Serialization** - Serialize values with explicit CBOR tags
- **Strict Validation** - Enforces strict decoding rules (no duplicate keys, required tags, etc.)

Built on [fxamacker/cbor](https://github.com/fxamacker/cbor) with deterministic encoding for cryptographic applications.
