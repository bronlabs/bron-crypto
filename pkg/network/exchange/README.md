# Exchange Helpers

Convenience functions that orchestrate broadcast and unicast communication patterns over a `network.Router` 
using correlation IDs and CBOR encoding.

## Notes

- Correlation IDs are namespaced with `:BROADCAST` and `:UNICAST` internally to avoid collisions.
- Messages are strongly typed by callers and serialized/deserialized via CBOR.
- Underlying routing and quorum information come from the provided `Router`.
