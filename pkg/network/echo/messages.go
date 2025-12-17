package echo

import "github.com/bronlabs/bron-crypto/pkg/threshold/sharing"

// Round1P2P carries the original broadcast payload.
type Round1P2P struct {
	Payload []byte `cbor:"payload"`
}

// Round2P2P carries echoed payloads from each sender.
type Round2P2P struct {
	Echo map[sharing.ID][]byte `cbor:"echo"`
}
