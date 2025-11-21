package echo

import "github.com/bronlabs/bron-crypto/pkg/threshold/sharing"

type Round1P2P struct {
	Payload []byte `cbor:"payload"`
}

type Round2P2P struct {
	Echo map[sharing.ID][]byte `cbor:"echo"`
}
