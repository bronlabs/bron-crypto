package dkg

import "github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"

type RoundPartialPublicKeyBroadcast struct {
	P *edwards25519.PrimeSubGroupPoint `cbor:"p"`
	N *edwards25519.PrimeSubGroupPoint `cbor:"n"`
}
