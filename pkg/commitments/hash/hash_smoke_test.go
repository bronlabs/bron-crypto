//nolint:testpackage // Preventing the app from running if HmacFunc doesn't match collision resistance.
package hash_comm

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
)

func init() {
	h, _ := HmacFunc(nil)
	if DigestSize != h.Size() {
		panic("DigestSize must match the output size of the hash function")
	}
	digestBits := h.Size() * 8 // 256
	if digestBits < base.CollisionResistance {
		panic("DigestSize must be at least CollisionResistance bits to achieve the desired security level")
	}
}

var (
	_ commitments.Message                = Message{}
	_ commitments.Witness                = Witness{}
	_ commitments.Commitment[Commitment] = Commitment{}

	_ commitments.CommitmentKey[*CommitmentKey, Message, Witness, Commitment] = (*CommitmentKey)(nil)
)
