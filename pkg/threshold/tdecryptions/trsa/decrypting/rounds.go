package decrypting

import (
	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/threshold/tdecryptions/trsa"
)

func (c *Codecryptor) ProducePartialDecryption(ciphertext []byte) *trsa.PartialDecryption {
	ciphertextNat := new(saferith.Nat).SetBytes(ciphertext)
	p1 := c.Cosigner.MyShard.D1Share.InExponent(ciphertextNat, c.Cosigner.MyShard.N1)
	p2 := c.Cosigner.MyShard.D2Share.InExponent(ciphertextNat, c.Cosigner.MyShard.N2)

	return &trsa.PartialDecryption{
		P1Share: p1,
		P2Share: p2,
	}
}
