package signing

import (
	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	trsa "github.com/bronlabs/bron-crypto/pkg/threshold/trsa"
	trsa_signatures "github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/trsa"
)

func (c *Cosigner) ProducePSSPartialSignature(message, salt []byte) (*trsa_signatures.PartialSignature, error) {
	digest, err := hashing.Hash(c.H.New, message)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot hash message")
	}
	mBytes, err := trsa.EmsaPSSEncode(digest, c.MyShard.PublicKey().N.BitLen()-1, salt, c.H.New())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot encode message")
	}
	m := new(saferith.Nat).SetBytes(mBytes)
	s1 := c.MyShard.D1Share.InExponent(m, c.MyShard.N1)
	s2 := c.MyShard.D2Share.InExponent(m, c.MyShard.N2)

	return &trsa_signatures.PartialSignature{
		S1Share: s1,
		S2Share: s2,
	}, nil
}

func (c *Cosigner) ProducePKCS1v15PartialSignature(message []byte) (*trsa_signatures.PartialSignature, error) {
	digest, err := hashing.Hash(c.H.New, message)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot hash message")
	}
	mBytes, err := trsa.Pkcs1v15ConstructEM(c.MyShard.PublicKey(), c.H.String(), digest)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot encode message")
	}
	m := new(saferith.Nat).SetBytes(mBytes)
	s1 := c.MyShard.D1Share.InExponent(m, c.MyShard.N1)
	s2 := c.MyShard.D2Share.InExponent(m, c.MyShard.N2)

	return &trsa_signatures.PartialSignature{
		S1Share: s1,
		S2Share: s2,
	}, nil
}
