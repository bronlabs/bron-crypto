package signing

import (
	"hash"
	"io"
	"slices"

	"github.com/cronokirby/saferith"
	"golang.org/x/crypto/blake2b"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/trsa"
)

func SignPSS(shard *trsa.Shard, message []byte, hashFunc func() hash.Hash, saltLength uint32) (*trsa.PartialSignature, error) {
	xof, err := blake2b.NewXOF(saltLength, shard.PaddingKey[:])
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create XOF")
	}
	_, err = xof.Write(slices.Concat(message, shard.N1.Bytes(), shard.N2.Bytes()))
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot write to XOF")
	}
	salt := make([]byte, saltLength)
	_, err = io.ReadFull(xof, salt)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot read salt")
	}

	digest, err := hashing.Hash(hashFunc, message)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot hash message")
	}
	mBytes, err := trsa.EmsaPSSEncode(digest, shard.PublicKey().N.BitLen()-1, salt, hashFunc())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot encode message")
	}
	m := new(saferith.Nat).SetBytes(mBytes)
	s1 := shard.D1Share.InExponent(m, shard.N1)
	s2 := shard.D2Share.InExponent(m, shard.N2)

	return &trsa.PartialSignature{
		S1Share: s1,
		S2Share: s2,
	}, nil
}
