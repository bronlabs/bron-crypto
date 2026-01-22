package fischlin

import (
	"encoding/binary"

	"github.com/bronlabs/errs-go/pkg/errs"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

func hash(b uint64, commonH []byte, i uint64, challenge sigma.ChallengeBytes, serializedResponse []byte) ([]byte, error) {
	// if b is divisible by 8, it will have one extra byte, but this is not a problem since it will always be zero
	bBytes := b/8 + 1
	bMask := byte((1 << (b % 8)) - 1)
	h, err := hashing.Hash(randomOracle, commonH, binary.LittleEndian.AppendUint64(make([]byte, 8), i), challenge, serializedResponse)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot hash challenge")
	}
	h[bBytes-1] &= bMask
	return h[:bBytes], nil
}

func isAllZeros(data []byte) bool {
	zeros := byte(0)
	for _, b := range data {
		zeros |= b
	}
	return zeros == 0
}
