package commitments

import (
	crand "crypto/rand"
	"crypto/subtle"
	"hash"

	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/hashing"
)

type (
	Commitment []byte
	Witness    []byte
)

func Commit(h func() hash.Hash, message []byte) (Commitment, Witness, error) {
	hasher := h()
	lambda := hasher.Size()

	witness := make([]byte, lambda)

	n, err := crand.Read(witness)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "reading random bytes")
	}
	if n != lambda {
		return nil, nil, errs.NewFailed("random reader did not return enough bytes. returned %d bytes whereas we need %d bytes", n, lambda)
	}

	commitment, err := hashing.Hash(h, message, witness)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "computing commitment hash")
	}
	return commitment, witness, nil
}

func Open(h func() hash.Hash, message []byte, commitment Commitment, witness Witness) error {
	hasher := h()
	lambda := hasher.Size()
	if lambda != len(commitment) {
		return errs.NewInvalidArgument("size of commitment is wrong given hash function. Need %d whereas we have %d", lambda, len(commitment))
	}
	if lambda != len(witness) {
		return errs.NewInvalidArgument("size of witness is wrong given hash function. Need %d whereas we have %d", lambda, len(witness))
	}
	recomputedCommitment, err := hashing.Hash(h, message, witness)
	if err != nil {
		return errs.WrapFailed(err, "recomputing commitment hash")
	}
	if subtle.ConstantTimeCompare(commitment, recomputedCommitment) != 1 {
		return errs.NewVerificationFailed("commitment is invalid")
	}
	return nil
}
