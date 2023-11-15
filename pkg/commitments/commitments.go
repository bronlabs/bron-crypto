package commitments

import (
	crand "crypto/rand"
	"crypto/subtle"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
)

type (
	Commitment []byte
	Witness    []byte
)

func Commit(message []byte) (Commitment, Witness, error) {
	hasher := base.CommitmentHashFunction()
	lambda := hasher.Size()

	witness := make([]byte, lambda)

	n, err := crand.Read(witness)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "reading random bytes")
	}
	if n != lambda {
		return nil, nil, errs.NewFailed("random reader did not return enough bytes. returned %d bytes whereas we need %d bytes", n, lambda)
	}

	commitment, err := hashing.Hash(base.CommitmentHashFunction, message, witness)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "computing commitment hash")
	}
	return commitment, witness, nil
}

func Open(message []byte, commitment Commitment, witness Witness) error {
	hasher := base.CommitmentHashFunction()
	lambda := hasher.Size()
	if lambda != len(commitment) {
		return errs.NewInvalidArgument("size of commitment is wrong given hash function. Need %d whereas we have %d", lambda, len(commitment))
	}
	if lambda != len(witness) {
		return errs.NewInvalidArgument("size of witness is wrong given hash function. Need %d whereas we have %d", lambda, len(witness))
	}
	recomputedCommitment, err := hashing.Hash(base.CommitmentHashFunction, message, witness)
	if err != nil {
		return errs.WrapFailed(err, "recomputing commitment hash")
	}
	if subtle.ConstantTimeCompare(commitment, recomputedCommitment) != 1 {
		return errs.NewVerificationFailed("commitment is invalid")
	}
	return nil
}
