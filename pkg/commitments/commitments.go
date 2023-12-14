package commitments

import (
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/subtle"
	"hash"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
)

type (
	Commitment []byte
	Witness    []byte
)

func CommitWithoutSession(message ...[]byte) (Commitment, Witness, error) {
	if len(message) == 0 {
		return nil, nil, errs.NewInvalidArgument("no commit message")
	}

	lambda := base.CommitmentHashFunction().Size()
	witness := make([]byte, lambda)

	n, err := crand.Read(witness)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "reading random bytes")
	}
	if n != lambda {
		return nil, nil, errs.NewFailed("random reader did not return enough bytes. returned %d bytes whereas we need %d bytes", n, lambda)
	}

	hmacHash := func() hash.Hash { return hmac.New(base.CommitmentHashFunction, witness) }
	commitment, err := hashing.Hash(hmacHash, message...)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "computing commitment hash")
	}
	return commitment, witness, nil
}

func OpenWithoutSession(commitment Commitment, witness Witness, message ...[]byte) error {
	lambda := base.CommitmentHashFunction().Size()
	if lambda != len(commitment) {
		return errs.NewInvalidArgument("size of commitment is wrong given hash function. Need %d whereas we have %d", lambda, len(commitment))
	}
	if lambda != len(witness) {
		return errs.NewInvalidArgument("size of witness is wrong given hash function. Need %d whereas we have %d", lambda, len(witness))
	}

	hmacHash := func() hash.Hash { return hmac.New(base.CommitmentHashFunction, witness) }
	recomputedCommitment, err := hashing.Hash(hmacHash, message...)
	if err != nil {
		return errs.WrapFailed(err, "recomputing commitment hash")
	}
	if subtle.ConstantTimeCompare(commitment, recomputedCommitment) != 1 {
		return errs.NewVerificationFailed("commitment is invalid")
	}

	return nil
}

func Commit(sessionId []byte, message ...[]byte) (Commitment, Witness, error) {
	if len(sessionId) == 0 {
		return nil, nil, errs.NewInvalidArgument("sessionId is empty/nil")
	}

	messageWithSessionId := append(append([][]byte{}, sessionId), message...)
	return CommitWithoutSession(messageWithSessionId...)
}

func Open(sessionId []byte, commitment Commitment, witness Witness, message ...[]byte) error {
	messageWithSessionId := append(append([][]byte{}, sessionId), message...)
	return OpenWithoutSession(commitment, witness, messageWithSessionId...)
}
