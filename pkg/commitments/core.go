package commitments

import (
	"crypto/hmac"
	"crypto/subtle"
	"hash"
	"io"
	"slices"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
)

func CommitWithoutSession(prng io.Reader, messages ...[]byte) (Commitment, Witness, error) {
	if prng == nil {
		return nil, nil, errs.NewIsNil("prng is nil")
	}
	if len(messages) == 0 {
		return nil, nil, errs.NewArgument("no commit message")
	}
	var msgs []byte
	for i, m := range messages {
		msgs = slices.Concat(msgs, bitstring.ToBytesLE(i), bitstring.ToBytesLE(len(m)), m)
	}

	return commitInternal(prng, msgs)
}

func OpenWithoutSession(commitment Commitment, witness Witness, messages ...[]byte) error {
	var msgs []byte
	for i, m := range messages {
		msgs = slices.Concat(msgs, bitstring.ToBytesLE(i), bitstring.ToBytesLE(len(m)), m)
	}

	return openInternal(commitment, witness, msgs)
}

func commitInternal(prng io.Reader, messages ...[]byte) (Commitment, Witness, error) {
	lambda := base.CommitmentHashFunction().Size()
	witness := make([]byte, lambda)

	_, err := io.ReadFull(prng, witness)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "reading random bytes")
	}

	hmacHash := func() hash.Hash { return hmac.New(base.CommitmentHashFunction, witness) }
	commitment := make([]byte, 0)
	for _, message := range messages {
		commitment, err = hashing.Hash(hmacHash, commitment, message)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "computing commitment hash")
		}
	}
	return commitment, witness, nil
}

func openInternal(commitment Commitment, witness Witness, message ...[]byte) error {
	lambda := base.CommitmentHashFunction().Size()
	if lambda != len(commitment) {
		return errs.NewArgument("size of commitment is wrong given hash function. Need %d whereas we have %d", lambda, len(commitment))
	}
	if lambda != len(witness) {
		return errs.NewArgument("size of witness is wrong given hash function. Need %d whereas we have %d", lambda, len(witness))
	}

	hmacHash := func() hash.Hash { return hmac.New(base.CommitmentHashFunction, witness) }
	recomputedCommitment := []byte{}
	for _, m := range message {
		var err error
		recomputedCommitment, err = hashing.Hash(hmacHash, recomputedCommitment, m)
		if err != nil {
			return errs.WrapFailed(err, "recomputing commitment hash")
		}
	}

	if subtle.ConstantTimeCompare(commitment, recomputedCommitment) != 1 {
		return errs.NewVerification("commitment is invalid")
	}

	return nil
}
