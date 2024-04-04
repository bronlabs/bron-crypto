package commitments

import (
	"crypto/hmac"
	"crypto/subtle"
	"hash"
	"io"
	"slices"

	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
)

var (
	// CommitmentHashFunction is used in the `commitments` package for a UC-secure commitment scheme which chains HMACs and enforces presence of a session-id. Size must be CollisionResistanceBytes.
	CommitmentHashFunction = sha3.New256
)

func computeCommitments(witness Witness, messages ...[]byte) (commitment Commitment, err error) {
	hmacHash := func() hash.Hash { return hmac.New(CommitmentHashFunction, witness) }

	commitment = make([]byte, base.CollisionResistanceBytes)
	for _, message := range messages {
		commitment, err = hashing.Hash(hmacHash, commitment, message)
		if err != nil {
			return nil, errs.WrapHashing(err, "computing commitment hash")
		}
	}
	return commitment, nil
}

func commitInternal(prng io.Reader, messages ...[]byte) (Commitment, Witness, error) {
	witness := make([]byte, base.CollisionResistanceBytes)
	if _, err := io.ReadFull(prng, witness); err != nil {
		return nil, nil, errs.WrapRandomSample(err, "reading random bytes")
	}
	commitment, err := computeCommitments(witness, messages...)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not compute commitment")
	}
	return commitment, witness, nil
}

func openInternal(commitment Commitment, witness Witness, messages ...[]byte) error {
	if err := commitment.Validate(); err != nil {
		return errs.WrapValidation(err, "commitment is invalid")
	}
	if err := witness.Validate(); err != nil {
		return errs.WrapValidation(err, "witness is invalid")
	}

	recomputedCommitment, err := computeCommitments(witness, messages...)
	if err != nil {
		return errs.WrapFailed(err, "could not recompute the commitment")
	}

	if subtle.ConstantTimeCompare(commitment, recomputedCommitment) != 1 {
		return errs.NewVerification("commitment is invalid")
	}

	return nil
}

func encode(messages ...[]byte) [][]byte {
	encoded := make([][]byte, len(messages))
	for i, m := range messages {
		encoded[i] = slices.Concat(bitstring.ToBytesLE(i), bitstring.ToBytesLE(len(m)), m)
	}
	return encoded
}

func encodeWithSessionId(sessionId []byte, messages ...[]byte) [][]byte {
	encoded := make([][]byte, len(messages)+1)
	encoded[0] = slices.Concat([]byte("SESSION_ID_"), bitstring.ToBytesLE(len(sessionId)), sessionId)
	for i, m := range encode(messages...) {
		encoded[i+1] = m
	}
	return encoded
}
