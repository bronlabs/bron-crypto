package hashcomm

import (
	"crypto/subtle"
	"io"
	"slices"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	"golang.org/x/crypto/sha3"
)

// Define the types for Message and Witness
type Message []byte
type Witness []byte

var (
	// CommitmentHashFunction is used in the `commitments` package for a UC-secure commitment scheme which chains HMACs and enforces presence of a session-id. Size must be CollisionResistanceBytes.
	CommitmentHashFunction = sha3.New256
)

type Committer struct {
	sessionId []byte
}

type Verifier struct {
	sessionId []byte
}

type Commitment struct {
	commitment []byte
}

type Opening struct {
	message Message
	witness Witness
}

func NewCommitter(sessionId []byte) *Committer {
	return &Committer{sessionId}
}

func NewVerifier(sessionId []byte) *Verifier {
	return &Verifier{sessionId}
}

func NewCommitment(commitment []byte) *Commitment {
	return &Commitment{commitment}
}

func NewOpening(message Message, witness Witness) *Opening {
	return &Opening{message, witness}
}

// Encode the session identifier along with the message to commit to
func encodeWithSessionId(sessionId []byte, message []byte) [][]byte {
	encoded := make([][]byte, 2)
	encoded[0] = slices.Concat([]byte("SESSION_ID_"), bitstring.ToBytes32LE(int32(len(sessionId))), sessionId)
	encoded[1] = message
	return encoded
}

// Implement Committer interface
func (c *Committer) Commit(prng io.Reader, message Message) (*Commitment, *Opening, error) {
	if prng == nil {
		return nil, nil, errs.NewIsNil("prng is nil")
	}
	if len(c.sessionId) == 0 {
		return nil, nil, errs.NewArgument("no session identifier")
	}
	witness := make([]byte, base.CollisionResistanceBytes)
	if _, err := io.ReadFull(prng, witness); err != nil {
		return nil, nil, errs.WrapRandomSample(err, "reading random bytes")
	}
	commitment, err := hashing.HmacChain(witness, CommitmentHashFunction, encodeWithSessionId(c.sessionId, message)...)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not compute commitment")
	}
	return NewCommitment(commitment), NewOpening(message, witness), nil
}

// Implement Verifier interface
func (v *Verifier) Verify(commitment *Commitment, opening *Opening) error {
	if len(commitment.commitment) != base.CollisionResistanceBytes {
		return errs.NewArgument("commitment length (%d) != %d", len(opening.witness), base.CollisionResistanceBytes)
	}
	if len(opening.witness) != base.CollisionResistanceBytes {
		return errs.NewArgument("witness length (%d) != %d", len(opening.witness), base.CollisionResistanceBytes)
	}

	localCommitment, err := hashing.HmacChain(opening.witness, CommitmentHashFunction, encodeWithSessionId(v.sessionId, opening.message)...)
	if err != nil {
		return errs.WrapFailed(err, "could not recompute the commitment")
	}

	if subtle.ConstantTimeCompare(commitment.commitment, localCommitment) != 1 {
		return errs.NewVerification("commitment is invalid")
	}

	return nil
}
