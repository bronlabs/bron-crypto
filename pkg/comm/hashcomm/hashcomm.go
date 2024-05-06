package hashcomm

import (
	"crypto/subtle"
	"io"
	"slices"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/comm"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	"golang.org/x/crypto/sha3"
)

const Name comm.Name = "HASH_COMMITMENT"

type Message []byte

var _ comm.Message = Message(nil)

type Witness []byte

var _ Witness = Witness(nil)

var (
	// CommitmentHashFunction is used in the `commitments` package for a UC-secure commitment scheme which chains HMACs and enforces presence of a session-id. Size must be CollisionResistanceBytes.
	CommitmentHashFunction = sha3.New256
)

type Opening struct {
	Message_ Message
	Witness  Witness
}

var _ comm.Opening[Message] = (*Opening)(nil)

func (o *Opening) Message() Message {
	return o.Message_
}

type Committer struct {
	prng      io.Reader
	sessionId []byte
}

type Verifier struct {
	sessionId []byte
}

var _ comm.Verifier[Message, Commitment, *Opening] = (*Verifier)(nil)

type Commitment struct {
	Commitment []byte
}

var _ comm.Commitment = (*Commitment)(nil)

// not UC-secure without session-id
func NewCommitter(sessionId []byte, prng io.Reader) (*Committer, error) {
	if prng == nil {
		return nil, errs.NewIsNil("prng is nil")
	}
	return &Committer{prng, sessionId}, nil
}

// not UC-secure without session-id
func NewVerifier(sessionId []byte) (*Verifier, error) {
	return &Verifier{sessionId}, nil
}

// Encode the session identifier along with the message to commit to
func encodeWithSessionId(sessionId []byte, message []byte) [][]byte {
	encoded := make([][]byte, 2)
	encoded[0] = slices.Concat([]byte("SESSION_ID_"), bitstring.ToBytes32LE(int32(len(sessionId))), sessionId)
	encoded[1] = message
	return encoded
}

func (c *Commitment) Validate() error {
	if c == nil {
		return errs.NewIsNil("receiver")
	}
	if len(c.Commitment) != base.CollisionResistanceBytes {
		return errs.NewArgument("commitment length (%d) != %d", len(c.Commitment), base.CollisionResistanceBytes)
	}
	return nil
}

func (o *Opening) Validate() error {
	if o == nil {
		return errs.NewIsNil("receiver")
	}
	if len(o.Witness) < base.CollisionResistanceBytes {
		return errs.NewArgument("witness length (%d) < %d", len(o.Witness), base.CollisionResistanceBytes)
	}
	return nil
}

func (c *Committer) Commit(message Message) (Commitment, Opening, error) {
	if c == nil {
		return Commitment{}, Opening{}, errs.NewIsNil("receiver")
	}
	witness := make([]byte, base.CollisionResistanceBytes)
	if _, err := io.ReadFull(c.prng, witness); err != nil {
		return Commitment{}, Opening{}, errs.WrapRandomSample(err, "reading random bytes")
	}
	commitment, err := hashing.Hmac(witness, CommitmentHashFunction, encodeWithSessionId(c.sessionId, message)...)
	if err != nil {
		return Commitment{}, Opening{}, errs.WrapHashing(err, "could not compute commitment")
	}
	return Commitment{commitment}, Opening{message, witness}, nil
}

func (v *Verifier) Verify(commitment Commitment, opening *Opening) error {
	if v == nil {
		return errs.NewIsNil("receiver")
	}
	if err := commitment.Validate(); err != nil {
		return errs.WrapValidation(err, "invalid commitment")
	}
	if err := opening.Validate(); err != nil {
		return errs.WrapValidation(err, "invalid opening")
	}
	localCommitment, err := hashing.Hmac(opening.Witness, CommitmentHashFunction, encodeWithSessionId(v.sessionId, opening.Message_)...)
	if err != nil {
		return errs.WrapFailed(err, "could not recompute the commitment")
	}
	if subtle.ConstantTimeCompare(commitment.Commitment, localCommitment) != 1 {
		return errs.NewVerification("verification failed")
	}
	return nil
}
