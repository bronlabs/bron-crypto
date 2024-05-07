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

var _ Witness = Witness(nil)
var _ comm.Message = Message(nil)
var _ comm.Commitment = (*Commitment)(nil)
var _ comm.Opening[Message] = (*Opening)(nil)
var _ comm.Committer[Message, *Commitment, *Opening] = (*Committer)(nil)
var _ comm.Verifier[Message, *Commitment, *Opening] = (*Verifier)(nil)

type Witness []byte
type Message []byte

var (
	// CommitmentHashFunction is used in the `commitments` package for a UC-secure commitment scheme which chains HMACs and enforces presence of a session-id. Size must be CollisionResistanceBytes.
	CommitmentHashFunction = sha3.New256
)

type Opening struct {
	message Message
	Witness Witness
}

type Committer struct {
	prng      io.Reader
	sessionId []byte
}

type Verifier struct {
	sessionId []byte
}

type Commitment struct {
	Commitment []byte
}

func (o *Opening) Message() Message {
	return o.message
}

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

// Encode the session identifier
func encodeSessionId(sessionId []byte) []byte {
	return slices.Concat([]byte("SESSION_ID_"), bitstring.ToBytes32LE(int32(len(sessionId))), sessionId)
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

func (c *Committer) Commit(message Message) (*Commitment, *Opening, error) {
	if message == nil {
		return nil, nil, errs.NewIsNil("message")
	}
	witness := make([]byte, base.CollisionResistanceBytes)
	if _, err := io.ReadFull(c.prng, witness); err != nil {
		return nil, nil, errs.WrapRandomSample(err, "reading random bytes")
	}
	commitment, err := hashing.Hmac(witness, CommitmentHashFunction, encodeSessionId(c.sessionId), message)
	if err != nil {
		return nil, nil, errs.WrapHashing(err, "could not compute commitment")
	}
	return &Commitment{commitment}, &Opening{message, witness}, nil
}

func (v *Verifier) Verify(commitment *Commitment, opening *Opening) error {
	if err := commitment.Validate(); err != nil {
		return errs.WrapValidation(err, "invalid commitment")
	}
	if err := opening.Validate(); err != nil {
		return errs.WrapValidation(err, "invalid opening")
	}
	localCommitment, err := hashing.Hmac(opening.Witness, CommitmentHashFunction, encodeSessionId(v.sessionId), opening.message)
	if err != nil {
		return errs.WrapFailed(err, "could not recompute the commitment")
	}
	if subtle.ConstantTimeCompare(commitment.Commitment, localCommitment) != 1 {
		return errs.NewVerification("verification failed")
	}
	return nil
}
