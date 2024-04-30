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
	message Message
	witness Witness
}

var _ comm.Opening[Message] = (*Opening)(nil)

func (o Opening) Message() Message {
	return o.message
}

type Committer struct {
	sessionId []byte
}

var _ comm.Committer[Message, Commitment, Opening] = (*Committer)(nil)

type Verifier struct {
	sessionId []byte
}

var _ comm.Verifier[Message, Commitment, Opening] = (*Verifier)(nil)

type Commitment struct {
	commitment []byte
}

var _ comm.Commitment = (*Commitment)(nil)

// not UC-secure without session-id
func NewCommitter(sessionId []byte) *Committer {
	return &Committer{sessionId}
}

// not UC-secure without session-id
func NewVerifier(sessionId []byte) *Verifier {
	return &Verifier{sessionId}
}

// Encode the session identifier along with the message to commit to
func encodeWithSessionId(sessionId []byte, message []byte) [][]byte {
	encoded := make([][]byte, 2)
	encoded[0] = slices.Concat([]byte("SESSION_ID_"), bitstring.ToBytes32LE(int32(len(sessionId))), sessionId)
	encoded[1] = message
	return encoded
}

func (c *Commitment) Validate() error {
	if len(c.commitment) != base.CollisionResistanceBytes {
		return errs.NewArgument("commitment length (%d) != %d", len(c.commitment), base.CollisionResistanceBytes)
	}
	return nil
}

func (o *Opening) Validate() error {
	if len(o.witness) < base.CollisionResistanceBytes {
		return errs.NewArgument("witness length (%d) < %d", len(o.witness), base.CollisionResistanceBytes)
	}
	return nil
}

func (c *Committer) Commit(prng io.Reader, message Message) (*Commitment, *Opening, error) {
	if prng == nil {
		return nil, nil, errs.NewIsNil("prng is nil")
	}
	witness := make([]byte, base.CollisionResistanceBytes)
	if _, err := io.ReadFull(prng, witness); err != nil {
		return nil, nil, errs.WrapRandomSample(err, "reading random bytes")
	}
	commitment, err := hashing.Hmac(witness, CommitmentHashFunction, encodeWithSessionId(c.sessionId, message)...)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not compute commitment")
	}
	return &Commitment{commitment}, &Opening{message, witness}, nil
}

func (v *Verifier) Verify(commitment *Commitment, opening *Opening) error {
	if commitment.Validate() != nil {
		return errs.NewArgument("unvalid commitment")
	}
	if opening.Validate() != nil {
		return errs.NewArgument("unvalid opening")
	}
	localCommitment, err := hashing.Hmac(opening.witness, CommitmentHashFunction, encodeWithSessionId(v.sessionId, opening.message)...)
	if err != nil {
		return errs.WrapFailed(err, "could not recompute the commitment")
	}
	if subtle.ConstantTimeCompare(commitment.commitment, localCommitment) != 1 {
		return errs.NewVerification("verification failed")
	}
	return nil
}
