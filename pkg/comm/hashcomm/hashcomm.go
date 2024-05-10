package hashcomm

import (
	"slices"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/comm"
)

const Name comm.Name = "HASH_COMMITMENT"

var (
	_ comm.Message          = Message(nil)
	_ comm.Commitment       = (*Commitment)(nil)
	_ comm.Opening[Message] = (*Opening)(nil)

	// CommitmentHashFunction is used in the `commitments` package for a UC-secure commitment scheme which chains HMACs and enforces presence of a session-id. Size must be CollisionResistanceBytes.
	hashFunc = base.RandomOracleHashFunction
)

type Witness []byte
type Message []byte

type Opening struct {
	message Message
	witness Witness
}

type Commitment struct {
	value []byte
}

func (o *Opening) Message() Message {
	return o.message
}

func (o *Opening) Validate() error {
	if o == nil {
		return errs.NewIsNil("receiver")
	}
	if len(o.witness) < base.CollisionResistanceBytes {
		return errs.NewArgument("witness length (%d) < %d", len(o.witness), base.CollisionResistanceBytes)
	}

	return nil
}

func (c *Commitment) Validate() error {
	if c == nil {
		return errs.NewIsNil("receiver")
	}
	if len(c.value) != base.CollisionResistanceBytes {
		return errs.NewArgument("commitment length (%d) != %d", len(c.value), base.CollisionResistanceBytes)
	}

	return nil
}

func encodeSessionId(sessionId []byte) []byte {
	return slices.Concat([]byte("SESSION_ID_"), bitstring.ToBytes32LE(int32(len(sessionId))), sessionId)
}
