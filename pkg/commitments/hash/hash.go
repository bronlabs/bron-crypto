package hashcommitments

import (
	"slices"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
)

const Name commitments.Name = "HASH_COMMITMENT"

var (
	_ commitments.Message          = Message(nil)
	_ commitments.Commitment       = (*Commitment)(nil)
	_ commitments.Opening[Message] = (*Opening)(nil)
)

type Witness []byte
type Message []byte

type Opening struct {
	Message Message
	Witness Witness
}

type Commitment struct {
	Value []byte
}

func (o *Opening) GetMessage() Message {
	return o.Message
}

func (o *Opening) Validate() error {
	if o == nil {
		return errs.NewIsNil("receiver")
	}
	if len(o.Witness) < base.CollisionResistanceBytes {
		return errs.NewArgument("Witness length (%d) < %d", len(o.Witness), base.CollisionResistanceBytes)
	}

	return nil
}

func (c *Commitment) Validate() error {
	if c == nil {
		return errs.NewIsNil("receiver")
	}
	if len(c.Value) != base.CollisionResistanceBytes {
		return errs.NewArgument("commitment length (%d) != %d", len(c.Value), base.CollisionResistanceBytes)
	}

	return nil
}

func encodeSessionId(sessionId []byte) []byte {
	return slices.Concat([]byte("SESSION_ID_"), bitstring.ToBytes32LE(int32(len(sessionId))), sessionId)
}
