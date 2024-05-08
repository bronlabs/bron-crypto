package pedersencomm

import (
	"fmt"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/comm"
)

const Name comm.Name = "PEDERSEN_COMMITMENT"

var (
	_ comm.Message          = Message(nil)
	_ comm.Commitment       = (*Commitment)(nil)
	_ comm.Opening[Message] = (*Opening)(nil)

	// hardcoded seed used to derive generators along with the session-id.
	nothingUpMySleeve = []byte(fmt.Sprintf("COPPER_KRYPTON_%s_SOMETHING_UP_MY_SLEEVE-", Name))
)

type Message curves.Scalar
type Witness curves.Scalar

type Commitment struct {
	value curves.Point
}

type Opening struct {
	message Message
	witness Witness
}

func (c *Commitment) Validate() error {
	if c == nil {
		return errs.NewIsNil("receiver")
	}
	if c.value == nil {
		return errs.NewIsNil("commitment")
	}
	if !c.value.IsInPrimeSubGroup() {
		return errs.NewMembership("commitment is not part of the prime order subgroup")
	}
	return nil
}

func (o *Opening) Validate() error {
	if o == nil {
		return errs.NewIsNil("receiver")
	}
	if o.message == nil {
		return errs.NewIsNil("message")
	}
	if o.witness == nil {
		return errs.NewIsNil("witness")
	}
	return nil
}

func (o *Opening) Message() Message {
	return o.message
}
