package pedersencommitments

import (
	"fmt"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/commitments"
)

const Name commitments.Name = "PEDERSEN_COMMITMENT"

var (
	_ commitments.Message          = Message(nil)
	_ commitments.Commitment       = (*Commitment)(nil)
	_ commitments.Opening[Message] = (*Opening)(nil)

	// hardcoded seed used to derive generators along with the session-id.
	nothingUpMySleeve = []byte(fmt.Sprintf("KRYPTON_%s_SOMETHING_UP_MY_SLEEVE-", Name))
)

type Message curves.Scalar
type Witness curves.Scalar

type Commitment struct {
	Value curves.Point
}

type Opening struct {
	Message Message
	Witness Witness
}

func (c *Commitment) Validate() error {
	if c == nil {
		return errs.NewIsNil("receiver")
	}
	if c.Value == nil {
		return errs.NewIsNil("commitment")
	}
	if !c.Value.IsInPrimeSubGroup() {
		return errs.NewMembership("commitment is not part of the prime order subgroup")
	}
	return nil
}

func (c *Commitment) GetValue() (curves.Point, error) {
	if c == nil {
		return nil, errs.NewIsNil("receiver")
	}
	return c.Value, nil
}

func (o *Opening) Validate() error {
	if o == nil {
		return errs.NewIsNil("receiver")
	}
	if o.Message == nil {
		return errs.NewIsNil("message")
	}
	if o.Witness == nil {
		return errs.NewIsNil("witness")
	}
	return nil
}

func (o *Opening) GetMessage() Message {
	return o.Message
}
