package elgamalcomm

import (
	"fmt"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/comm"
)

const Name comm.Name = "ELGAMAL_COMMITMENT"

var (
	_ comm.Message          = Message(nil)
	_ comm.Commitment       = (*Commitment)(nil)
	_ comm.Opening[Message] = (*Opening)(nil)

	// hardcoded seed used to derive generators along with the session-id.
	nothingUpMySleeve = []byte(fmt.Sprintf("COPPER_KRYPTON_%s_NOTHING_UP_MY_SLEEVE-", Name))
)

type Message curves.Point
type Witness curves.Scalar

type Opening struct {
	message Message
	witness Witness
}

type Commitment struct {
	c1 curves.Point
	c2 curves.Point
}

func (c *Commitment) Validate() error {
	if c == nil {
		return errs.NewIsNil("commitment")
	}
	if c.c1 == nil {
		return errs.NewIsNil("first commitment component")
	}
	if c.c2 == nil {
		return errs.NewIsNil("second commitment component")
	}
	if c.c1.IsAdditiveIdentity() {
		return errs.NewIsIdentity("first commitment component is identity")
	}
	if c.c2.IsAdditiveIdentity() {
		return errs.NewIsIdentity("second commitment component is identity")
	}
	if !c.c1.IsInPrimeSubGroup() {
		return errs.NewMembership("first commitment is not part of the prime order subgroup")
	}
	if !c.c2.IsInPrimeSubGroup() {
		return errs.NewMembership("first commitment is not part of the prime order subgroup")
	}

	return nil
}

func (o *Opening) Validate() error {
	if o == nil {
		return errs.NewIsNil("opening")
	}
	if o.message == nil {
		return errs.NewIsNil("opening message")
	}
	if o.witness == nil {
		return errs.NewIsNil("opening witness")
	}

	return nil
}

func (o *Opening) Message() Message {
	return o.message
}

func encrypt(publicKey curves.Point, message Message, nonce curves.Scalar) (c1, c2 curves.Point, err error) {
	if publicKey == nil {
		return nil, nil, errs.NewIsNil("public key")
	}
	if publicKey.IsAdditiveIdentity() {
		return nil, nil, errs.NewIsIdentity("public key is identity")
	}

	curve := message.Curve()
	rE := publicKey.ScalarMul(nonce)
	c1 = curve.Generator().ScalarMul(nonce)
	c2 = rE.Add(message)

	return c1, c2, nil
}
