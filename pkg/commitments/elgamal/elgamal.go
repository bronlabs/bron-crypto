package elgamalcommitments

import (
	"fmt"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/commitments"
)

const Name commitments.Name = "ELGAMAL_COMMITMENT"

var (
	_ commitments.Message          = Message(nil)
	_ commitments.Commitment       = (*Commitment)(nil)
	_ commitments.Opening[Message] = (*Opening)(nil)

	// hardcoded seed used to derive generators along with the session-id.
	nothingUpMySleeve = []byte(fmt.Sprintf("KRYPTON_%s_NOTHING_UP_MY_SLEEVE-", Name))
)

type Message curves.Point
type Witness curves.Scalar

type Opening struct {
	Message Message
	Witness Witness
}

type Commitment struct {
	C1 curves.Point
	C2 curves.Point
}

func (c *Commitment) Validate() error {
	if c == nil {
		return errs.NewIsNil("commitment")
	}
	if c.C1 == nil {
		return errs.NewIsNil("first commitment component")
	}
	if c.C2 == nil {
		return errs.NewIsNil("second commitment component")
	}
	if c.C1.IsAdditiveIdentity() {
		return errs.NewIsIdentity("first commitment component is identity")
	}
	if c.C2.IsAdditiveIdentity() {
		return errs.NewIsIdentity("second commitment component is identity")
	}
	if !c.C1.IsInPrimeSubGroup() {
		return errs.NewMembership("first commitment is not part of the prime order subgroup")
	}
	if !c.C2.IsInPrimeSubGroup() {
		return errs.NewMembership("first commitment is not part of the prime order subgroup")
	}

	return nil
}

func (o *Opening) Validate() error {
	if o == nil {
		return errs.NewIsNil("opening")
	}
	if o.Message == nil {
		return errs.NewIsNil("opening message")
	}
	if o.Witness == nil {
		return errs.NewIsNil("opening witness")
	}

	return nil
}

func (o *Opening) GetMessage() Message {
	return o.Message
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
