package rvole_softspoken

import (
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/mpc/rvole"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/ot"
	"github.com/bronlabs/bron-crypto/pkg/ot/extension/iknp03"
	"github.com/bronlabs/bron-crypto/pkg/ot/extension/softspoken"
)

// sigma is the number of check rows the extension adds to the ξ OTs.
const sigma = 128

// Alice is the party with input a ∈ Z_q^ℓ; she is the OT-extension sender and
// therefore holds the base-OT receiver output.
type Alice[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	core   *rvole.Alice[softspoken.Message, P, B, S]
	sender *softspoken.Sender
	round  network.Round
}

// Bob is the party that receives a random b; he is the OT-extension receiver
// and therefore holds the base-OT sender output.
type Bob[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	core     *rvole.Bob[softspoken.Message, P, B, S]
	receiver *softspoken.Receiver
	round    network.Round
}

// NewAlice builds Alice from the base-OT receiver output (κ chosen 128-bit
// seeds and their choice bits, see softspoken.NewSender) and a cryptographic
// prng for the masking column. The gadget vector is derived from the
// transcript, which already binds the base OT, before the extension is set up.
func NewAlice[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](ctx *session.Context, suite *rvole.Suite[P, B, S], baseOTReceiverOutput *ot.ReceiverOutput[iknp03.Seed], prng io.Reader) (*Alice[P, B, S], error) {
	core, err := rvole.NewAlice[softspoken.Message](ctx, suite, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create Alice")
	}
	sender, err := softspoken.NewSender(ctx, baseOTReceiverOutput)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create the OT-extension sender")
	}
	return &Alice[P, B, S]{core: core, sender: sender, round: 2}, nil
}

// NewBob builds Bob from the base-OT sender output (κ pairs of 128-bit seeds,
// see softspoken.NewReceiver) and a cryptographic prng for the choice bits.
func NewBob[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](ctx *session.Context, suite *rvole.Suite[P, B, S], baseOTSenderOutput *ot.SenderOutput[iknp03.Seed], prng io.Reader) (*Bob[P, B, S], error) {
	core, err := rvole.NewBob[softspoken.Message](ctx, suite, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create Bob")
	}
	receiver, err := softspoken.NewReceiver(ctx, baseOTSenderOutput, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create the OT-extension receiver")
	}
	return &Bob[P, B, S]{core: core, receiver: receiver, round: 1}, nil
}
