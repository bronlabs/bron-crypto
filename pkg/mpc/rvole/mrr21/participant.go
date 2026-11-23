package rvole_mrr21

import (
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/mpc/rvole"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/ot"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/mrr21"
)

// Message is the OT message type: 256 bits, the input of the cSHAKE256
// expansion into field elements.
type Message = ot.Message256

// Alice is the party with input a ∈ Z_q^ℓ; she is the base-OT sender.
type Alice[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	core   *rvole.Alice[Message, P, B, S]
	sender *mrr21.Sender[Message, P, S]
	round  network.Round
}

// Bob is the party that receives a random b; he is the base-OT receiver and
// samples his own choice bits β.
type Bob[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	core     *rvole.Bob[Message, P, B, S]
	receiver *mrr21.Receiver[Message, P, S]
	prng     io.Reader
	round    network.Round
}

// NewAlice builds Alice on the two-party session ctx, running ξ base OTs over
// the suite's curve; prng must be cryptographically secure, it draws the
// key-agreement secret and the masking column.
func NewAlice[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](ctx *session.Context, suite *rvole.Suite[P, B, S], prng io.Reader) (*Alice[P, B, S], error) {
	core, err := rvole.NewAlice[Message](ctx, suite, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create Alice")
	}
	sender, err := mrr21.NewSender[Message, P, S](ctx, suite.Curve(), suite.Xi(), prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create the base-OT sender")
	}
	return &Alice[P, B, S]{core: core, sender: sender, round: 1}, nil
}

// NewBob builds Bob on the two-party session ctx; prng must be
// cryptographically secure, it draws the choice bits and the key-agreement
// secrets.
func NewBob[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](ctx *session.Context, suite *rvole.Suite[P, B, S], prng io.Reader) (*Bob[P, B, S], error) {
	core, err := rvole.NewBob[Message](ctx, suite, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create Bob")
	}
	receiver, err := mrr21.NewReceiver[Message, P, S](ctx, suite.Curve(), suite.Xi(), prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create the base-OT receiver")
	}
	return &Bob[P, B, S]{core: core, receiver: receiver, prng: prng, round: 1}, nil
}
