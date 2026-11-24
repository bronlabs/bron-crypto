package signing_softspoken

import (
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	rvole_softspoken "github.com/bronlabs/bron-crypto/pkg/mpc/rvole/softspoken"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/dkls23"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/dkls23/signing"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/mrr21"
	"github.com/bronlabs/bron-crypto/pkg/ot/extension/iknp03"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

const (
	transcriptLabel = "BRON_CRYPTO-DKLS23-SIGNING-SOFTSPOKEN-"
	// baseOTCount is κ, the number of base OTs seeding one OT extension; their
	// messages are the extension's 128-bit PRG seeds, iknp03.Seed.
	baseOTCount = 128
)

// Cosigner is one signing party. For every counterparty it keeps two pairwise
// sub-sessions: one in which it is Alice of the rVOLE (and so the base-OT
// receiver) and one in which it is Bob (the base-OT sender).
type Cosigner[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	core  *signing.Core[P, B, S]
	round network.Round

	aliceCtx        map[sharing.ID]*session.Context
	bobCtx          map[sharing.ID]*session.Context
	baseOTReceivers map[sharing.ID]*mrr21.Receiver[iknp03.Seed, P, S]
	baseOTSenders   map[sharing.ID]*mrr21.Sender[iknp03.Seed, P, S]
	alice           map[sharing.ID]*rvole_softspoken.Alice[P, B, S]
	bob             map[sharing.ID]*rvole_softspoken.Bob[P, B, S]
}

// NewCosigner builds a cosigner for the quorum of ctx, which must be
// qualified for the shard's access structure, and sets up the pairwise
// sub-sessions and base-OT participants with every other party.
func NewCosigner[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](ctx *session.Context, suite *ecdsa.Suite[P, B, S], shard *dkls23.Shard[P, B, S], prng io.Reader) (*Cosigner[P, B, S], error) {
	core, err := signing.NewCore(ctx, suite, shard, prng, transcriptLabel)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create the signing core")
	}
	me := core.SharingID()
	c := &Cosigner[P, B, S]{
		core:            core,
		round:           1,
		aliceCtx:        make(map[sharing.ID]*session.Context),
		bobCtx:          make(map[sharing.ID]*session.Context),
		baseOTReceivers: make(map[sharing.ID]*mrr21.Receiver[iknp03.Seed, P, S]),
		baseOTSenders:   make(map[sharing.ID]*mrr21.Sender[iknp03.Seed, P, S]),
		alice:           make(map[sharing.ID]*rvole_softspoken.Alice[P, B, S]),
		bob:             make(map[sharing.ID]*rvole_softspoken.Bob[P, B, S]),
	}
	for id := range ctx.OtherPartiesOrdered() {
		// This party is Alice, so the base-OT receiver, with id as Bob.
		c.aliceCtx[id], err = core.PairContext(me, id)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create the Alice session with %d", id)
		}
		c.baseOTReceivers[id], err = mrr21.NewReceiver[iknp03.Seed, P, S](c.aliceCtx[id], suite.Curve(), baseOTCount, prng)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create the base-OT receiver for %d", id)
		}
		// This party is Bob, so the base-OT sender, with id as Alice.
		c.bobCtx[id], err = core.PairContext(id, me)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create the Bob session with %d", id)
		}
		c.baseOTSenders[id], err = mrr21.NewSender[iknp03.Seed, P, S](c.bobCtx[id], suite.Curve(), baseOTCount, prng)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create the base-OT sender for %d", id)
		}
	}
	return c, nil
}

// Core returns the signing-layer core, which the cosigning aggregator takes.
func (c *Cosigner[P, B, S]) Core() *signing.Core[P, B, S] {
	return c.core
}

// SharingID returns the participant's sharing identifier.
func (c *Cosigner[P, B, S]) SharingID() sharing.ID {
	return c.core.SharingID()
}

// Quorum returns the signing quorum.
func (c *Cosigner[P, B, S]) Quorum() network.Quorum {
	return c.core.Quorum()
}
