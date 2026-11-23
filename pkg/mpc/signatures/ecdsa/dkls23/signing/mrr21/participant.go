package signing_mrr21

import (
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	rvole_mrr21 "github.com/bronlabs/bron-crypto/pkg/mpc/rvole/mrr21"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/dkls23"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/dkls23/signing"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

const transcriptLabel = "BRON_CRYPTO-DKLS23-SIGNING-MRR21-"

// Cosigner is one signing party. For every counterparty it keeps two rVOLEs on
// their own pairwise sub-sessions: one in which it is Alice and one in which
// it is Bob.
type Cosigner[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	core  *signing.Core[P, B, S]
	round network.Round

	alice map[sharing.ID]*rvole_mrr21.Alice[P, B, S]
	bob   map[sharing.ID]*rvole_mrr21.Bob[P, B, S]
}

// NewCosigner builds a cosigner for the quorum of ctx, which must be
// qualified for the shard's access structure, and sets up the pairwise
// sub-sessions and rVOLE participants with every other party.
func NewCosigner[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](ctx *session.Context, suite *ecdsa.Suite[P, B, S], shard *dkls23.Shard[P, B, S], prng io.Reader) (*Cosigner[P, B, S], error) {
	core, err := signing.NewCore(ctx, suite, shard, prng, transcriptLabel)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create the signing core")
	}
	me := core.SharingID()
	c := &Cosigner[P, B, S]{
		core:  core,
		round: 1,
		alice: make(map[sharing.ID]*rvole_mrr21.Alice[P, B, S]),
		bob:   make(map[sharing.ID]*rvole_mrr21.Bob[P, B, S]),
	}
	for id := range ctx.OtherPartiesOrdered() {
		aliceCtx, err := core.PairContext(me, id)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create the Alice session with %d", id)
		}
		c.alice[id], err = rvole_mrr21.NewAlice(aliceCtx, core.MulSuite(), prng)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create rVOLE Alice with %d", id)
		}
		bobCtx, err := core.PairContext(id, me)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create the Bob session with %d", id)
		}
		c.bob[id], err = rvole_mrr21.NewBob(bobCtx, core.MulSuite(), prng)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create rVOLE Bob with %d", id)
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
