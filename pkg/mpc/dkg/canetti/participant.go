package canetti

import (
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/mathutils"
	"github.com/bronlabs/bron-crypto/pkg/commitments/hashcom"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/feldman"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/dlog/batch_schnorr"
)

const (
	domainSeparator = "BRON_CRYPTO_DKG_CANETTI-"
	ckLabel         = "BRON_CRYPTO_DKG_CANETTI_CK-"
	proverIDLabel   = "BRON_CRYPTO_DKG_CANETTI_PROVER_ID-"
	iLabel          = "BRON_CRYPTO_DKG_CANETTI_i-"
	rhoLabel        = "BRON_CRYPTO_DKG_CANETTI_RHO-"
)

// Participant executes the Canetti-style DKG rounds for one party.
type Participant[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	ctx           *session.Context
	commitmentKey *hashcom.CommitmentKey
	group         algebra.PrimeGroup[G, S]
	sharingScheme *feldman.Scheme[G, S]
	schScheme     *batch_schnorr.Protocol[G, S]
	round         network.Round
	prng          io.Reader
	rhoLen        int
	state         state[G, S]
}

type state[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	proverCtx    *session.Context
	verifierCtxs map[sharing.ID]*session.Context

	dealerFunc         *feldman.DealerFunc[S]
	share              *feldman.Share[S]
	verificationVector *feldman.VerificationVector[G, S]

	rho []byte
	tau *batch_schnorr.State[S]
	msg map[sharing.ID]*CommitmentMessage[G, S]

	u  hashcom.Witness
	vs map[sharing.ID]hashcom.Commitment
}

// NewParticipant creates a participant bound to the provided session context,
// access structure, group, and randomness source.
func NewParticipant[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](ctx *session.Context, accessStructure accessstructures.Monotone, group algebra.PrimeGroup[G, S], prng io.Reader) (*Participant[G, S], error) {
	if ctx == nil || accessStructure == nil || group == nil || prng == nil {
		return nil, ErrInvalidArgument.WithMessage("argument is nil")
	}
	if !ctx.Quorum().Equal(accessStructure.Shareholders()) {
		return nil, ErrInvalidArgument.WithMessage("invalid quorum")
	}

	ctx.Transcript().AppendDomainSeparator(domainSeparator)
	commitmentKey, err := hashcom.ExtractCommitmentKey(ctx.Transcript(), ckLabel)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not extract commitment key from transcript")
	}
	sharingScheme, err := feldman.NewScheme(group, accessStructure)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create feldman scheme")
	}
	schScheme, err := batch_schnorr.NewProtocol(int(sharingScheme.MSP().D()), group, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create ZK scheme")
	}
	rhoLenBits := base.ComputationalSecurityBits + mathutils.CeilLog2(int(sharingScheme.MSP().D()))
	rhoLen := mathutils.CeilDiv(rhoLenBits, 8)

	proverCtx := ctx.Clone()
	proverCtx.Transcript().AppendBytes(proverIDLabel, ctx.HolderID().Bytes())
	verifierCtxs := make(map[sharing.ID]*session.Context)
	for id := range ctx.OtherPartiesOrdered() {
		verifierCtx := ctx.Clone()
		verifierCtx.Transcript().AppendBytes(proverIDLabel, id.Bytes())
		verifierCtxs[id] = verifierCtx
	}

	//nolint:exhaustruct // state is lazy initialised
	p := &Participant[G, S]{
		ctx:           ctx,
		commitmentKey: commitmentKey,
		sharingScheme: sharingScheme,
		schScheme:     schScheme,
		group:         group,
		rhoLen:        rhoLen,
		round:         1,
		prng:          prng,
		state: state[G, S]{
			proverCtx:    proverCtx,
			verifierCtxs: verifierCtxs,
		},
	}
	return p, nil
}

// SharingScheme returns the underlying Feldman sharing scheme used by the DKG protocol.
func (p *Participant[G, S]) SharingScheme() *feldman.Scheme[G, S] {
	return p.sharingScheme
}

// PRNG returns the randomness source of the participant.
func (p *Participant[G, S]) PRNG() io.Reader {
	return p.prng
}

// Group returns the group used by the DKG protocol.
func (p *Participant[G, S]) Group() algebra.PrimeGroup[G, S] {
	return p.group
}

// Ctx returns the session context of the participant.
func (p *Participant[G, S]) Ctx() *session.Context {
	return p.ctx
}

// SharingID returns the sharing identifier of the local participant.
func (p *Participant[G, S]) SharingID() sharing.ID {
	return p.ctx.HolderID()
}
