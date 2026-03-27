package gennaro

import (
	"fmt"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	pedcom "github.com/bronlabs/bron-crypto/pkg/commitments/pedersen"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw/msp"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/meta/feldman"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/meta/pedersen"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	ts "github.com/bronlabs/bron-crypto/pkg/transcripts"
	"github.com/bronlabs/errs-go/errs"
)

const (
	transcriptLabel              = "BRON_CRYPTO_DKG_GENNARO-"
	secondPedersenGeneratorLabel = "second generator of pedersen key"
)

type Participant[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	ctx            *session.Context
	group          algebra.PrimeGroup[E, S]
	scalarField    algebra.PrimeField[S]
	prng           io.Reader
	niCompilerName compiler.Name
	state          *State[E, S]
	round          network.Round
}

type State[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	key         *pedcom.Key[E, S]
	lsss        *kw.Scheme[S]
	pedersenVSS *pedersen.Scheme[E, S]
	feldmanVSS  *feldman.Scheme[E, S]

	localPedersenDealerOutput      *pedersen.DealerOutput[E, S]
	pedersenDealerFunc             *pedersen.DealerFunc[S]
	localFeldmanVerificationVector *feldman.VerificationVector[E, S]
	localShare                     *pedersen.Share[S]
	receivedShares                 map[sharing.ID]*pedersen.Share[S]
	summedShareValue               []S
}

// SharingID returns the participant's identifier within the sharing scheme.
func (p *Participant[E, S]) SharingID() sharing.ID {
	return p.ctx.HolderID()
}

func (p *Participant[E, S]) MSP() *msp.MSP[S] {
	return p.state.lsss.MSP()
}

func NewParticipant[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](
	ctx *session.Context,
	group algebra.PrimeGroup[E, S],
	ac accessstructures.Monotone,
	niCompilerName compiler.Name,
	prng io.Reader,
) (*Participant[E, S], error) {
	if ctx == nil {
		return nil, ErrInvalidArgument.WithMessage("context is nil")
	}
	if ac == nil {
		return nil, ErrInvalidArgument.WithMessage("access structure is nil")
	}
	if !ctx.Quorum().Equal(ac.Shareholders()) {
		return nil, ErrInvalidArgument.WithMessage("access structure doesn't match context")
	}
	if group == nil {
		return nil, ErrInvalidArgument.WithMessage("group is nil")
	}
	if prng == nil {
		return nil, ErrInvalidArgument.WithMessage("prng is nil")
	}
	sf := algebra.StructureMustBeAs[algebra.PrimeField[S]](group.ScalarStructure())

	dst := fmt.Sprintf("%s-%s-%s", transcriptLabel, ctx.SessionID(), group.Name())
	ctx.Transcript().AppendDomainSeparator(dst)

	h, err := ts.Extract(ctx.Transcript(), secondPedersenGeneratorLabel, group)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to extract second generator for pedersen key")
	}
	key, err := pedcom.NewCommitmentKey(group.Generator(), h)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create pedersen key")
	}
	pedersenVSS, err := pedersen.NewScheme(key, ac)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create pedersen VSS scheme")
	}
	feldmanVSS, err := feldman.NewScheme(group, ac)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create feldman VSS scheme")
	}
	lsss, err := kw.NewScheme(sf, ac)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create LSSS scheme for Gennaro DKG")
	}

	return &Participant[E, S]{
		ctx:            ctx,
		group:          group,
		scalarField:    sf,
		prng:           prng,
		niCompilerName: niCompilerName,
		state: &State[E, S]{ //nolint:exhaustruct // readability.
			key:            key,
			pedersenVSS:    pedersenVSS,
			feldmanVSS:     feldmanVSS,
			lsss:           lsss,
			receivedShares: make(map[sharing.ID]*pedersen.Share[S]),
		},
		round: 1,
	}, nil
}
