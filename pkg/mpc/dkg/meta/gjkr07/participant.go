package gjkr07

import (
	"fmt"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	pedcom "github.com/bronlabs/bron-crypto/pkg/commitments/pedersen"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
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

type Participant[
	S sharing.LinearShare[S, SV], SV algebra.PrimeFieldElement[SV],
	W interface {
		sharing.Secret[W]
		base.Transparent[WV]
	}, WV algebra.RingElement[WV],
	DO sharing.DealerOutput[S],
	AC accessstructures.Monotone,
	DF sharing.DealerFunc[S, SV, AC],
	LFTDF interface {
		algebra.Operand[LFTDF]
		sharing.DealerFunc[LFTS, LFTSV, AC]
	}, LFTS sharing.LinearShare[LFTS, LFTSV],
	LFTSV algebra.PrimeGroupElement[LFTSV, SV],
	LFTW interface {
		sharing.Secret[LFTW]
		base.Transparent[LFTWV]
	}, LFTWV algebra.ModuleElement[LFTWV, WV],
] struct {
	sid            network.SID
	ac             AC
	id             sharing.ID
	niCompilerName compiler.Name
	tape           ts.Transcript
	prng           io.Reader
	state          *State[S, SV, W, WV, DO, AC, DF, LFTDF, LFTS, LFTSV, LFTW, LFTWV]
	round          network.Round
}

type State[
	S sharing.LinearShare[S, SV], SV algebra.PrimeFieldElement[SV],
	W interface {
		sharing.Secret[W]
		base.Transparent[WV]
	}, WV algebra.RingElement[WV],
	DO sharing.DealerOutput[S],
	AC accessstructures.Monotone,
	DF sharing.DealerFunc[S, SV, AC],
	LFTDF interface {
		algebra.Operand[LFTDF]
		sharing.DealerFunc[LFTS, LFTSV, AC]
	}, LFTS sharing.LinearShare[LFTS, LFTSV],
	LFTSV algebra.PrimeGroupElement[LFTSV, SV],
	LFTW interface {
		sharing.Secret[LFTW]
		base.Transparent[LFTWV]
	}, LFTWV algebra.ModuleElement[LFTWV, WV],
] struct {
	key         *pedcom.Key[LFTSV, SV]
	pedersenVSS *pedersen.Scheme[S, SV, W, WV, DO, AC, DF, LFTDF, LFTS, LFTSV, LFTW, LFTWV]
	feldmanVSS  *feldman.Scheme[S, SV, W, WV, DO, AC, DF, LFTDF, LFTS, LFTSV, LFTW, LFTWV]

	receivedPedersenVerificationVectors map[sharing.ID]LFTDF
	receivedFeldmanVerificationVectors  map[sharing.ID]LFTDF

	localPedersenDealerOutput      *pedersen.DealerOutput[S, SV, LFTDF, LFTS, LFTSV, AC]
	pedersenDealerFunc             *pedersen.DealerFunc[DF, S, SV, AC]
	localFeldmanVerificationVector LFTDF
	localSecret                    W
	localShare                     *pedersen.Share[S, SV]
}

func NewParticipant[
	S sharing.LinearShare[S, SV], SV algebra.PrimeFieldElement[SV],
	W interface {
		sharing.Secret[W]
		base.Transparent[WV]
	}, WV algebra.RingElement[WV],
	DO sharing.DealerOutput[S],
	AC accessstructures.Monotone,
	DF sharing.DealerFunc[S, SV, AC],
	LFTDF interface {
		algebra.Operand[LFTDF]
		sharing.DealerFunc[LFTS, LFTSV, AC]
	}, LFTS sharing.LinearShare[LFTS, LFTSV],
	LFTSV algebra.PrimeGroupElement[LFTSV, SV],
	LFTW interface {
		sharing.Secret[LFTW]
		base.Transparent[LFTWV]
	}, LFTWV algebra.ModuleElement[LFTWV, WV],
](
	sid network.SID,
	group algebra.PrimeGroup[LFTSV, SV],
	lsss sharing.LiftableLSSS[S, SV, W, WV, DO, AC, DF, LFTS, LFTSV, LFTDF, LFTW, LFTWV],
	ac AC,
	myID sharing.ID,
	niCompilerName compiler.Name,
	tape ts.Transcript,
	prng io.Reader,
) (*Participant[S, SV, W, WV, DO, AC, DF, LFTDF, LFTS, LFTSV, LFTW, LFTWV], error) {
	if utils.IsNil(group) {
		return nil, ErrInvalidArgument.WithMessage("group is nil")
	}
	if lsss == nil {
		return nil, ErrInvalidArgument.WithMessage("liftable LSSS cannot be nil")
	}
	if tape == nil {
		return nil, ErrInvalidArgument.WithMessage("tape is nil")
	}
	if prng == nil {
		return nil, ErrInvalidArgument.WithMessage("prng is nil")
	}
	if utils.IsNil(ac) {
		return nil, ErrInvalidArgument.WithMessage("access structure is nil")
	}
	if !ac.Shareholders().Contains(myID) {
		return nil, ErrInvalidArgument.WithMessage("myID is not a shareholder in the access structure")
	}
	dst := fmt.Sprintf("%s-%d-%s", transcriptLabel, sid, group.Name())
	tape.AppendDomainSeparator(dst)

	h, err := ts.Extract(tape, secondPedersenGeneratorLabel, group)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to extract second generator for pedersen key")
	}
	key, err := pedcom.NewCommitmentKey(group.Generator(), h)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create pedersen key")
	}
	pedersenVSS, err := pedersen.NewScheme(key, lsss)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create pedersen VSS scheme")
	}
	feldmanVSS, err := feldman.NewScheme(group.Generator(), lsss)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create feldman VSS scheme")
	}
	return &Participant[S, SV, W, WV, DO, AC, DF, LFTDF, LFTS, LFTSV, LFTW, LFTWV]{
		sid:            sid,
		ac:             ac,
		id:             myID,
		niCompilerName: niCompilerName,
		tape:           tape,
		prng:           prng,
		//nolint:exhaustruct // initially partially empty state
		state: &State[S, SV, W, WV, DO, AC, DF, LFTDF, LFTS, LFTSV, LFTW, LFTWV]{
			key:                                 key,
			pedersenVSS:                         pedersenVSS,
			feldmanVSS:                          feldmanVSS,
			receivedPedersenVerificationVectors: make(map[sharing.ID]LFTDF),
			receivedFeldmanVerificationVectors:  make(map[sharing.ID]LFTDF),
		},
		round: 1,
	}, nil
}

func (p *Participant[S, SV, W, WV, DO, AC, DF, LFTDF, LFTS, LFTSV, LFTW, LFTWV]) SharingID() sharing.ID {
	return p.id
}

func (p *Participant[S, SV, W, WV, DO, AC, DF, LFTDF, LFTS, LFTSV, LFTW, LFTWV]) AccessStructure() AC {
	return p.ac
}
