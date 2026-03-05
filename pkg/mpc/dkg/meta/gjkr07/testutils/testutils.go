package testutils

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/mpc/dkg/meta/gjkr07"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/network"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/errs-go/errs"
)

type P[
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
] = gjkr07.Participant[S, SV, W, WV, DO, AC, DF, LFTDF, LFTS, LFTSV, LFTW, LFTWV]

func DoRound1[
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
	participants []*P[S, SV, W, WV, DO, AC, DF, LFTDF, LFTS, LFTSV, LFTW, LFTWV],
) (
	r1bo map[sharing.ID]*gjkr07.Round1Broadcast[LFTDF, LFTS, LFTSV, SV, AC], err error,
) {
	r1bo = make(map[sharing.ID]*gjkr07.Round1Broadcast[LFTDF, LFTS, LFTSV, SV, AC], len(participants))
	for _, pi := range participants {
		r1bo[pi.SharingID()], err = pi.Round1()
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("%d could not run round 1", pi.SharingID())
		}
	}
	return r1bo, nil
}

func DoRound2[
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
	participants []*P[S, SV, W, WV, DO, AC, DF, LFTDF, LFTS, LFTSV, LFTW, LFTWV],
	r2bi map[sharing.ID]network.RoundMessages[*gjkr07.Round1Broadcast[LFTDF, LFTS, LFTSV, SV, AC]],
) (
	r2bo map[sharing.ID]*gjkr07.Round2Broadcast[LFTDF, LFTS, LFTSV, SV, AC],
	r2uo map[sharing.ID]network.RoundMessages[*gjkr07.Round2Unicast[S, SV]],
	err error,
) {
	r2bo = make(map[sharing.ID]*gjkr07.Round2Broadcast[LFTDF, LFTS, LFTSV, SV, AC], len(participants))
	r2uo = make(map[sharing.ID]network.RoundMessages[*gjkr07.Round2Unicast[S, SV]], len(participants))
	for _, pi := range participants {
		r2bo[pi.SharingID()], r2uo[pi.SharingID()], err = pi.Round2(r2bi[pi.SharingID()])
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("%d could not run round 2", pi.SharingID())
		}
	}
	return r2bo, r2uo, nil
}

func DoRound3[
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
	participants []*P[S, SV, W, WV, DO, AC, DF, LFTDF, LFTS, LFTSV, LFTW, LFTWV],
	r3bi map[sharing.ID]network.RoundMessages[*gjkr07.Round2Broadcast[LFTDF, LFTS, LFTSV, SV, AC]],
	r3ui map[sharing.ID]network.RoundMessages[*gjkr07.Round2Unicast[S, SV]],
) (
	dkgOutput ds.MutableMap[sharing.ID, *gjkr07.DKGOutput[LFTDF, LFTS, LFTSV, S, SV, AC]], err error,
) {
	dkgOutput = hashmap.NewComparable[sharing.ID, *gjkr07.DKGOutput[LFTDF, LFTS, LFTSV, S, SV, AC]]()
	for _, pi := range participants {
		v, err := pi.Round3(r3bi[pi.SharingID()], r3ui[pi.SharingID()])
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("%d could not run round 3", pi.SharingID())
		}
		dkgOutput.Put(pi.SharingID(), v)
	}
	return dkgOutput, nil
}

func DoDKG[
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
	tb testing.TB,
	participants []*P[S, SV, W, WV, DO, AC, DF, LFTDF, LFTS, LFTSV, LFTW, LFTWV],
) (
	dkgOutput ds.MutableMap[sharing.ID, *gjkr07.DKGOutput[LFTDF, LFTS, LFTSV, S, SV, AC]], err error,
) {
	tb.Helper()

	r1bo, err := DoRound1[S, SV, W, WV, DO, AC, DF, LFTDF, LFTS, LFTSV, LFTW, LFTWV](participants)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not run round 1")
	}

	r2bi := ntu.MapBroadcastO2I(tb, participants, r1bo)

	r2bo, r2uo, err := DoRound2[S, SV, W, WV, DO, AC, DF, LFTDF, LFTS, LFTSV, LFTW, LFTWV](participants, r2bi)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not run round 2")
	}

	r3bi := ntu.MapBroadcastO2I(tb, participants, r2bo)
	r3ui := ntu.MapUnicastO2I(tb, participants, r2uo)

	dkgOutput, err = DoRound3[S, SV, W, WV, DO, AC, DF, LFTDF, LFTS, LFTSV, LFTW, LFTWV](participants, r3bi, r3ui)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not run round 3")
	}

	return dkgOutput, nil
}
