package testutils

import (
	"testing"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/network"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/dkg/gennaro"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

func DoGennaroRound1[
	E gennaro.GroupElement[E, S], S gennaro.Scalar[S],
](
	participants []*gennaro.Participant[E, S],
) (
	r1bo map[sharing.ID]*gennaro.Round1Broadcast[E, S], err error,
) {
	r1bo = make(map[sharing.ID]*gennaro.Round1Broadcast[E, S], len(participants))
	for _, pi := range participants {
		r1bo[pi.SharingID()], err = pi.Round1()
		if err != nil {
			return nil, errs.WrapFailed(err, "%d could not run Gennaro round 1", pi.SharingID())
		}
	}

	return r1bo, nil
}

func DoGennaroRound2[
	E gennaro.GroupElement[E, S], S gennaro.Scalar[S],
](
	participants []*gennaro.Participant[E, S], r2bi map[sharing.ID]network.RoundMessages[*gennaro.Round1Broadcast[E, S]],
) (
	r2bo map[sharing.ID]*gennaro.Round2Broadcast[E, S], r2uo map[sharing.ID]network.RoundMessages[*gennaro.Round2Unicast[E, S]], err error,
) {
	r2bo = make(map[sharing.ID]*gennaro.Round2Broadcast[E, S], len(participants))
	r2uo = make(map[sharing.ID]network.RoundMessages[*gennaro.Round2Unicast[E, S]], len(participants))
	for _, pi := range participants {
		r2bo[pi.SharingID()], r2uo[pi.SharingID()], err = pi.Round2(r2bi[pi.SharingID()])
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "%d could not run Gennaro round 2", pi.SharingID())
		}
	}
	return r2bo, r2uo, nil
}

func DoGennaroRound3[
	E gennaro.GroupElement[E, S], S gennaro.Scalar[S],
](
	participants []*gennaro.Participant[E, S], r3bi map[sharing.ID]network.RoundMessages[*gennaro.Round2Broadcast[E, S]], r3ui map[sharing.ID]network.RoundMessages[*gennaro.Round2Unicast[E, S]],
) (
	dkgOutput ds.MutableMap[sharing.ID, *gennaro.DKGOutput[E, S]], err error,
) {
	dkgOutput = hashmap.NewComparable[sharing.ID, *gennaro.DKGOutput[E, S]]()
	for _, pi := range participants {
		v, err := pi.Round3(r3bi[pi.SharingID()], r3ui[pi.SharingID()])
		if err != nil {
			return nil, errs.WrapFailed(err, "%d could not run Gennaro round 3", pi.SharingID())
		}
		dkgOutput.Put(pi.SharingID(), v)
	}
	return dkgOutput, nil
}

func DoGennaroDKG[
	E gennaro.GroupElement[E, S], S gennaro.Scalar[S],
](
	tb testing.TB, participants []*gennaro.Participant[E, S],
) (
	dkgOutput ds.MutableMap[sharing.ID, *gennaro.DKGOutput[E, S]], err error,
) {
	tb.Helper()
	r1bo, err := DoGennaroRound1(participants)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not run Gennaro round 1")
	}

	r2bi := ntu.MapBroadcastO2I(tb, participants, r1bo)

	r2bo, r2uo, err := DoGennaroRound2(participants, r2bi)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not run Gennaro round 2")
	}

	r3bi := ntu.MapBroadcastO2I(tb, participants, r2bo)
	r3ui := ntu.MapUnicastO2I(tb, participants, r2uo)

	dkgOutput, err = DoGennaroRound3(participants, r3bi, r3ui)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not run Gennaro round 3")
	}

	return dkgOutput, nil
}
