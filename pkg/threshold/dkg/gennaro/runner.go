package gennaro

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/network/echo"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/shamir"
	ts "github.com/bronlabs/bron-crypto/pkg/transcripts"
)

func RunGennaroDKG[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](
	rt *network.Router,
	sessionId network.SID,
	group algebra.PrimeGroup[G, S],
	sharingId sharing.ID,
	accessStructure *shamir.AccessStructure,
	tape ts.Transcript,
	prng io.Reader,
) (*DKGOutput[G, S], error) {
	party, err := NewParticipant(sessionId, group, sharingId, accessStructure, tape, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create participant")
	}

	// r1
	r1OutB, err := party.Round1()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot run round 1")
	}
	r2InB, err := echo.ExchangeEchoBroadcastSimple(rt, "GennaroDKGRound1Broadcast", r1OutB)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot exchange broadcast")
	}

	// r2
	r2OutB, r2OutU, err := party.Round2(hashmap.NewImmutableComparableFromNativeLike(r2InB))
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot run round 2")
	}
	r3InB, err := echo.ExchangeEchoBroadcastSimple(rt, "GennaroDKGRound2Broadcast", r2OutB)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot exchange broadcast")
	}
	r3InU, err := network.ExchangeUnicastSimple(rt, "GennaroDKGRound2Unicast", toNative(r2OutU))
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot exchange unicast")
	}

	// r3
	dkgOutput, err := party.Round3(hashmap.NewImmutableComparableFromNativeLike(r3InB), hashmap.NewImmutableComparableFromNativeLike(r3InU))
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot run round 3")
	}

	return dkgOutput, nil
}

func toNative[M any](messages network.OutgoingUnicasts[M]) map[sharing.ID]M {
	messagesMap, ok := messages.(*hashmap.ImmutableComparableHashMap[sharing.ID, M])
	if !ok {
		panic("this should never happen: unexpected type of messages")
	}
	nativeMap := make(map[sharing.ID]M)
	for id, msg := range messagesMap.Iter() {
		nativeMap[id] = msg
	}
	return nativeMap
}
