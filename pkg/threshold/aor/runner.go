package aor

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/network/echo"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

func RunAgreeOnRandom(rt *network.Router, id sharing.ID, quorum network.Quorum, size int, tape transcripts.Transcript, prng io.Reader) ([]byte, error) {
	party, err := NewParticipant(id, quorum, size, tape, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create participant")
	}

	// r1
	r1Out, err := party.Round1()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot run round 1")
	}
	r2In, err := echo.ExchangeEchoBroadcastSimple(rt, "AgreeOnRandomRound1Broadcast", r1Out)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot exchange broadcast")
	}

	// r2
	r2Out, err := party.Round2(hashmap.NewImmutableComparableFromNativeLike(r2In))
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot run round 2")
	}
	r3In, err := echo.ExchangeEchoBroadcastSimple(rt, "AgreeOnRandomRound2Broadcast", r2Out)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot exchange broadcast")
	}

	// r3
	sample, err := party.Round3(hashmap.NewImmutableComparableFromNativeLike(r3In))
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot run round 3")
	}

	return sample, nil
}
