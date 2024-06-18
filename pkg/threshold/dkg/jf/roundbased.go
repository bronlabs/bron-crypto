package jf

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/roundbased"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
)

func RoundBasedRunner(router roundbased.MessageRouter, participant *Participant) (*tsignatures.SigningKeyShare, *tsignatures.PartialPublicKeys, error) {
	id := participant.IdentityKey()
	r1b := roundbased.NewBroadcastRound[*Round1Broadcast](id, 1, router)
	r1u := roundbased.NewUnicastRound[*Round1P2P](id, 1, router)
	r2b := roundbased.NewBroadcastRound[*Round2Broadcast](id, 2, router)

	// round 1
	r1bo, r1uo, err := participant.Round1()
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "round 1 failed")
	}
	r1b.BroadcastOut() <- r1bo
	r1u.UnicastOut() <- r1uo

	// round 2
	r2bo, err := participant.Round2(<-r1b.BroadcastIn(), <-r1u.UnicastIn())
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "round 2 failed")
	}
	r2b.BroadcastOut() <- r2bo

	// round3
	signingKeyShare, publicKeyShares, err := participant.Round3(<-r2b.BroadcastIn())
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "round 3 failed")
	}

	return signingKeyShare, publicKeyShares, nil
}
