package pedersen

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/roundbased"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
)

func RoundBasedRunner(router roundbased.MessageRouter, participant *Participant) (*tsignatures.SigningKeyShare, *tsignatures.PartialPublicKeys, error) {
	id := participant.IdentityKey()
	r1b := roundbased.NewBroadcastRound[*Round1Broadcast](id, 1, router)
	r1u := roundbased.NewUnicastRound[*Round1P2P](id, 1, router)

	// round 1
	r1bo, r1uo, err := participant.Round1(participant.State.A_i0)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "round 1 failed")
	}
	r1b.BroadcastOut() <- r1bo
	r1u.UnicastOut() <- r1uo

	// round 2
	signingKeyShare, publicKeyShares, err := participant.Round2(<-r1b.BroadcastIn(), <-r1u.UnicastIn())
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "round 2 failed")
	}
	return signingKeyShare, publicKeyShares, nil
}
