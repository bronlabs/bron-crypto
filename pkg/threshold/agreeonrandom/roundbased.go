package agreeonrandom

import "github.com/copperexchange/krypton-primitives/pkg/base/roundbased"

func RoundBasedRunner(router roundbased.MessageRouter, participant *Participant) ([]byte, error) {
	r1 := roundbased.NewBroadcastRound[*Round1Broadcast](participant.IdentityKey(), 1, router)
	r2 := roundbased.NewBroadcastRound[*Round2Broadcast](participant.IdentityKey(), 2, router)

	// round 1
	r1Out, err := participant.Round1()
	if err != nil {
		return nil, err
	}
	r1.BroadcastOut() <- r1Out

	// round 2
	r2Out, err := participant.Round2(<-r1.BroadcastIn())
	if err != nil {
		return nil, err
	}
	r2.BroadcastOut() <- r2Out

	// round 3
	r3Out, err := participant.Round3(<-r2.BroadcastIn())
	if err != nil {
		return nil, err
	}
	return r3Out, nil
}
