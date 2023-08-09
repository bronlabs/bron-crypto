package sample

import (
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/datastructures/hashmap"
	"github.com/copperexchange/knox-primitives/pkg/datastructures/hashset"
	"github.com/copperexchange/knox-primitives/pkg/sharing/zero"
)

type Participant struct {
	Curve               *curves.Curve
	MyIdentityKey       integration.IdentityKey
	MySharingId         int
	PresentParticipants []integration.IdentityKey
	UniqueSessionId     []byte

	IdentityKeyToSharingId *hashmap.HashMap[integration.IdentityKey, int]

	Seeds zero.PairwiseSeeds

	round int
}

func NewParticipant(curve *curves.Curve, uniqueSessionId []byte, identityKey integration.IdentityKey, seeds zero.PairwiseSeeds, presentParticipants []integration.IdentityKey) (*Participant, error) {
	if curve == nil {
		return nil, errs.NewInvalidArgument("curve is nil")
	}
	if identityKey == nil {
		return nil, errs.NewInvalidArgument("my identity key is nil")
	}
	if uniqueSessionId == nil {
		return nil, errs.NewInvalidArgument("session id is nil")
	}
	if len(presentParticipants) < 2 {
		return nil, errs.NewInvalidArgument("need at least 2 participants")
	}
	for i, participant := range presentParticipants {
		if participant == nil {
			return nil, errs.NewIsNil("participant %d is nil", i)
		}
	}
	presentParticipantHashSet, err := hashset.NewHashSet(presentParticipants)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct present participant hash set")
	}
	_, found := presentParticipantHashSet.Get(identityKey)
	if !found {
		return nil, errs.NewInvalidArgument("i'm not part of the participants")
	}

	if seeds == nil {
		return nil, errs.NewInvalidArgument("seeds are nil")
	}
	if seeds.Size() == 0 {
		return nil, errs.NewInvalidArgument("there are no seeds in the seeds map")
	}
	allParticipants := make([]integration.IdentityKey, seeds.Size()+1)
	i := 0
	for _, participant := range seeds.Keys() {
		sharedSeed, found := seeds.Get(participant)
		if !found {
			return nil, errs.NewInvalidArgument("could not find shared seed for participant")
		}
		if participant.PublicKey().Equal(identityKey.PublicKey()) {
			return nil, errs.NewInvalidArgument("found a shared seed with myself")
		}
		foundAnyNonZeroByte := false
		for _, b := range sharedSeed {
			if b != byte(0) {
				foundAnyNonZeroByte = true
				break
			}
		}
		if !foundAnyNonZeroByte {
			return nil, errs.NewInvalidArgument("found a shared seed with all zero bytes")
		}

		allParticipants[i] = participant
		i++
	}
	// i won't be in seeds, and i is already incremented
	allParticipants[seeds.Size()] = identityKey

	// if you pass presentParticipants to below, sharing ids will be different
	_, identityKeyToSharingId, mySharingId := integration.DeriveSharingIds(identityKey, allParticipants)
	if mySharingId == -1 {
		return nil, errs.NewMissing("my sharing id could not be found")
	}
	return &Participant{
		Curve:                  curve,
		MyIdentityKey:          identityKey,
		MySharingId:            mySharingId,
		UniqueSessionId:        uniqueSessionId,
		PresentParticipants:    presentParticipants,
		IdentityKeyToSharingId: identityKeyToSharingId,
		round:                  1,
		Seeds:                  seeds,
	}, nil
}
