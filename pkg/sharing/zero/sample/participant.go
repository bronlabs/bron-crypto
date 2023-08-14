package sample

import (
	"encoding/hex"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/datastructures/hashset"
	"github.com/copperexchange/knox-primitives/pkg/sharing/zero"
)

type Participant struct {
	Curve               curves.Curve
	MyIdentityKey       integration.IdentityKey
	MySharingId         int
	PresentParticipants []integration.IdentityKey
	UniqueSessionId     []byte

	IdentityKeyToSharingId map[integration.IdentityHash]int

	Seeds zero.PairwiseSeeds

	round int
}

func NewParticipant(cohortConfig *integration.CohortConfig, uniqueSessionId []byte, identityKey integration.IdentityKey, seeds zero.PairwiseSeeds, presentParticipants []integration.IdentityKey) (*Participant, error) {
	if err := cohortConfig.CipherSuite.Validate(); err != nil {
		return nil, errs.WrapInvalidArgument(err, "cohort config is invalid")
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
	if len(seeds) == 0 {
		return nil, errs.NewInvalidArgument("there are no seeds in the seeds map")
	}
	err = checkSeedMatch(cohortConfig.Participants, seeds)
	if err != nil {
		return nil, errs.WrapFailed(err, "seeds do not match participants")
	}
	for participant, sharedSeed := range seeds {
		if participant == identityKey.Hash() {
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
	}

	// if you pass presentParticipants to below, sharing ids will be different
	_, identityKeyToSharingId, mySharingId := integration.DeriveSharingIds(identityKey, cohortConfig.Participants)
	if mySharingId == -1 {
		return nil, errs.NewMissing("my sharing id could not be found")
	}
	return &Participant{
		Curve:                  cohortConfig.CipherSuite.Curve,
		MyIdentityKey:          identityKey,
		MySharingId:            mySharingId,
		UniqueSessionId:        uniqueSessionId,
		PresentParticipants:    presentParticipants,
		IdentityKeyToSharingId: identityKeyToSharingId,
		round:                  1,
		Seeds:                  seeds,
	}, nil
}

func checkSeedMatch(participants []integration.IdentityKey, seeds zero.PairwiseSeeds) error {
	if len(participants) != len(seeds)+1 {
		return errs.NewFailed("number of participants and seeds do not match")
	}
	for seedKey := range seeds {
		found := false
		for _, idKey := range participants {
			if seedKey == idKey.Hash() {
				found = true
				break
			}
		}
		if !found {
			return errs.NewFailed("seed for participant %s is missing", hex.EncodeToString(seedKey[:]))
		}
	}
	return nil
}
