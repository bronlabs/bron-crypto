package test_utils

import (
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	test_utils_integration "github.com/copperexchange/knox-primitives/pkg/core/integration/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/core/protocols"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/dkls23"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/dkls23/keygen/dkg"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/dkls23/test_utils"
	"hash"
)

func KeyGen(curve curves.Curve, h func() hash.Hash, threshold int, n int, identities []integration.IdentityKey, sid []byte) ([]integration.IdentityKey, *integration.CohortConfig, []*dkg.Participant, []*dkls23.Shard, error) {
	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  h,
	}

	var err error
	if identities == nil {
		identities, err = test_utils_integration.MakeIdentities(cipherSuite, n)
		if err != nil {
			return nil, nil, nil, nil, err
		}
	}
	cohortConfig, err := test_utils_integration.MakeCohort(cipherSuite, protocols.DKLS23, identities, threshold, identities)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	participants, err := test_utils.MakeDkgParticipants(curve, cohortConfig, identities, nil, sid)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	r1OutsB, r1OutsU, err := test_utils.DoDkgRound1(participants)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	for _, out := range r1OutsU {
		if len(out) != cohortConfig.TotalParties-1 {
			return nil, nil, nil, nil, errs.NewFailed("output size does not match")
		}
	}

	r2InsB, r2InsU := test_utils.MapDkgRound1OutputsToRound2Inputs(participants, r1OutsB, r1OutsU)
	r2OutsB, r2OutsU, err := test_utils.DoDkgRound2(participants, r2InsB, r2InsU)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	for _, out := range r2OutsU {
		if len(out) != cohortConfig.TotalParties-1 {
			return nil, nil, nil, nil, errs.NewFailed("output size does not match")
		}
	}

	r3InsB, r3InsU := test_utils.MapDkgRound2OutputsToRound3Inputs(participants, r2OutsB, r2OutsU)
	r3OutsU, err := test_utils.DoDkgRound3(participants, r3InsB, r3InsU)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	for _, out := range r3OutsU {
		if len(out) != cohortConfig.TotalParties-1 {
			return nil, nil, nil, nil, errs.NewFailed("output size does not match")
		}
	}

	r4InsU := test_utils.MapDkgRound3OutputsToRound4Inputs(participants, r3OutsU)
	r4OutsU, err := test_utils.DoDkgRound4(participants, r4InsU)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	for _, out := range r4OutsU {
		if len(out) != cohortConfig.TotalParties-1 {
			return nil, nil, nil, nil, errs.NewFailed("output size does not match")
		}
	}

	r5InsU := test_utils.MapDkgRound4OutputsToRound5Inputs(participants, r4OutsU)
	r5OutsU, err := test_utils.DoDkgRound5(participants, r5InsU)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	for _, out := range r5OutsU {
		if len(out) != cohortConfig.TotalParties-1 {
			return nil, nil, nil, nil, errs.NewFailed("output size does not match")
		}
	}

	r6InsU := test_utils.MapDkgRound5OutputsToRound6Inputs(participants, r5OutsU)
	shards, err := test_utils.DoDkgRound6(participants, r6InsU)
	return identities, cohortConfig, participants, shards, err
}
