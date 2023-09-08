package testutils

import (
	"github.com/copperexchange/krypton/pkg/base/types/integration"
	testutils_integration "github.com/copperexchange/krypton/pkg/base/types/integration/testutils"
	"hash"

	"github.com/copperexchange/krypton/pkg/base/curves"
	"github.com/copperexchange/krypton/pkg/base/errs"
	"github.com/copperexchange/krypton/pkg/base/protocols"
	"github.com/copperexchange/krypton/pkg/threshold/tsignatures/tecdsa/dkls23"
	"github.com/copperexchange/krypton/pkg/threshold/tsignatures/tecdsa/dkls23/keygen/dkg"
	"github.com/copperexchange/krypton/pkg/threshold/tsignatures/tecdsa/dkls23/testutils"
)

func KeyGen(curve curves.Curve, h func() hash.Hash, threshold int, n int, identities []integration.IdentityKey, sid []byte) ([]integration.IdentityKey, *integration.CohortConfig, []*dkg.Participant, []*dkls23.Shard, error) {
	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  h,
	}

	var err error
	if identities == nil {
		identities, err = testutils_integration.MakeIdentities(cipherSuite, n)
		if err != nil {
			return nil, nil, nil, nil, err
		}
	}
	cohortConfig, err := testutils_integration.MakeCohortProtocol(cipherSuite, protocols.DKLS23, identities, threshold, identities)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	participants, err := testutils.MakeDkgParticipants(curve, cohortConfig, identities, nil, sid)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	r1OutsB, r1OutsU, err := testutils.DoDkgRound1(participants)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	for _, out := range r1OutsU {
		if len(out) != cohortConfig.Protocol.TotalParties-1 {
			return nil, nil, nil, nil, errs.NewFailed("output size does not match")
		}
	}

	r2InsB, r2InsU := testutils.MapDkgRound1OutputsToRound2Inputs(participants, r1OutsB, r1OutsU)
	r2OutsB, r2OutsU, err := testutils.DoDkgRound2(participants, r2InsB, r2InsU)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	for _, out := range r2OutsU {
		if len(out) != cohortConfig.Protocol.TotalParties-1 {
			return nil, nil, nil, nil, errs.NewFailed("output size does not match")
		}
	}

	r3InsB, r3InsU := testutils.MapDkgRound2OutputsToRound3Inputs(participants, r2OutsB, r2OutsU)
	r3OutsU, err := testutils.DoDkgRound3(participants, r3InsB, r3InsU)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	for _, out := range r3OutsU {
		if len(out) != cohortConfig.Protocol.TotalParties-1 {
			return nil, nil, nil, nil, errs.NewFailed("output size does not match")
		}
	}

	r4InsU := testutils.MapDkgRound3OutputsToRound4Inputs(participants, r3OutsU)
	r4OutsU, err := testutils.DoDkgRound4(participants, r4InsU)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	for _, out := range r4OutsU {
		if len(out) != cohortConfig.Protocol.TotalParties-1 {
			return nil, nil, nil, nil, errs.NewFailed("output size does not match")
		}
	}

	r5InsU := testutils.MapDkgRound4OutputsToRound5Inputs(participants, r4OutsU)
	r5OutsU, err := testutils.DoDkgRound5(participants, r5InsU)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	for _, out := range r5OutsU {
		if len(out) != cohortConfig.Protocol.TotalParties-1 {
			return nil, nil, nil, nil, errs.NewFailed("output size does not match")
		}
	}

	r6InsU := testutils.MapDkgRound5OutputsToRound6Inputs(participants, r5OutsU)
	shards, err := testutils.DoDkgRound6(participants, r6InsU)
	return identities, cohortConfig, participants, shards, err
}
