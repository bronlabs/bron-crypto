package testutils

import (
	"hash"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/protocols"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	integration_testutils "github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24/keygen/dkg"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24/testutils"
)

func KeyGen(curve curves.Curve, h func() hash.Hash, threshold, n int, identities []integration.IdentityKey, sid []byte) ([]integration.IdentityKey, *integration.CohortConfig, []*dkg.Participant, []*dkls24.Shard, error) {
	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  h,
	}

	var err error
	if identities == nil {
		identities, err = integration_testutils.MakeTestIdentities(cipherSuite, n)
		if err != nil {
			return nil, nil, nil, nil, errs.WrapFailed(err, "could not construct test identities")
		}
	}
	cohortConfig, err := integration_testutils.MakeCohortProtocol(cipherSuite, protocols.DKLS24, identities, threshold, identities)
	if err != nil {
		return nil, nil, nil, nil, errs.WrapFailed(err, "could not construct cohort protocol")
	}

	participants, err := testutils.MakeDkgParticipants(curve, cohortConfig, identities, nil, sid)
	if err != nil {
		return nil, nil, nil, nil, errs.WrapFailed(err, "could not construct participants")
	}

	r1OutsB, r1OutsU, err := testutils.DoDkgRound1(participants)
	if err != nil {
		return nil, nil, nil, nil, errs.WrapFailed(err, "could not run DKG round 1")
	}
	for _, out := range r1OutsU {
		if len(out) != cohortConfig.Protocol.TotalParties-1 {
			return nil, nil, nil, nil, errs.NewFailed("output size does not match")
		}
	}

	r2InsB, r2InsU := integration_testutils.MapO2I(participants, r1OutsB, r1OutsU)
	r2OutsB, r2OutsU, err := testutils.DoDkgRound2(participants, r2InsB, r2InsU)
	if err != nil {
		return nil, nil, nil, nil, errs.WrapFailed(err, "could not run DKG round 2")
	}
	for _, out := range r2OutsU {
		if len(out) != cohortConfig.Protocol.TotalParties-1 {
			return nil, nil, nil, nil, errs.NewFailed("output size does not match")
		}
	}

	r3InsB, r3InsU := integration_testutils.MapO2I(participants, r2OutsB, r2OutsU)
	r3OutsU, err := testutils.DoDkgRound3(participants, r3InsB, r3InsU)
	if err != nil {
		return nil, nil, nil, nil, errs.WrapFailed(err, "could not run DKG round 3")
	}
	for _, out := range r3OutsU {
		if len(out) != cohortConfig.Protocol.TotalParties-1 {
			return nil, nil, nil, nil, errs.NewFailed("output size does not match")
		}
	}

	r4InsU := integration_testutils.MapUnicastO2I(participants, r3OutsU)
	r4OutsU, err := testutils.DoDkgRound4(participants, r4InsU)
	if err != nil {
		return nil, nil, nil, nil, errs.WrapFailed(err, "could not run DKG round 4")
	}
	for _, out := range r4OutsU {
		if len(out) != cohortConfig.Protocol.TotalParties-1 {
			return nil, nil, nil, nil, errs.NewFailed("output size does not match")
		}
	}

	r5InsU := integration_testutils.MapUnicastO2I(participants, r4OutsU)
	r5OutsU, err := testutils.DoDkgRound5(participants, r5InsU)
	if err != nil {
		return nil, nil, nil, nil, errs.WrapFailed(err, "could not run DKG round 5")
	}
	for _, out := range r5OutsU {
		if len(out) != cohortConfig.Protocol.TotalParties-1 {
			return nil, nil, nil, nil, errs.NewFailed("output size does not match")
		}
	}

	r6InsU := integration_testutils.MapUnicastO2I(participants, r5OutsU)
	shards, err := testutils.DoDkgRound6(participants, r6InsU)
	return identities, cohortConfig, participants, shards, errs.WrapFailed(err, "could not run DKG round 6")
}
