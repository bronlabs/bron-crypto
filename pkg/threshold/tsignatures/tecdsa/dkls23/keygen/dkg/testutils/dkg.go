package testutils

import (
	"hash"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	ttu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	jf_testutils "github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/jf/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls23"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls23/keygen/dkg"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls23/testutils"
)

func KeyGen(curve curves.Curve, h func() hash.Hash, threshold, n int, identities []types.IdentityKey, sid []byte) ([]types.IdentityKey, types.ThresholdSignatureProtocol, []*dkg.Participant, []*dkls23.Shard, error) {
	cipherSuite, err := ttu.MakeSigningSuite(curve, h)
	if err != nil {
		return nil, nil, nil, nil, errs.WrapFailed(err, "could not construct ciphersuite")
	}
	if identities == nil {
		identities, err = ttu.MakeTestIdentities(cipherSuite, n)
		if err != nil {
			return nil, nil, nil, nil, errs.WrapFailed(err, "could not construct test identities")
		}
	}
	protocol, err := ttu.MakeThresholdSignatureProtocol(cipherSuite, identities, threshold, identities)
	if err != nil {
		return nil, nil, nil, nil, errs.WrapFailed(err, "could not construct protocol config")
	}

	private, public, err := jf_testutils.RunDKG(sid, protocol, identities)
	if err != nil {
		return nil, nil, nil, nil, errs.WrapFailed(err, "could not run JF-DKG protocol")
	}

	participants, err := testutils.MakeDkgParticipants(curve, protocol, identities, private, public, nil, sid)
	if err != nil {
		return nil, nil, nil, nil, errs.WrapFailed(err, "could not construct participants")
	}

	r1OutsU, err := testutils.DoDkgRound1(participants)
	if err != nil {
		return nil, nil, nil, nil, errs.WrapFailed(err, "could not run DKG round 1")
	}
	for _, out := range r1OutsU {
		if out.Size() != int(protocol.TotalParties())-1 {
			return nil, nil, nil, nil, errs.NewFailed("output size does not match")
		}
	}

	r2InsU := ttu.MapUnicastO2I(participants, r1OutsU)
	r2OutsU, err := testutils.DoDkgRound2(participants, r2InsU)
	if err != nil {
		return nil, nil, nil, nil, errs.WrapFailed(err, "could not run DKG round 2")
	}
	for _, out := range r2OutsU {
		if out.Size() != int(protocol.TotalParties()-1) {
			return nil, nil, nil, nil, errs.NewFailed("output size does not match")
		}
	}

	r3InsU := ttu.MapUnicastO2I(participants, r2OutsU)
	shards, err := testutils.DoDkgRound3(private, participants, r3InsU)
	if err != nil {
		return nil, nil, nil, nil, errs.WrapFailed(err, "could not run DKG round 3")
	}
	if len(shards) != int(protocol.TotalParties()) {
		return nil, nil, nil, nil, errs.NewFailed("output size does not match")
	}

	return identities, protocol, participants, shards, errs.WrapFailed(err, "could not run DKG round 6")
}
