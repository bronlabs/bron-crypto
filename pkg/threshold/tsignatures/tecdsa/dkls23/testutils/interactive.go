package testutils

import (
	crand "crypto/rand"
	"io"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	ttu "github.com/bronlabs/krypton-primitives/pkg/base/types/testutils"
	"github.com/bronlabs/krypton-primitives/pkg/csprng"
	"github.com/bronlabs/krypton-primitives/pkg/network"
	"github.com/bronlabs/krypton-primitives/pkg/signatures/ecdsa"
	agreeonrandom_testutils "github.com/bronlabs/krypton-primitives/pkg/threshold/agreeonrandom/testutils"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls23"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls23/signing"
	interactiveSigning "github.com/bronlabs/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls23/signing/interactive"
)

func MakeInteractiveCosigners(t require.TestingT, protocol types.ThresholdSignatureProtocol, identities []types.IdentityKey, shards []*dkls23.Shard, tprngs []io.Reader, seededPrng csprng.CSPRNG, sids [][]byte) (participants []*interactiveSigning.Cosigner, err error) {
	if len(identities) < int(protocol.Threshold()) {
		return nil, errs.NewArgument("invalid number of identities %d != %d", len(identities), protocol.Threshold())
	}
	if sids != nil && len(sids) != len(identities) {
		return nil, errs.NewLength("invalid number of hardcoded sids %d != %d", len(sids), len(identities))
	}
	if sids == nil { // Create a common sid if no hardcoded sids are provided
		sids = make([][]byte, len(identities))
		sid, err := agreeonrandom_testutils.RunAgreeOnRandom(t, protocol.Curve(), identities, crand.Reader)
		if err != nil {
			return nil, errs.WrapFailed(err, "failed to produce shared random value")
		}
		for i := range identities {
			sids[i] = sid
		}
	}

	participants = make([]*interactiveSigning.Cosigner, protocol.Threshold())
	for i, identity := range identities {
		var prng io.Reader
		if len(tprngs) != 0 && tprngs[i] != nil {
			prng = tprngs[i]
		} else {
			prng = crand.Reader
		}

		if !protocol.Participants().Contains(identity) {
			return nil, errs.NewValue("identity not in protocol config")
		}
		participants[i], err = interactiveSigning.NewCosigner(sids[i], identity.(types.AuthKey), hashset.NewHashableHashSet(identities...), shards[i], protocol, seededPrng, prng, nil)
		if err != nil || participants[i] == nil {
			return nil, errs.WrapFailed(err, "failed to create cosigner")
		}
	}

	return participants, nil
}

func DoInteractiveSignRound1(participants []*interactiveSigning.Cosigner) (round1OutputsP2P []network.RoundMessages[types.ThresholdSignatureProtocol, *signing.Round1P2P], err error) {
	round1OutputsP2P = make([]network.RoundMessages[types.ThresholdSignatureProtocol, *signing.Round1P2P], len(participants))
	for i, participant := range participants {
		round1OutputsP2P[i], err = participant.Round1()
		if err != nil {
			return nil, errs.WrapFailed(err, "failed to run round 1 of DKLs23 signing")
		}
	}
	return round1OutputsP2P, nil
}

func DoInteractiveSignRound2(participants []*interactiveSigning.Cosigner, round2UnicastInputs []network.RoundMessages[types.ThresholdSignatureProtocol, *signing.Round1P2P]) (round2UnicastOutputs []network.RoundMessages[types.ThresholdSignatureProtocol, *signing.Round2P2P], err error) {
	round2UnicastOutputs = make([]network.RoundMessages[types.ThresholdSignatureProtocol, *signing.Round2P2P], len(participants))
	for i := range participants {
		round2UnicastOutputs[i], err = participants[i].Round2(round2UnicastInputs[i])
		if err != nil {
			return nil, errs.WrapFailed(err, "failed to run round 2 of DKLs23 signing")
		}
	}
	return round2UnicastOutputs, nil
}

func DoInteractiveSignRound3(participants []*interactiveSigning.Cosigner, round3UnicastInputs []network.RoundMessages[types.ThresholdSignatureProtocol, *signing.Round2P2P]) (round3OutputsBroadcast []*signing.Round3Broadcast, round3OutputsP2P []network.RoundMessages[types.ThresholdSignatureProtocol, *signing.Round3P2P], err error) {
	round3OutputsBroadcast = make([]*signing.Round3Broadcast, len(participants))
	round3OutputsP2P = make([]network.RoundMessages[types.ThresholdSignatureProtocol, *signing.Round3P2P], len(participants))
	for i, participant := range participants {
		round3OutputsBroadcast[i], round3OutputsP2P[i], err = participant.Round3(round3UnicastInputs[i])
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "failed to run round 3 of DKLs23 signing")
		}
	}

	return round3OutputsBroadcast, round3OutputsP2P, nil
}

func DoInteractiveSignRound4(participants []*interactiveSigning.Cosigner, round4BroadcastInputs []network.RoundMessages[types.ThresholdSignatureProtocol, *signing.Round3Broadcast], round4UnicastInputs []network.RoundMessages[types.ThresholdSignatureProtocol, *signing.Round3P2P]) (round4BroadcastOutputs []*signing.Round4Broadcast, round4UnicastOutputs []network.RoundMessages[types.ThresholdSignatureProtocol, *signing.Round4P2P], err error) {
	round4BroadcastOutputs = make([]*signing.Round4Broadcast, len(participants))
	round4UnicastOutputs = make([]network.RoundMessages[types.ThresholdSignatureProtocol, *signing.Round4P2P], len(participants))
	for i := range participants {
		round4BroadcastOutputs[i], round4UnicastOutputs[i], err = participants[i].Round4(round4BroadcastInputs[i], round4UnicastInputs[i])
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "failed to run round 4 of DKLs23 signing")
		}
	}
	return round4BroadcastOutputs, round4UnicastOutputs, nil
}

func DoInteractiveSignRound5(participants []*interactiveSigning.Cosigner, round5BroadcastInputs []network.RoundMessages[types.ThresholdSignatureProtocol, *signing.Round4Broadcast], round5UnicastInputs []network.RoundMessages[types.ThresholdSignatureProtocol, *signing.Round4P2P], message []byte) (partialSignatures []*dkls23.PartialSignature, err error) {
	partialSignatures = make([]*dkls23.PartialSignature, len(participants))
	for i := range participants {
		partialSignatures[i], err = participants[i].Round5(round5BroadcastInputs[i], round5UnicastInputs[i], message)
		if err != nil {
			return nil, errs.WrapFailed(err, "failed to run round 5 DKLs23 signing")
		}
	}

	return partialSignatures, nil
}

func MapPartialSignatures(identities []types.IdentityKey, partialSignatures []*dkls23.PartialSignature) network.RoundMessages[types.ThresholdSignatureProtocol, *dkls23.PartialSignature] {
	result := network.NewRoundMessages[types.ThresholdSignatureProtocol, *dkls23.PartialSignature]()
	for i, identity := range identities {
		result.Put(identity, partialSignatures[i])
	}
	return result
}

func RunSignatureAggregation(protocol types.ThresholdSignatureProtocol, identities []types.IdentityKey, participants []*interactiveSigning.Cosigner, partialSignatures []*dkls23.PartialSignature, message []byte) (producedSignatures []*ecdsa.Signature, err error) {
	mappedPartialSignatures := MapPartialSignatures(identities, partialSignatures)
	producedSignatures = make([]*ecdsa.Signature, len(participants))
	for i, participant := range participants {
		signature, err := signing.Aggregate(participant.Protocol.SigningSuite(), participant.Shard().SigningKeyShare.PublicKey, mappedPartialSignatures, message)
		if err != nil {
			return nil, errs.WrapFailed(err, "failed to aggregate signature")
		}

		if err := ecdsa.Verify(signature, protocol.SigningSuite().Hash(), participant.Shard().SigningKeyShare.PublicKey, message); err != nil {
			return nil, errs.WrapVerification(err, "failed to verify signature")
		}
		producedSignatures[i] = signature
	}
	return producedSignatures, nil
}

func CheckInteractiveSignResults(producedSignatures []*ecdsa.Signature) error {
	if len(producedSignatures) == 0 {
		return errs.NewFailed("no signatures produced")
	}
	// all signatures the same
	for i := 0; i < len(producedSignatures); i++ {
		for j := i + 1; j < len(producedSignatures); j++ {
			if producedSignatures[i].R.Cmp(producedSignatures[j].R) != 0 {
				return errs.NewFailed("signatures not equal: r")
			}
			if producedSignatures[i].S.Cmp(producedSignatures[j].S) != 0 {
				return errs.NewFailed("signatures not equal: s")
			}
		}
	}
	return nil
}

func RunInteractiveSign(t require.TestingT, protocol types.ThresholdSignatureProtocol, identities []types.IdentityKey, shards []*dkls23.Shard, message []byte, seededPrng csprng.CSPRNG, sids [][]byte) error {
	participants, err := MakeInteractiveCosigners(t, protocol, identities, shards, nil, seededPrng, sids)
	if err != nil {
		return errs.WrapFailed(err, "failed to make interactive cosigners")
	}

	r1OutU, err := DoInteractiveSignRound1(participants)
	if err != nil {
		return errs.WrapFailed(err, "failed to run round 1 of DKLs23 signing")
	}
	r2InU := ttu.MapUnicastO2I(t, participants, r1OutU)
	r2OutU, err := DoInteractiveSignRound2(participants, r2InU)
	if err != nil {
		return errs.WrapFailed(err, "failed to run round 2 of DKLs23 signing")
	}
	r3InU := ttu.MapUnicastO2I(t, participants, r2OutU)
	r3OutB, r3OutU, err := DoInteractiveSignRound3(participants, r3InU)
	if err != nil {
		return errs.WrapFailed(err, "failed to run round 3 of DKLs23 signing")
	}
	r4InB, r4InU := ttu.MapO2I(t, participants, r3OutB, r3OutU)
	r4OutB, r4OutU, err := DoInteractiveSignRound4(participants, r4InB, r4InU)
	if err != nil {
		return errs.WrapFailed(err, "failed to run round 4 of DKLs23 signing")
	}
	r5InB, r5InU := ttu.MapO2I(t, participants, r4OutB, r4OutU)
	partialSignatures, err := DoInteractiveSignRound5(participants, r5InB, r5InU, message)
	if err != nil {
		return errs.WrapFailed(err, "failed to run round 5 of DKLs23 signing")
	}

	producedSignatures, err := RunSignatureAggregation(protocol, identities, participants, partialSignatures, message)
	if err != nil {
		return errs.WrapFailed(err, "failed to run signature aggregation")
	}

	if err = CheckInteractiveSignResults(producedSignatures); err != nil {
		return errs.WrapVerification(err, "Verification of interactive sign results failed")
	}
	return err
}

func RunInteractiveSignHappyPath(t require.TestingT, protocol types.ThresholdSignatureProtocol, identities []types.IdentityKey, shards []*dkls23.Shard, message []byte, seededPrng csprng.CSPRNG, sids [][]byte) {
	err := RunInteractiveSign(t, protocol, identities, shards, message, seededPrng, sids)
	require.NoError(t, err)
}
