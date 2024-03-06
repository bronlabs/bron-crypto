package testutils

import (
	crand "crypto/rand"
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	ttu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/csprng"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/ecdsa"
	agreeonrandom_testutils "github.com/copperexchange/krypton-primitives/pkg/threshold/agreeonrandom/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24/signing"
	interactiveSigning "github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24/signing/interactive"
)

func MakeInteractiveCosigners(protocol types.ThresholdSignatureProtocol, identities []types.IdentityKey, shards []*dkls24.Shard, tprngs []io.Reader, seededPrng csprng.CSPRNG, sids [][]byte) (participants []*interactiveSigning.Cosigner, err error) {
	if len(identities) < int(protocol.Threshold()) {
		return nil, errs.NewArgument("invalid number of identities %d != %d", len(identities), protocol.Threshold())
	}
	if sids != nil && len(sids) != len(identities) {
		return nil, errs.NewLength("invalid number of hardcoded sids %d != %d", len(sids), len(identities))
	}
	if sids == nil { // Create a common sid if no hardcoded sids are provided
		sids = make([][]byte, len(identities))
		sid, err := agreeonrandom_testutils.RunAgreeOnRandom(protocol.Curve(), identities, crand.Reader)
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
		participants[i], err = interactiveSigning.NewCosigner(sids[i], identity.(types.AuthKey), hashset.NewHashableHashSet(identities...), shards[i], protocol, prng, seededPrng, nil)
		if err != nil || participants[i] == nil {
			return nil, errs.WrapFailed(err, "failed to create cosigner")
		}
	}

	return participants, nil
}

func DoInteractiveSignRound1(participants []*interactiveSigning.Cosigner) (round1OutputsBroadcast []*signing.Round1Broadcast, round1OutputsP2P []network.RoundMessages[*signing.Round1P2P], err error) {
	round1OutputsBroadcast = make([]*signing.Round1Broadcast, len(participants))
	round1OutputsP2P = make([]network.RoundMessages[*signing.Round1P2P], len(participants))
	for i, participant := range participants {
		round1OutputsBroadcast[i], round1OutputsP2P[i], err = participant.Round1()
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "failed to run round 1 of DKLs24 signing")
		}
	}

	return round1OutputsBroadcast, round1OutputsP2P, nil
}

func DoInteractiveSignRound2(participants []*interactiveSigning.Cosigner, round2BroadcastInputs []network.RoundMessages[*signing.Round1Broadcast], round2UnicastInputs []network.RoundMessages[*signing.Round1P2P]) (round2BroadcastOutputs []*signing.Round2Broadcast, round2UnicastOutputs []network.RoundMessages[*signing.Round2P2P], err error) {
	round2BroadcastOutputs = make([]*signing.Round2Broadcast, len(participants))
	round2UnicastOutputs = make([]network.RoundMessages[*signing.Round2P2P], len(participants))
	for i := range participants {
		round2BroadcastOutputs[i], round2UnicastOutputs[i], err = participants[i].Round2(round2BroadcastInputs[i], round2UnicastInputs[i])
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "failed to run round 2 of DKLs24 signing")
		}
	}
	return round2BroadcastOutputs, round2UnicastOutputs, nil
}

func DoInteractiveSignRound3(participants []*interactiveSigning.Cosigner, round3BroadcastInputs []network.RoundMessages[*signing.Round2Broadcast], round3UnicastInputs []network.RoundMessages[*signing.Round2P2P], message []byte) (partialSignatures []*dkls24.PartialSignature, err error) {
	partialSignatures = make([]*dkls24.PartialSignature, len(participants))
	for i := range participants {
		partialSignatures[i], err = participants[i].Round3(round3BroadcastInputs[i], round3UnicastInputs[i], message)
		if err != nil {
			return nil, errs.WrapFailed(err, "failed to run round 3 of DKLs24 signing")
		}
	}

	return partialSignatures, nil
}

func MapPartialSignatures(identities []types.IdentityKey, partialSignatures []*dkls24.PartialSignature) network.RoundMessages[*dkls24.PartialSignature] {
	result := network.NewRoundMessages[*dkls24.PartialSignature]()
	for i, identity := range identities {
		result.Put(identity, partialSignatures[i])
	}
	return result
}

func RunSignatureAggregation(protocol types.ThresholdSignatureProtocol, identities []types.IdentityKey, participants []*interactiveSigning.Cosigner, partialSignatures []*dkls24.PartialSignature, message []byte) (producedSignatures []*ecdsa.Signature, err error) {
	mappedPartialSignatures := MapPartialSignatures(identities, partialSignatures)
	producedSignatures = make([]*ecdsa.Signature, len(participants))
	for i, participant := range participants {
		signature, err := signing.Aggregate(participant.Protocol.CipherSuite(), participant.Shard().SigningKeyShare.PublicKey, mappedPartialSignatures, message)
		if err != nil {
			return nil, errs.WrapFailed(err, "failed to aggregate signature")
		}

		if err := ecdsa.Verify(signature, protocol.CipherSuite().Hash(), participant.Shard().SigningKeyShare.PublicKey, message); err != nil {
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

func RunInteractiveSign(protocol types.ThresholdSignatureProtocol, identities []types.IdentityKey, shards []*dkls24.Shard, message []byte, seededPrng csprng.CSPRNG, sids [][]byte) error {
	participants, err := MakeInteractiveCosigners(protocol, identities, shards, nil, seededPrng, sids)
	if err != nil {
		return errs.WrapFailed(err, "failed to make interactive cosigners")
	}

	r1OutB, r1OutU, err := DoInteractiveSignRound1(participants)
	if err != nil {
		return errs.WrapFailed(err, "failed to run round 1 of DKLs24 signing")
	}
	r2InB, r2InU := ttu.MapO2I(participants, r1OutB, r1OutU)
	r2OutB, r2OutU, err := DoInteractiveSignRound2(participants, r2InB, r2InU)
	if err != nil {
		return errs.WrapFailed(err, "failed to run round 2 of DKLs24 signing")
	}
	r3InB, r3InU := ttu.MapO2I(participants, r2OutB, r2OutU)
	partialSignatures, err := DoInteractiveSignRound3(participants, r3InB, r3InU, message)
	if err != nil {
		return errs.WrapFailed(err, "failed to run round 3 of DKLs24 signing")
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
