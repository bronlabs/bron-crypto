package testutils

import (
	crand "crypto/rand"
	"io"

	"github.com/pkg/errors"

	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/csprng"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/ecdsa"
	agreeonrandom_testutils "github.com/copperexchange/krypton-primitives/pkg/threshold/agreeonrandom/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls23"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls23/signing"
)

func MakeInteractiveCosigners(cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, shards []*dkls23.Shard, tprngs []io.Reader, seededPrng csprng.CSPRNG) (participants []*signing.Cosigner, err error) {
	if len(identities) < cohortConfig.Protocol.Threshold {
		return nil, errors.Errorf("invalid number of identities %d != %d", len(identities), cohortConfig.Protocol.Threshold)
	}
	sid, err := agreeonrandom_testutils.ProduceSharedRandomValue(cohortConfig.CipherSuite.Curve, identities, crand.Reader)
	if err != nil {
		return nil, err
	}

	participants = make([]*signing.Cosigner, cohortConfig.Protocol.Threshold)
	for i, identity := range identities {
		var prng io.Reader
		if len(tprngs) != 0 && tprngs[i] != nil {
			prng = tprngs[i]
		} else {
			prng = crand.Reader
		}

		if !cohortConfig.IsInCohort(identity) {
			return nil, errors.New("invalid identity")
		}
		// TODO: test for what happens if session participants are set to be different for different parties
		participants[i], err = signing.NewCosigner(sid, identity, hashset.NewHashSet(identities), shards[i], cohortConfig, prng, seededPrng, nil)
		if err != nil {
			return nil, err
		}
	}

	return participants, nil
}

func DoInteractiveSignRound1(participants []*signing.Cosigner) (round1OutputsBroadcast []*signing.Round1Broadcast, round1OutputsP2P []map[types.IdentityHash]*signing.Round1P2P, err error) {
	round1OutputsBroadcast = make([]*signing.Round1Broadcast, len(participants))
	round1OutputsP2P = make([]map[types.IdentityHash]*signing.Round1P2P, len(participants))
	for i, participant := range participants {
		round1OutputsBroadcast[i], round1OutputsP2P[i], err = participant.Round1()
		if err != nil {
			return nil, nil, err
		}
	}

	return round1OutputsBroadcast, round1OutputsP2P, nil
}

func MapInteractiveSignRound1OutputsToRound2Inputs(participants []*signing.Cosigner, round1BroadcastOutputs []*signing.Round1Broadcast, round1UnicastOutputs []map[types.IdentityHash]*signing.Round1P2P) (round2BroadcastInputs []map[types.IdentityHash]*signing.Round1Broadcast, round2UnicastInputs []map[types.IdentityHash]*signing.Round1P2P) {
	round2BroadcastInputs = make([]map[types.IdentityHash]*signing.Round1Broadcast, len(participants))
	for i := range participants {
		round2BroadcastInputs[i] = make(map[types.IdentityHash]*signing.Round1Broadcast)
		for j := range participants {
			if j != i {
				round2BroadcastInputs[i][participants[j].GetIdentityKey().Hash()] = round1BroadcastOutputs[j]
			}
		}
	}

	round2UnicastInputs = make([]map[types.IdentityHash]*signing.Round1P2P, len(participants))
	for i := range participants {
		round2UnicastInputs[i] = make(map[types.IdentityHash]*signing.Round1P2P)
		for j := range participants {
			if j != i {
				round2UnicastInputs[i][participants[j].GetIdentityKey().Hash()] = round1UnicastOutputs[j][participants[i].GetIdentityKey().Hash()]
			}
		}
	}

	return round2BroadcastInputs, round2UnicastInputs
}

func DoInteractiveSignRound2(participants []*signing.Cosigner, round2BroadcastInputs []map[types.IdentityHash]*signing.Round1Broadcast, round2UnicastInputs []map[types.IdentityHash]*signing.Round1P2P) (round2BroadcastOutputs []*signing.Round2Broadcast, round2UnicastOutputs []map[types.IdentityHash]*signing.Round2P2P, err error) {
	round2BroadcastOutputs = make([]*signing.Round2Broadcast, len(participants))
	round2UnicastOutputs = make([]map[types.IdentityHash]*signing.Round2P2P, len(participants))
	for i := range participants {
		round2BroadcastOutputs[i], round2UnicastOutputs[i], err = participants[i].Round2(round2BroadcastInputs[i], round2UnicastInputs[i])
		if err != nil {
			return nil, nil, err
		}
	}
	return round2BroadcastOutputs, round2UnicastOutputs, nil
}

func MapInteractiveSignRound2OutputsToRound3Inputs(participants []*signing.Cosigner, round2BroadcastOutputs []*signing.Round2Broadcast, round2UnicastOutputs []map[types.IdentityHash]*signing.Round2P2P) (round3BroadcastInputs []map[types.IdentityHash]*signing.Round2Broadcast, round3UnicastInputs []map[types.IdentityHash]*signing.Round2P2P) {
	round3BroadcastInputs = make([]map[types.IdentityHash]*signing.Round2Broadcast, len(participants))
	for i := range participants {
		round3BroadcastInputs[i] = make(map[types.IdentityHash]*signing.Round2Broadcast)
		for j := range participants {
			if j != i {
				round3BroadcastInputs[i][participants[j].GetIdentityKey().Hash()] = round2BroadcastOutputs[j]
			}
		}
	}
	round3UnicastInputs = make([]map[types.IdentityHash]*signing.Round2P2P, len(participants))
	for i := range participants {
		round3UnicastInputs[i] = make(map[types.IdentityHash]*signing.Round2P2P)
		for j := range participants {
			if j != i {
				round3UnicastInputs[i][participants[j].GetIdentityKey().Hash()] = round2UnicastOutputs[j][participants[i].GetIdentityKey().Hash()]
			}
		}
	}

	return round3BroadcastInputs, round3UnicastInputs
}

func DoInteractiveSignRound3(participants []*signing.Cosigner, round3BroadcastInputs []map[types.IdentityHash]*signing.Round2Broadcast, round3UnicastInputs []map[types.IdentityHash]*signing.Round2P2P, message []byte) (partialSignatures []*dkls23.PartialSignature, err error) {
	partialSignatures = make([]*dkls23.PartialSignature, len(participants))
	for i := range participants {
		partialSignatures[i], err = participants[i].Round3(round3BroadcastInputs[i], round3UnicastInputs[i], message)
		if err != nil {
			return nil, err
		}
	}

	return partialSignatures, nil
}

func MapPartialSignatures(identities []integration.IdentityKey, partialSignatures []*dkls23.PartialSignature) map[types.IdentityHash]*dkls23.PartialSignature {
	result := make(map[types.IdentityHash]*dkls23.PartialSignature)
	for i, identity := range identities {
		result[identity.Hash()] = partialSignatures[i]
	}
	return result
}

func RunInteractiveSign(cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, shards []*dkls23.Shard, message []byte, seededPrng csprng.CSPRNG) error {
	participants, err := MakeInteractiveCosigners(cohortConfig, identities, shards, nil, seededPrng)
	if err != nil {
		return err
	}
	for _, participant := range participants {
		if participant == nil {
			return errs.NewFailed("nil participant")
		}
	}

	r1OutB, r1OutU, err := DoInteractiveSignRound1(participants)
	if err != nil {
		return err
	}

	r2InB, r2InU := MapInteractiveSignRound1OutputsToRound2Inputs(participants, r1OutB, r1OutU)
	r2OutB, r2OutU, err := DoInteractiveSignRound2(participants, r2InB, r2InU)
	if err != nil {
		return err
	}

	r3InB, r3InU := MapInteractiveSignRound2OutputsToRound3Inputs(participants, r2OutB, r2OutU)
	partialSignatures, err := DoInteractiveSignRound3(participants, r3InB, r3InU, message)
	if err != nil {
		return err
	}

	mappedPartialSignatures := MapPartialSignatures(identities, partialSignatures)
	var producedSignatures []*ecdsa.Signature
	for _, participant := range participants {
		// TODO: test for signature aggregator
		if !cohortConfig.IsSignatureAggregator(participant.MyIdentityKey) {
			continue
		}
		signature, err := signing.Aggregate(participant.CohortConfig.CipherSuite, participant.Shard.SigningKeyShare.PublicKey, mappedPartialSignatures, message)
		producedSignatures = append(producedSignatures, signature)
		if err != nil {
			return err
		}
		err = ecdsa.Verify(signature, cohortConfig.CipherSuite.Hash, participant.Shard.SigningKeyShare.PublicKey, message)
		if err != nil {
			return err
		}
	}

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
