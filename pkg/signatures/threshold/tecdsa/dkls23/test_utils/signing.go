package test_utils

import (
	crand "crypto/rand"
	"io"

	"github.com/pkg/errors"

	agreeonrandom_test_utils "github.com/copperexchange/knox-primitives/pkg/agreeonrandom/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/signatures/ecdsa"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/dkls23"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/dkls23/signing/interactive"
)

func MakeInteractiveCosigners(cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, shards []*dkls23.Shard, prngs []io.Reader) (participants []*interactive.Cosigner, err error) {
	if len(identities) < cohortConfig.Threshold {
		return nil, errors.Errorf("invalid number of identities %d != %d", len(identities), cohortConfig.Threshold)
	}
	sid, err := agreeonrandom_test_utils.ProduceSharedRandomValue(cohortConfig.CipherSuite.Curve, identities)
	if err != nil {
		return nil, err
	}

	participants = make([]*interactive.Cosigner, cohortConfig.Threshold)
	for i, identity := range identities {
		var prng io.Reader
		if len(prngs) != 0 && prngs[i] != nil {
			prng = prngs[i]
		} else {
			prng = crand.Reader
		}

		if !cohortConfig.IsInCohort(identity) {
			return nil, errors.New("invalid identity")
		}
		// TODO: test for what happens if session participants are set to be different for different parties
		participants[i], err = interactive.NewCosigner(sid, identity, identities, shards[i], cohortConfig, prng, nil)
		if err != nil {
			return nil, err
		}
	}

	return participants, nil
}

func DoInteractiveSignRound1(participants []*interactive.Cosigner) (round1OutputsBroadcast []*interactive.Round1Broadcast, round1OutputsP2P []map[integration.IdentityKey]*interactive.Round1P2P, err error) {
	round1OutputsBroadcast = make([]*interactive.Round1Broadcast, len(participants))
	round1OutputsP2P = make([]map[integration.IdentityKey]*interactive.Round1P2P, len(participants))
	for i, participant := range participants {
		round1OutputsBroadcast[i], round1OutputsP2P[i], err = participant.Round1()
		if err != nil {
			return nil, nil, err
		}
	}

	return round1OutputsBroadcast, round1OutputsP2P, nil
}

func MapInteractiveSignRound1OutputsToRound2Inputs(participants []*interactive.Cosigner, round1BroadcastOutputs []*interactive.Round1Broadcast, round1UnicastOutputs []map[integration.IdentityKey]*interactive.Round1P2P) (round2BroadcastInputs []map[integration.IdentityKey]*interactive.Round1Broadcast, round2UnicastInputs []map[integration.IdentityKey]*interactive.Round1P2P) {
	round2BroadcastInputs = make([]map[integration.IdentityKey]*interactive.Round1Broadcast, len(participants))
	for i := range participants {
		round2BroadcastInputs[i] = make(map[integration.IdentityKey]*interactive.Round1Broadcast)
		for j := range participants {
			if j != i {
				round2BroadcastInputs[i][participants[j].GetIdentityKey()] = round1BroadcastOutputs[j]
			}
		}
	}

	round2UnicastInputs = make([]map[integration.IdentityKey]*interactive.Round1P2P, len(participants))
	for i := range participants {
		round2UnicastInputs[i] = make(map[integration.IdentityKey]*interactive.Round1P2P)
		for j := range participants {
			if j != i {
				round2UnicastInputs[i][participants[j].GetIdentityKey()] = round1UnicastOutputs[j][participants[i].GetIdentityKey()]
			}
		}
	}

	return round2BroadcastInputs, round2UnicastInputs
}

func DoInteractiveSignRound2(participants []*interactive.Cosigner, round2BroadcastInputs []map[integration.IdentityKey]*interactive.Round1Broadcast, round2UnicastInputs []map[integration.IdentityKey]*interactive.Round1P2P) (round2BroadcastOutputs []*interactive.Round2Broadcast, round2UnicastOutputs []map[integration.IdentityKey]*interactive.Round2P2P, err error) {
	round2BroadcastOutputs = make([]*interactive.Round2Broadcast, len(participants))
	round2UnicastOutputs = make([]map[integration.IdentityKey]*interactive.Round2P2P, len(participants))
	for i := range participants {
		round2BroadcastOutputs[i], round2UnicastOutputs[i], err = participants[i].Round2(round2BroadcastInputs[i], round2UnicastInputs[i])
		if err != nil {
			return nil, nil, err
		}
	}
	return round2BroadcastOutputs, round2UnicastOutputs, nil
}

func MapInteractiveSignRound2OutputsToRound3Inputs(participants []*interactive.Cosigner, round2BroadcastOutputs []*interactive.Round2Broadcast, round2UnicastOutputs []map[integration.IdentityKey]*interactive.Round2P2P) (round3BroadcastInputs []map[integration.IdentityKey]*interactive.Round2Broadcast, round3UnicastInputs []map[integration.IdentityKey]*interactive.Round2P2P) {
	round3BroadcastInputs = make([]map[integration.IdentityKey]*interactive.Round2Broadcast, len(participants))
	for i := range participants {
		round3BroadcastInputs[i] = make(map[integration.IdentityKey]*interactive.Round2Broadcast)
		for j := range participants {
			if j != i {
				round3BroadcastInputs[i][participants[j].GetIdentityKey()] = round2BroadcastOutputs[j]
			}
		}
	}
	round3UnicastInputs = make([]map[integration.IdentityKey]*interactive.Round2P2P, len(participants))
	for i := range participants {
		round3UnicastInputs[i] = make(map[integration.IdentityKey]*interactive.Round2P2P)
		for j := range participants {
			if j != i {
				round3UnicastInputs[i][participants[j].GetIdentityKey()] = round2UnicastOutputs[j][participants[i].GetIdentityKey()]
			}
		}
	}

	return round3BroadcastInputs, round3UnicastInputs
}

func DoInteractiveSignRound3(participants []*interactive.Cosigner, round3BroadcastInputs []map[integration.IdentityKey]*interactive.Round2Broadcast, round3UnicastInputs []map[integration.IdentityKey]*interactive.Round2P2P, message []byte) (partialSignatures []*dkls23.PartialSignature, err error) {
	partialSignatures = make([]*dkls23.PartialSignature, len(participants))
	for i := range participants {
		partialSignatures[i], err = participants[i].Round3(round3BroadcastInputs[i], round3UnicastInputs[i], message)
		if err != nil {
			return nil, err
		}
	}

	return partialSignatures, nil
}

func MapPartialSignatures(identities []integration.IdentityKey, partialSignatures []*dkls23.PartialSignature) map[integration.IdentityKey]*dkls23.PartialSignature {
	result := make(map[integration.IdentityKey]*dkls23.PartialSignature)
	for i, identity := range identities {
		result[identity] = partialSignatures[i]
	}
	return result
}

func RunInteractiveSign(cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, shards []*dkls23.Shard, message []byte) error {
	participants, err := MakeInteractiveCosigners(cohortConfig, identities, shards, nil)
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
		signature, err := interactive.Aggregate(participant.CohortConfig.CipherSuite, participant.Shard.SigningKeyShare.PublicKey, mappedPartialSignatures, message)
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
