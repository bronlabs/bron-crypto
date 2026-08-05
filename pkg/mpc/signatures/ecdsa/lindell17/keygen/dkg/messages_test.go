package dkg_test

import (
	"maps"
	"slices"
	"testing"

	"github.com/bronlabs/errs-go/errs"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/mpc/dkg/trusteddealer"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/threshold"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/lindell17/keygen/dkg"
	"github.com/bronlabs/bron-crypto/pkg/network"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/proofs"
	paillierrange "github.com/bronlabs/bron-crypto/pkg/proofs/paillier/range"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
)

type nestedProofParticipant = dkg.Participant[*k256.Point, *k256.BaseFieldElement, *k256.Scalar]

//nolint:paralleltest // Subtests share participants whose protocol rounds advance sequentially.
func TestLindell17DKGRejectsMalformedNestedProofFields(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	shareholders := sharing.NewOrdinalShareholderSet(2)
	accessStructure, err := threshold.NewThresholdAccessStructure(2, shareholders)
	require.NoError(t, err)
	baseShards, err := trusteddealer.Deal(curve, accessStructure, pcg.NewRandomised())
	require.NoError(t, err)
	contexts := session_testutils.MakeRandomContexts(t, shareholders, pcg.NewRandomised())

	ids := []sharing.ID{1, 2}
	participants := make(map[sharing.ID]*nestedProofParticipant, len(ids))
	participantList := make([]*nestedProofParticipant, 0, len(ids))
	for _, id := range ids {
		baseShard, ok := baseShards.Get(id)
		require.True(t, ok)
		participant, err := dkg.NewParticipant(
			contexts[id],
			baseShard,
			1024,
			curve,
			pcg.NewRandomised(),
			fiatshamir.Name,
		)
		require.NoError(t, err)
		participants[id] = participant
		participantList = append(participantList, participant)
	}

	round1Outputs := make(map[sharing.ID]*dkg.Round1Broadcast[*k256.Point, *k256.BaseFieldElement, *k256.Scalar], len(ids))
	for _, id := range ids {
		round1Outputs[id], err = participants[id].Round1()
		require.NoError(t, err)
	}
	round2Inputs := ntu.MapBroadcastO2I(t, participantList, round1Outputs)
	round2Outputs := make(map[sharing.ID]*dkg.Round2Broadcast[*k256.Point, *k256.BaseFieldElement, *k256.Scalar], len(ids))
	for _, id := range ids {
		round2Outputs[id], err = participants[id].Round2(round2Inputs[id])
		require.NoError(t, err)
	}
	round3Inputs := ntu.MapBroadcastO2I(t, participantList, round2Outputs)
	round3Outputs := make(map[sharing.ID]*dkg.Round3Broadcast[*k256.Point, *k256.BaseFieldElement, *k256.Scalar], len(ids))
	for _, id := range ids {
		round3Outputs[id], err = participants[id].Round3(round3Inputs[id])
		require.NoError(t, err)
	}
	round4Inputs := ntu.MapBroadcastO2I(t, participantList, round3Outputs)
	round4Outputs := make(map[sharing.ID]network.OutgoingUnicasts[*dkg.Round4P2P[*k256.Point, *k256.BaseFieldElement, *k256.Scalar], *nestedProofParticipant], len(ids))
	for _, id := range ids {
		round4Outputs[id], err = participants[id].Round4(round4Inputs[id])
		require.NoError(t, err)
	}
	round5Inputs := ntu.MapUnicastO2I(t, participantList, round4Outputs)

	const victim, sender sharing.ID = 1, 2
	validRound4, ok := round5Inputs[victim].Get(sender)
	require.True(t, ok)
	otherDirectionRound4, ok := round5Inputs[sender].Get(victim)
	require.True(t, ok)

	t.Run("LP statement with nil group element", func(t *testing.T) {
		tampered := *validRound4
		lpOutput := *validRound4.LpRound1Output
		lpOutput.X = slices.Clone(lpOutput.X)
		statement := *lpOutput.X[0]
		statement.X = nil
		lpOutput.X[0] = &statement
		tampered.LpRound1Output = &lpOutput

		requireNestedProofDeserializationError(t, &tampered)
	})

	t.Run("LP commitment with nil group element", func(t *testing.T) {
		tampered := *validRound4
		lpOutput := *validRound4.LpRound1Output
		lpOutput.NthRootsProverOutput = slices.Clone(lpOutput.NthRootsProverOutput)
		commitment := *lpOutput.NthRootsProverOutput[0]
		commitment.A = nil
		lpOutput.NthRootsProverOutput[0] = &commitment
		tampered.LpRound1Output = &lpOutput

		requireNestedProofDeserializationError(t, &tampered)
	})

	t.Run("LPDL ciphertext from wrong Paillier group", func(t *testing.T) {
		tampered := *validRound4
		tampered.Components = slices.Clone(validRound4.Components)
		component := *tampered.Components[0]
		lpdlOutput := *component.LpdlPrimeRound1Output
		lpdlOutput.CPrime = otherDirectionRound4.Components[0].LpdlPrimeRound1Output.CPrime
		component.LpdlPrimeRound1Output = &lpdlOutput
		tampered.Components[0] = &component
		wireMessage := ntu.CBORRoundTrip(t, &tampered)

		requireNestedProofValidationError(t, func() error {
			_, err := participants[victim].Round5(singletonNestedProofMessage(sender, wireMessage))
			return err
		})
	})

	round5Outputs := make(map[sharing.ID]network.OutgoingUnicasts[*dkg.Round5P2P[*k256.Point, *k256.BaseFieldElement, *k256.Scalar], *nestedProofParticipant], len(ids))
	for _, id := range ids {
		round5Outputs[id], err = participants[id].Round5(round5Inputs[id])
		require.NoError(t, err)
	}
	round6Inputs := ntu.MapUnicastO2I(t, participantList, round5Outputs)
	validRound5, ok := round6Inputs[victim].Get(sender)
	require.True(t, ok)

	for _, tc := range []struct {
		name       string
		doublePart bool
	}{
		{name: "LPDL range commitment with nil C1", doublePart: false},
		{name: "LPDL range commitment with nil C2", doublePart: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tampered := *validRound5
			tampered.Components = slices.Clone(validRound5.Components)
			component := *tampered.Components[0]
			lpdlOutput := *component.LpdlPrimeRound2Output
			rangeCommitment := *lpdlOutput.RangeProverOutput
			if tc.doublePart {
				rangeCommitment.C2 = slices.Clone(rangeCommitment.C2)
				rangeCommitment.C2[0] = nil
			} else {
				rangeCommitment.C1 = slices.Clone(rangeCommitment.C1)
				rangeCommitment.C1[0] = nil
			}
			lpdlOutput.RangeProverOutput = &rangeCommitment
			component.LpdlPrimeRound2Output = &lpdlOutput
			tampered.Components[0] = &component
			wireMessage := ntu.CBORRoundTrip(t, &tampered)

			requireNestedProofValidationError(t, func() error {
				_, err := participants[victim].Round6(singletonNestedProofMessage(sender, wireMessage))
				return err
			})
		})
	}

	round6Outputs := make(map[sharing.ID]network.OutgoingUnicasts[*dkg.Round6P2P[*k256.Point, *k256.BaseFieldElement, *k256.Scalar], *nestedProofParticipant], len(ids))
	for _, id := range ids {
		round6Outputs[id], err = participants[id].Round6(round6Inputs[id])
		require.NoError(t, err)
	}
	round7Inputs := ntu.MapUnicastO2I(t, participantList, round6Outputs)
	validRound6, ok := round7Inputs[victim].Get(sender)
	require.True(t, ok)

	t.Run("LP response with nil group element", func(t *testing.T) {
		tampered := *validRound6
		lpOutput := *validRound6.LpRound3Output
		lpOutput.NthRootsProverOutput = slices.Clone(lpOutput.NthRootsProverOutput)
		response := *lpOutput.NthRootsProverOutput[0]
		response.Z = nil
		lpOutput.NthRootsProverOutput[0] = &response
		tampered.LpRound3Output = &lpOutput

		requireNestedProofDeserializationError(t, &tampered)
	})

	round7Outputs := make(map[sharing.ID]network.OutgoingUnicasts[*dkg.Round7P2P[*k256.Point, *k256.BaseFieldElement, *k256.Scalar], *nestedProofParticipant], len(ids))
	for _, id := range ids {
		round7Outputs[id], err = participants[id].Round7(round7Inputs[id])
		require.NoError(t, err)
	}
	round8Inputs := ntu.MapUnicastO2I(t, participantList, round7Outputs)
	validRound7, ok := round8Inputs[victim].Get(sender)
	require.True(t, ok)

	t.Run("LPDL range response with nil plaintext", func(t *testing.T) {
		tampered := *validRound7
		tampered.Components = slices.Clone(validRound7.Components)
		component := *tampered.Components[0]
		lpdlOutput := *component.LpdlPrimeRound4Output
		response := cloneRangeResponse(lpdlOutput.RangeProverOutput)
		mutated := false
		for i := range response.W1 {
			response.W1[i] = nil
			mutated = true
			break
		}
		if !mutated {
			for i := range response.Wj {
				response.Wj[i] = nil
				mutated = true
				break
			}
		}
		require.True(t, mutated)
		lpdlOutput.RangeProverOutput = response
		component.LpdlPrimeRound4Output = &lpdlOutput
		tampered.Components[0] = &component
		wireMessage := ntu.CBORRoundTrip(t, &tampered)

		requireNestedProofValidationError(t, func() error {
			_, err := participants[victim].Round8(singletonNestedProofMessage(sender, wireMessage))
			return err
		})
	})

	t.Run("LPDL range response with nil nonce", func(t *testing.T) {
		tampered := *validRound7
		tampered.Components = slices.Clone(validRound7.Components)
		component := *tampered.Components[0]
		lpdlOutput := *component.LpdlPrimeRound4Output
		response := cloneRangeResponse(lpdlOutput.RangeProverOutput)
		mutated := false
		for i := range response.R1 {
			response.R1[i] = nil
			mutated = true
			break
		}
		if !mutated {
			for i := range response.Rj {
				response.Rj[i] = nil
				mutated = true
				break
			}
		}
		require.True(t, mutated)
		lpdlOutput.RangeProverOutput = response
		component.LpdlPrimeRound4Output = &lpdlOutput
		tampered.Components[0] = &component
		wireMessage := ntu.CBORRoundTrip(t, &tampered)

		requireNestedProofValidationError(t, func() error {
			_, err := participants[victim].Round8(singletonNestedProofMessage(sender, wireMessage))
			return err
		})
	})

	t.Run("LPDL range response with inconsistent map keys", func(t *testing.T) {
		tampered := *validRound7
		tampered.Components = slices.Clone(validRound7.Components)
		component := *tampered.Components[0]
		lpdlOutput := *component.LpdlPrimeRound4Output
		response := cloneRangeResponse(lpdlOutput.RangeProverOutput)
		mutated := false
		for i := range response.R1 {
			delete(response.R1, i)
			mutated = true
			break
		}
		if !mutated {
			for i := range response.Rj {
				delete(response.Rj, i)
				mutated = true
				break
			}
		}
		require.True(t, mutated)
		lpdlOutput.RangeProverOutput = response
		component.LpdlPrimeRound4Output = &lpdlOutput
		tampered.Components[0] = &component
		wireMessage := ntu.CBORRoundTrip(t, &tampered)

		requireNestedProofValidationError(t, func() error {
			_, err := participants[victim].Round8(singletonNestedProofMessage(sender, wireMessage))
			return err
		})
	})

	for _, id := range ids {
		_, err = participants[id].Round8(round8Inputs[id])
		require.NoError(t, err)
	}
}

func singletonNestedProofMessage[M network.Message[*nestedProofParticipant]](sender sharing.ID, message M) network.RoundMessages[M, *nestedProofParticipant] {
	messages := hashmap.NewComparable[sharing.ID, M]()
	messages.Put(sender, message)
	return messages.Freeze()
}

func requireNestedProofValidationError(t *testing.T, run func() error) {
	t.Helper()
	var err error
	require.NotPanics(t, func() {
		err = run()
	})
	require.Error(t, err)
	require.True(t, errs.Is(err, dkg.ErrValidation), "expected wrapped DKG validation error, got: %v", err)
}

func requireNestedProofDeserializationError[T any](t *testing.T, message T) {
	t.Helper()

	data, err := serde.MarshalCBOR(message)
	require.NoError(t, err)
	_, err = serde.UnmarshalCBOR[T](data)
	require.True(t, errs.Is(err, proofs.ErrInvalidArgument), "expected invalid proof deserialisation error, got: %v", err)
}

func cloneRangeResponse(response *paillierrange.Response) *paillierrange.Response {
	clone := *response
	clone.W1 = maps.Clone(response.W1)
	clone.R1 = maps.Clone(response.R1)
	clone.W2 = maps.Clone(response.W2)
	clone.R2 = maps.Clone(response.R2)
	clone.Wj = maps.Clone(response.Wj)
	clone.Rj = maps.Clone(response.Rj)
	clone.J = maps.Clone(response.J)
	return &clone
}
