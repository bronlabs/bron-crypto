package gennaro_test

import (
	"crypto/sha3"
	"fmt"
	"io"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	pedcom "github.com/bronlabs/bron-crypto/pkg/commitments/pedersen"
	"github.com/bronlabs/bron-crypto/pkg/network"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/dkg/gennaro"
	tu "github.com/bronlabs/bron-crypto/pkg/threshold/dkg/gennaro/testutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/scheme/feldman"
	pedersenVSS "github.com/bronlabs/bron-crypto/pkg/threshold/sharing/scheme/pedersen"
	ts "github.com/bronlabs/bron-crypto/pkg/transcripts"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
)

func setup[
	E gennaro.GroupElement[E, S], S gennaro.Scalar[S],
](
	t *testing.T, threshold, total uint, group gennaro.Group[E, S], sid network.SID, tape ts.Transcript, prng io.Reader,
) (
	ac *sharing.ThresholdAccessStructure,
	parties ds.MutableMap[sharing.ID, *gennaro.Participant[E, S]],
) {
	t.Helper()
	shareholders := sharing.NewOrdinalShareholderSet(total)
	ac, err := sharing.NewThresholdAccessStructure(threshold, shareholders)
	require.NoError(t, err)
	require.NotNil(t, group)
	if ct.SliceIsZero(sid[:]) == 1 {
		sid = sha3.Sum256([]byte("test-sid"))
	}
	if tape == nil {
		tape = hagrid.NewTranscript("test")
	}
	if prng == nil {
		prng = pcg.New(0, 0)
	}

	parties = hashmap.NewComparable[sharing.ID, *gennaro.Participant[E, S]]()
	for id := range shareholders.Iter() {
		p, err := gennaro.NewParticipant(
			sid,
			group,
			id,
			ac,
			fiatshamir.Name,
			tape.Clone(),
			prng,
		)
		require.NoError(t, err)
		parties.Put(id, p)
	}
	return ac, parties
}

// TestDKGWithVariousThresholds tests DKG with different threshold configurations
func TestDKGWithVariousThresholds(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		threshold uint
		total     uint
	}{
		{"minimal 2-of-3", 2, 3},
		{"standard 3-of-5", 3, 5},
		{"unanimous 4-of-4", 4, 4},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			group := k256.NewCurve()
			sid := network.SID(sha3.Sum256([]byte(fmt.Sprintf("test-threshold-%s", tc.name))))
			tape := hagrid.NewTranscript(tc.name)
			prng := pcg.NewRandomised()

			ac, parties := setup(t, tc.threshold, tc.total, group, sid, tape, prng)

			// Run complete DKG
			outputs, err := tu.DoGennaroDKG(t, parties.Values())
			require.NoError(t, err)
			require.Equal(t, int(tc.total), outputs.Size())

			// Verify all outputs have correct access structure
			for id, output := range outputs.Iter() {
				require.NotNil(t, output.AccessStructure())
				require.Equal(t, tc.threshold, output.AccessStructure().Threshold())
				require.Equal(t, int(tc.total), output.AccessStructure().Shareholders().Size())
				require.Equal(t, id, output.Share().ID())
			}

			// Collect shares and verify reconstruction
			shares := make([]*feldman.Share[*k256.Scalar], 0, tc.total)
			var referenceVV feldman.VerificationVector[*k256.Point, *k256.Scalar]

			for _, output := range outputs.Values() {
				shares = append(shares, output.Share())
				if referenceVV == nil {
					referenceVV = output.VerificationVector()
				} else {
					// All participants should have same verification vector
					require.True(t, referenceVV.Equal(output.VerificationVector()))
				}
			}

			// Create Feldman scheme for reconstruction
			feldmanScheme, err := feldman.NewScheme(group.Generator(), ac)
			require.NoError(t, err)

			// Test reconstruction with all shares
			secret, err := feldmanScheme.ReconstructAndVerify(referenceVV, shares...)
			require.NoError(t, err)
			require.NotNil(t, secret)
			require.False(t, secret.Value().IsZero())

			// Test reconstruction with exactly threshold shares
			if tc.threshold < tc.total {
				thresholdShares := shares[:tc.threshold]
				secretFromThreshold, err := feldmanScheme.ReconstructAndVerify(referenceVV, thresholdShares...)
				require.NoError(t, err)
				require.True(t, secret.Equal(secretFromThreshold))
			}
		})
	}
}

// TestDKGPublicKeyFields tests the new public key fields in DKGOutput
func TestDKGPublicKeyFields(t *testing.T) {
	t.Parallel()

	threshold := uint(2)
	total := uint(3)
	group := k256.NewCurve()
	sid := network.SID(sha3.Sum256([]byte("test-public-key-fields")))
	tape := hagrid.NewTranscript("TestPublicKeyFields")
	prng := pcg.NewRandomised()

	_, parties := setup(t, threshold, total, group, sid, tape, prng)
	outputs, err := tu.DoGennaroDKG(t, parties.Values())
	require.NoError(t, err)

	t.Run("public key consistency", func(t *testing.T) {
		t.Parallel()
		var commonPublicKey *k256.Point
		for id, output := range outputs.Iter() {
			pk := output.PublicKeyValue()
			require.NotNil(t, pk, "participant %d has nil public key", id)
			require.False(t, pk.IsZero(), "participant %d has zero public key", id)

			if commonPublicKey == nil {
				commonPublicKey = pk
			} else {
				require.True(t, commonPublicKey.Equal(pk),
					"participant %d has different public key", id)
			}
		}
	})

	t.Run("partial public keys properties", func(t *testing.T) {
		t.Parallel()
		// Collect all partial public keys
		allPartialPKs := make(map[sharing.ID]map[sharing.ID]*k256.Point)

		for id, output := range outputs.Iter() {
			partialPKs := output.PartialPublicKeyValues()
			require.NotNil(t, partialPKs)
			require.Equal(t, int(total), partialPKs.Size())

			allPartialPKs[id] = make(map[sharing.ID]*k256.Point)
			for pid, ppk := range partialPKs.Iter() {
				require.NotNil(t, ppk)
				require.False(t, ppk.IsZero())
				allPartialPKs[id][pid] = ppk
			}
		}

		// Verify consistency: participant i's partial public key for j should be the same
		// across all participants
		for i := sharing.ID(1); i <= sharing.ID(total); i++ {
			for j := sharing.ID(1); j <= sharing.ID(total); j++ {
				var referencePPK *k256.Point
				for holderID, holderPartialPKs := range allPartialPKs {
					ppk := holderPartialPKs[j]
					if referencePPK == nil {
						referencePPK = ppk
					} else {
						require.True(t, referencePPK.Equal(ppk),
							"inconsistent partial public key for participant %d held by %d", j, holderID)
					}
				}
			}
		}
	})

	t.Run("partial public keys match verification vector evaluations", func(t *testing.T) {
		t.Parallel()
		// Get the common verification vector
		output0 := outputs.Values()[0]
		verificationVector := output0.VerificationVector()
		scalarField := k256.NewScalarField()

		// Check that each partial public key matches the verification vector evaluation
		partialPKMap := output0.PartialPublicKeyValues()
		for id, ppk := range partialPKMap.Iter() {
			// Evaluate verification vector at x = id
			x := scalarField.FromUint64(uint64(id))
			expectedPPK := verificationVector.Eval(x)

			require.True(t, expectedPPK.Equal(ppk),
				"partial public key for id %d doesn't match verification vector evaluation", id)
		}

		// Also verify the public key matches evaluation at x=0
		expectedPublicKey := verificationVector.Eval(scalarField.Zero())
		require.True(t, expectedPublicKey.Equal(output0.PublicKeyValue()),
			"public key doesn't match verification vector evaluation at 0")
	})
}

// TestDKGShareProperties tests properties of shares generated by DKG
func TestDKGShareProperties(t *testing.T) {
	t.Parallel()

	threshold := uint(2)
	total := uint(3)
	group := k256.NewCurve()
	sid := network.SID(sha3.Sum256([]byte("test-share-properties")))
	tape := hagrid.NewTranscript("TestShareProperties")
	prng := pcg.NewRandomised()

	_, parties := setup(t, threshold, total, group, sid, tape, prng)
	outputs, err := tu.DoGennaroDKG(t, parties.Values())
	require.NoError(t, err)

	// Collect all shares
	sharesByID := make(map[sharing.ID]*feldman.Share[*k256.Scalar])
	for id, output := range outputs.Iter() {
		sharesByID[id] = output.Share()
	}

	t.Run("share uniqueness", func(t *testing.T) {
		t.Parallel()
		// Verify all shares have unique values
		shareValues := make(map[string]sharing.ID)
		for id, share := range sharesByID {
			valueStr := share.Value().String()
			if existingID, exists := shareValues[valueStr]; exists {
				t.Fatalf("shares for participants %d and %d have identical values", id, existingID)
			}
			shareValues[valueStr] = id
		}
	})

	t.Run("share IDs match participant IDs", func(t *testing.T) {
		t.Parallel()
		for id, share := range sharesByID {
			require.Equal(t, id, share.ID())
		}
	})

	t.Run("verification vectors consistency", func(t *testing.T) {
		t.Parallel()
		var referenceVV feldman.VerificationVector[*k256.Point, *k256.Scalar]
		for _, output := range outputs.Values() {
			if referenceVV == nil {
				referenceVV = output.VerificationVector()
			} else {
				require.True(t, referenceVV.Equal(output.VerificationVector()),
					"all outputs should have identical verification vectors")
			}
		}
	})

	t.Run("share reconstruction subsets", func(t *testing.T) {
		t.Parallel()
		feldmanAS, err := sharing.NewThresholdAccessStructure(threshold, parties.Values()[0].AccessStructure().Shareholders())
		require.NoError(t, err)
		feldmanScheme, err := feldman.NewScheme(group.Generator(), feldmanAS)
		require.NoError(t, err)

		// Test different combinations of threshold shares
		combinations := [][]sharing.ID{
			{1, 2},
			{1, 3},
			{2, 3},
			{1, 2, 3},
		}

		var reconstructedSecrets []*feldman.Secret[*k256.Scalar]
		referenceVV := outputs.Values()[0].VerificationVector()

		for _, combo := range combinations {
			shares := make([]*feldman.Share[*k256.Scalar], 0, len(combo))
			for _, id := range combo {
				shares = append(shares, sharesByID[id])
			}

			secret, err := feldmanScheme.ReconstructAndVerify(referenceVV, shares...)
			require.NoError(t, err)
			reconstructedSecrets = append(reconstructedSecrets, secret)
		}

		// All reconstructed secrets should be identical
		for i := 1; i < len(reconstructedSecrets); i++ {
			require.True(t, reconstructedSecrets[0].Equal(reconstructedSecrets[i]),
				"all threshold subsets should reconstruct to the same secret")
		}
	})
}

// TestDKGRoundMessages tests the message generation in each round
func TestDKGRoundMessages(t *testing.T) {
	t.Parallel()

	threshold := uint(2)
	total := uint(3)
	group := k256.NewCurve()
	sid := network.SID(sha3.Sum256([]byte("test-round-messages")))
	tape := hagrid.NewTranscript("TestRoundMessages")
	prng := pcg.NewRandomised()

	t.Run("round 1 message properties", func(t *testing.T) {
		t.Parallel()
		_, parties := setup(t, threshold, total, group, sid, tape, prng)

		r1broadcasts, err := tu.DoGennaroRound1(parties.Values())
		require.NoError(t, err)
		require.Len(t, r1broadcasts, int(total))

		// Check each broadcast has a valid Pedersen verification vector
		for i, broadcast := range r1broadcasts {
			require.NotNil(t, broadcast.PedersenVerificationVector)
			// Verify uniqueness
			for j, other := range r1broadcasts {
				if i != j {
					require.False(t, broadcast.PedersenVerificationVector.Equal(other.PedersenVerificationVector))
				}
			}
		}
	})
}

// TestDKGDeterminism tests that DKG produces consistent results with same randomness
func TestDKGDeterminism(t *testing.T) {
	t.Parallel()

	threshold := uint(2)
	total := uint(3)
	group := k256.NewCurve()
	sid := network.SID(sha3.Sum256([]byte("test-determinism")))
	tape := hagrid.NewTranscript("TestDeterminism")

	// Fixed seed for deterministic randomness
	seed1, seed2 := uint64(42), uint64(1337)

	// First run
	prng1 := pcg.New(seed1, seed2)
	_, parties1 := setup(t, threshold, total, group, sid, tape, prng1)
	outputs1, err := tu.DoGennaroDKG(t, parties1.Values())
	require.NoError(t, err)

	// Second run with same seed
	prng2 := pcg.New(seed1, seed2)
	_, parties2 := setup(t, threshold, total, group, sid, tape, prng2)
	outputs2, err := tu.DoGennaroDKG(t, parties2.Values())
	require.NoError(t, err)

	// Compare outputs
	for id, output1 := range outputs1.Iter() {
		output2, ok := outputs2.Get(id)
		require.True(t, ok)

		// Share values should be identical
		require.True(t, output1.Share().Value().Equal(output2.Share().Value()))

		// Verification vectors should be identical
		require.True(t, output1.VerificationVector().Equal(output2.VerificationVector()))
	}
}

// TestDKGParticipantValidation tests participant validation edge cases
func TestDKGParticipantValidation(t *testing.T) {
	t.Parallel()

	group := k256.NewCurve()
	sid := network.SID(sha3.Sum256([]byte("test-validation")))
	tape := hagrid.NewTranscript("TestValidation")
	prng := pcg.NewRandomised()

	t.Run("participant not in access structure", func(t *testing.T) {
		t.Parallel()
		shareholders := sharing.NewOrdinalShareholderSet(3)
		ac, err := sharing.NewThresholdAccessStructure(2, shareholders)
		require.NoError(t, err)

		// Try to create participant with ID not in shareholders
		_, err = gennaro.NewParticipant(
			sid,
			group,
			sharing.ID(10), // Not in shareholders (1-5)
			ac,
			fiatshamir.Name,
			tape.Clone(),
			prng,
		)
		require.Error(t, err)
		require.ErrorIs(t, err, gennaro.ErrInvalidArgument)
	})

	t.Run("minimum participants", func(t *testing.T) {
		t.Parallel()
		// Test with minimum viable configuration (2-of-2)
		shareholders := sharing.NewOrdinalShareholderSet(2)
		ac, err := sharing.NewThresholdAccessStructure(2, shareholders)
		require.NoError(t, err)

		parties := hashmap.NewComparable[sharing.ID, *gennaro.Participant[*k256.Point, *k256.Scalar]]()
		for id := range shareholders.Iter() {
			p, err := gennaro.NewParticipant(
				sid,
				group,
				id,
				ac,
				fiatshamir.Name,
				tape.Clone(),
				prng,
			)
			require.NoError(t, err)
			parties.Put(id, p)
		}

		// Should be able to complete DKG
		outputs, err := tu.DoGennaroDKG(t, parties.Values())
		require.NoError(t, err)
		require.Equal(t, 2, outputs.Size())
	})
}

// TestParticipantCreation tests various scenarios for creating participants
func TestParticipantCreation(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	sid := network.SID(sha3.Sum256([]byte("test-sid")))
	tape := hagrid.NewTranscript("TestParticipantCreation")
	prng := pcg.New(12345, 67890)

	t.Run("valid participant creation", func(t *testing.T) {
		t.Parallel()
		shareholders := sharing.NewOrdinalShareholderSet(3)
		ac, err := sharing.NewThresholdAccessStructure(2, shareholders)
		require.NoError(t, err)

		p, err := gennaro.NewParticipant(
			sid,
			curve,
			sharing.ID(1),
			ac,
			fiatshamir.Name,
			tape.Clone(),
			prng,
		)
		require.NoError(t, err)
		require.NotNil(t, p)
		require.Equal(t, sharing.ID(1), p.SharingID())
		require.Equal(t, ac, p.AccessStructure())
	})

	t.Run("nil group", func(t *testing.T) {
		t.Parallel()
		shareholders := sharing.NewOrdinalShareholderSet(5)
		ac, err := sharing.NewThresholdAccessStructure(3, shareholders)
		require.NoError(t, err)

		p, err := gennaro.NewParticipant[*k256.Point](
			sid,
			nil,
			sharing.ID(1),
			ac,
			fiatshamir.Name,
			tape.Clone(),
			prng,
		)
		require.Error(t, err)
		require.ErrorIs(t, err, gennaro.ErrInvalidArgument)
		require.Nil(t, p)
	})

	t.Run("nil tape", func(t *testing.T) {
		t.Parallel()
		shareholders := sharing.NewOrdinalShareholderSet(5)
		ac, err := sharing.NewThresholdAccessStructure(3, shareholders)
		require.NoError(t, err)

		p, err := gennaro.NewParticipant(
			sid,
			curve,
			sharing.ID(1),
			ac,
			fiatshamir.Name,
			nil,
			prng,
		)
		require.Error(t, err)
		require.ErrorIs(t, err, gennaro.ErrInvalidArgument)
		require.Nil(t, p)
	})

	t.Run("nil prng", func(t *testing.T) {
		t.Parallel()
		shareholders := sharing.NewOrdinalShareholderSet(5)
		ac, err := sharing.NewThresholdAccessStructure(3, shareholders)
		require.NoError(t, err)

		p, err := gennaro.NewParticipant(
			sid,
			curve,
			sharing.ID(1),
			ac,
			fiatshamir.Name,
			tape.Clone(),
			nil,
		)
		require.Error(t, err)
		require.ErrorIs(t, err, gennaro.ErrInvalidArgument)
		require.Nil(t, p)
	})

	t.Run("nil access structure", func(t *testing.T) {
		t.Parallel()
		p, err := gennaro.NewParticipant(
			sid,
			curve,
			sharing.ID(1),
			nil,
			fiatshamir.Name,
			tape.Clone(),
			prng,
		)
		require.Error(t, err)
		require.ErrorIs(t, err, gennaro.ErrInvalidArgument)
		require.Nil(t, p)
	})

	t.Run("invalid participant ID not in shareholders", func(t *testing.T) {
		t.Parallel()
		shareholders := sharing.NewOrdinalShareholderSet(5)
		ac, err := sharing.NewThresholdAccessStructure(3, shareholders)
		require.NoError(t, err)

		p, err := gennaro.NewParticipant(
			sid,
			curve,
			sharing.ID(10), // ID not in shareholders
			ac,
			fiatshamir.Name,
			tape.Clone(),
			prng,
		)
		require.Error(t, err)
		require.ErrorIs(t, err, gennaro.ErrInvalidArgument)
		require.Nil(t, p)
	})

}

// TestRoundProgression tests the three rounds of Gennaro DKG
func TestRoundProgression(t *testing.T) {
	t.Parallel()

	threshold := uint(2)
	total := uint(3)
	group := k256.NewCurve()
	sid := network.SID(sha3.Sum256([]byte("test-round-progression")))
	tape := hagrid.NewTranscript("TestRoundProgression")
	prng := pcg.NewRandomised()

	t.Run("round 1 broadcasts", func(t *testing.T) {
		t.Parallel()
		_, parties := setup(t, threshold, total, group, sid, tape, prng)
		// Execute round 1 for all participants
		r1broadcasts, err := tu.DoGennaroRound1(parties.Values())
		require.NoError(t, err)
		require.Len(t, r1broadcasts, int(total))

		// Verify each round 1 broadcast
		for id1, broadcast := range r1broadcasts {
			require.NotNil(t, broadcast)
			require.NotNil(t, broadcast.PedersenVerificationVector)

			// Verification vectors should be unique per participant
			for id2, otherBroadcast := range r1broadcasts {
				if id1 != id2 {
					require.False(t, broadcast.PedersenVerificationVector.Equal(otherBroadcast.PedersenVerificationVector),
						"participants %d and %d have identical verification vectors", id1, id2)
				}
			}
		}
	})

	t.Run("round 2 broadcasts and unicasts", func(t *testing.T) {
		t.Parallel()
		_, parties := setup(t, threshold, total, group, sid, tape, prng)
		// Execute round 1
		r1broadcasts, err := tu.DoGennaroRound1(parties.Values())
		require.NoError(t, err)

		// Map round 1 outputs to round 2 inputs
		r2inputs := ntu.MapBroadcastO2I(t, parties.Values(), r1broadcasts)

		// Execute round 2
		r2broadcasts, r2unicasts, err := tu.DoGennaroRound2(parties.Values(), r2inputs)
		require.NoError(t, err)
		require.Len(t, r2broadcasts, int(total))
		require.Len(t, r2unicasts, int(total))

		// Verify round 2 broadcasts (Feldman verification vectors)
		for id1, broadcast := range r2broadcasts {
			require.NotNil(t, broadcast)
			require.NotNil(t, broadcast.FeldmanVerificationVector)

			// Feldman vectors should be unique
			for id2, otherBroadcast := range r2broadcasts {
				if id1 != id2 {
					require.False(t, broadcast.FeldmanVerificationVector.Equal(otherBroadcast.FeldmanVerificationVector),
						"participants %d and %d have identical Feldman verification vectors", id1, id2)
				}
			}
		}

		// Verify round 2 unicasts (Pedersen shares)
		for senderID, unicasts := range r2unicasts {
			// Each participant should send shares to all others
			require.Equal(t, int(total-1), unicasts.Size())

			for receiverID, share := range unicasts.Iter() {
				require.NotNil(t, share)
				require.NotNil(t, share.Share)
				// Verify that participant doesn't send to themselves
				require.NotEqual(t, senderID, receiverID)
			}
		}
	})

	t.Run("round 3 output", func(t *testing.T) {
		t.Parallel()
		_, parties := setup(t, threshold, total, group, sid, tape.Clone(), prng)
		outputs, err := tu.DoGennaroDKG(t, parties.Values())
		require.NoError(t, err)
		require.Equal(t, int(total), outputs.Size())

		// Collect all shares
		shares := make([]*feldman.Share[*k256.Scalar], 0, total)
		var referenceVV feldman.VerificationVector[*k256.Point, *k256.Scalar]

		for id, output := range outputs.Iter() {
			require.NotNil(t, output)
			require.NotNil(t, output.Share())
			require.Equal(t, id, output.Share().ID())

			shares = append(shares, output.Share())

			// All participants should have the same verification vector
			if referenceVV == nil {
				referenceVV = output.VerificationVector()
			} else {
				require.True(t, referenceVV.Equal(output.VerificationVector()),
					"participant %d has different verification vector", id)
			}
		}

		// Verify that shares can reconstruct a valid secret
		feldmanAS, err := sharing.NewThresholdAccessStructure(threshold, parties.Values()[0].AccessStructure().Shareholders())
		require.NoError(t, err)
		feldmanScheme, err := feldman.NewScheme(group.Generator(), feldmanAS)
		require.NoError(t, err)

		secret, err := feldmanScheme.ReconstructAndVerify(referenceVV, shares...)
		require.NoError(t, err)
		require.NotNil(t, secret)
		require.False(t, secret.Value().IsZero())
	})
}

// TestRoundOutOfOrder tests that rounds must be executed in order
func TestRoundOutOfOrder(t *testing.T) {
	t.Parallel()

	threshold := uint(2)
	total := uint(3)
	group := k256.NewCurve()
	sid := network.SID(sha3.Sum256([]byte("test-round-order")))
	tape := hagrid.NewTranscript("TestRoundOutOfOrder")
	prng := pcg.NewRandomised()

	_, parties := setup(t, threshold, total, group, sid, tape, prng)
	participant := parties.Values()[0]

	t.Run("cannot execute round 2 before round 1", func(t *testing.T) { //nolint:paralleltest // false positive.
		// Create dummy round 2 input
		dummyR2Input := hashmap.NewComparable[sharing.ID, *gennaro.Round1Broadcast[*k256.Point, *k256.Scalar]]().Freeze()

		_, _, err := participant.Round2(dummyR2Input)
		require.Error(t, err)
		require.ErrorIs(t, err, gennaro.ErrRound)
	})

	t.Run("cannot execute round 3 before completing previous rounds", func(t *testing.T) { //nolint:paralleltest // false positive.
		// Create dummy round 3 inputs
		dummyR3Broadcast := hashmap.NewComparable[sharing.ID, *gennaro.Round2Broadcast[*k256.Point, *k256.Scalar]]().Freeze()
		dummyR3Unicast := hashmap.NewComparable[sharing.ID, *gennaro.Round2Unicast[*k256.Point, *k256.Scalar]]().Freeze()

		_, err := participant.Round3(dummyR3Broadcast, dummyR3Unicast)
		require.Error(t, err)
		require.ErrorIs(t, err, gennaro.ErrRound)
	})

	t.Run("cannot re-execute round 1", func(t *testing.T) { //nolint:paralleltest // false positive.
		// Execute round 1
		_, err := participant.Round1()
		require.NoError(t, err)

		// Try to execute round 1 again
		_, err = participant.Round1()
		require.Error(t, err)
		require.ErrorIs(t, err, gennaro.ErrRound)
	})
}

// TestMaliciousParticipants tests handling of malicious participants
func TestMaliciousParticipants(t *testing.T) {
	t.Parallel()

	threshold := uint(2)
	total := uint(3)
	group := k256.NewCurve()
	sid := network.SID(sha3.Sum256([]byte("test-malicious")))
	tape := hagrid.NewTranscript("TestMaliciousParticipants")
	prng := pcg.NewRandomised()

	t.Run("invalid Pedersen share in round 2", func(t *testing.T) {
		t.Parallel()
		_, parties := setup(t, threshold, total, group, sid, tape, prng)

		// Execute round 1
		r1broadcasts, err := tu.DoGennaroRound1(parties.Values())
		require.NoError(t, err)
		r2inputs := ntu.MapBroadcastO2I(t, parties.Values(), r1broadcasts)

		// Execute round 2
		r2broadcasts, r2unicasts, err := tu.DoGennaroRound2(parties.Values(), r2inputs)
		require.NoError(t, err)

		// Use deterministic IDs: malicious is ID 1, victim is ID 2
		maliciousID := sharing.ID(1)
		victimID := sharing.ID(2)

		// Get the unicast messages from malicious participant and corrupt the one to the victim
		maliciousUnicasts := hashmap.NewComparable[sharing.ID, *gennaro.Round2Unicast[*k256.Point, *k256.Scalar]]()
		for id, msg := range r2unicasts[maliciousID].Iter() {
			if id == victimID {
				// Corrupt the share by modifying the secret value
				originalShare := msg.Share
				scalarField := k256.NewScalarField()

				// Create a corrupted secret by adding 1 to the original value
				corruptedSecretValue := originalShare.Value().Add(scalarField.One())
				corruptedSecret := pedcom.NewMessage(corruptedSecretValue)

				// Create a new corrupted share with the modified secret but same blinding
				corruptedShare, err := pedersenVSS.NewShare(
					originalShare.ID(),
					corruptedSecret,
					originalShare.Blinding(),
					nil,
				)
				require.NoError(t, err)

				maliciousUnicasts.Put(id, &gennaro.Round2Unicast[*k256.Point, *k256.Scalar]{
					Share: corruptedShare,
				})
			} else {
				maliciousUnicasts.Put(id, msg)
			}
		}
		r2unicasts[maliciousID] = maliciousUnicasts.Freeze()

		// Map round 2 outputs to round 3 inputs
		r3broadcastInputs := ntu.MapBroadcastO2I(t, parties.Values(), r2broadcasts)
		r3unicastInputs := ntu.MapUnicastO2I(t, parties.Values(), r2unicasts)

		// Round 3 should fail for the victim due to verification failure
		for _, participant := range parties.Values() {
			output, err := participant.Round3(r3broadcastInputs[participant.SharingID()], r3unicastInputs[participant.SharingID()])
			if participant.SharingID() == victimID {
				require.Error(t, err)
				require.ErrorIs(t, err, sharing.ErrVerification)
				require.True(t, base.IsIdentifiableAbortError(err))
				culprits := base.GetMaliciousIdentities[sharing.ID](err)
				require.Len(t, culprits, 1)
				require.Contains(t, culprits, maliciousID)
				require.Nil(t, output)
			} else if participant.SharingID() != maliciousID {
				// Other honest participants should succeed
				require.NoError(t, err)
				require.NotNil(t, output)
			}
		}
	})
}

// TestDeterministicPRNG tests that DKG produces consistent results with same PRNG seed
func TestDeterministicPRNG(t *testing.T) {
	t.Parallel()

	threshold := uint(2)
	total := uint(3)
	group := k256.NewCurve()
	sid := network.SID(sha3.Sum256([]byte("test-deterministic")))
	tape := hagrid.NewTranscript("TestDeterministic")

	// Run DKG twice with same PRNG seed
	seed1, seed2 := uint64(12345), uint64(67890)

	// First run
	prng1 := pcg.New(seed1, seed2)
	_, parties1 := setup(t, threshold, total, group, sid, tape, prng1)
	outputs1, err := tu.DoGennaroDKG(t, parties1.Values())
	require.NoError(t, err)

	// Second run with same seed
	prng2 := pcg.New(seed1, seed2)
	_, parties2 := setup(t, threshold, total, group, sid, tape, prng2)
	outputs2, err := tu.DoGennaroDKG(t, parties2.Values())
	require.NoError(t, err)

	// Results should be identical
	require.Equal(t, outputs1.Size(), outputs2.Size())

	for id, output1 := range outputs1.Iter() {
		output2, _ := outputs2.Get(id)

		// Share values should be identical
		require.True(t, output1.Share().Value().Equal(output2.Share().Value()),
			"participant %d has different share values between runs", id)

		// Verification vectors should be identical
		require.True(t, output1.VerificationVector().Equal(output2.VerificationVector()),
			"participant %d has different verification vectors between runs", id)
	}
}

// setupBench is a helper for benchmarks
func setupBench[
	E gennaro.GroupElement[E, S], S gennaro.Scalar[S],
](
	b *testing.B, threshold, total uint, group gennaro.Group[E, S], sid network.SID, tape ts.Transcript, prng io.Reader,
) (
	ac *sharing.ThresholdAccessStructure,
	parties ds.MutableMap[sharing.ID, *gennaro.Participant[E, S]],
) {
	b.Helper()
	shareholders := sharing.NewOrdinalShareholderSet(total)
	ac, err := sharing.NewThresholdAccessStructure(threshold, shareholders)
	require.NoError(b, err)
	require.NotNil(b, group)
	if ct.SliceIsZero(sid[:]) == 1 {
		sid = network.SID(sha3.Sum256([]byte("test-sid")))
	}
	if tape == nil {
		tape = hagrid.NewTranscript("test")
	}
	if prng == nil {
		prng = pcg.New(0, 0)
	}

	parties = hashmap.NewComparable[sharing.ID, *gennaro.Participant[E, S]]()
	for id := range shareholders.Iter() {
		p, err := gennaro.NewParticipant(
			sid,
			group,
			id,
			ac,
			fiatshamir.Name,
			tape.Clone(),
			prng,
		)
		require.NoError(b, err)
		parties.Put(id, p)
	}
	return ac, parties
}

// BenchmarkGennaroDKG benchmarks the DKG protocol
func BenchmarkGennaroDKG(b *testing.B) {
	benchmarks := []struct {
		name      string
		threshold uint
		total     uint
	}{
		{"3-of-5", 2, 3},
		{"3-of-5", 3, 5},
		{"4-of-4", 4, 4},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			group := k256.NewCurve()
			sid := network.SID(sha3.Sum256([]byte("benchmark")))
			tape := hagrid.NewTranscript("Benchmark")
			prng := pcg.NewRandomised()

			b.ResetTimer()
			for range b.N {
				_, parties := setupBench(b, bm.threshold, bm.total, group, sid, tape, prng)
				_, err := tu.DoGennaroDKG(b, parties.Values())
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkGennaroRounds benchmarks individual rounds
func BenchmarkGennaroRounds(b *testing.B) {
	threshold := uint(2)
	total := uint(3)
	group := k256.NewCurve()
	sid := network.SID(sha3.Sum256([]byte("benchmark-rounds")))
	tape := hagrid.NewTranscript("BenchmarkRounds")
	prng := pcg.NewRandomised()

	b.Run("Round1", func(b *testing.B) {
		b.ResetTimer()
		for range b.N {
			b.StopTimer()
			_, parties := setupBench(b, threshold, total, group, sid, tape, prng)
			b.StartTimer()

			_, err := tu.DoGennaroRound1(parties.Values())
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("Round2", func(b *testing.B) {
		b.ResetTimer()
		for range b.N {
			b.StopTimer()
			_, parties := setupBench(b, threshold, total, group, sid, tape, prng)
			r1broadcasts, _ := tu.DoGennaroRound1(parties.Values())
			r2inputs := ntu.MapBroadcastO2I(b, parties.Values(), r1broadcasts)
			b.StartTimer()

			_, _, err := tu.DoGennaroRound2(parties.Values(), r2inputs)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("Round3", func(b *testing.B) {
		b.ResetTimer()
		for range b.N {
			b.StopTimer()
			_, parties := setupBench(b, threshold, total, group, sid, tape, prng)
			r1broadcasts, _ := tu.DoGennaroRound1(parties.Values())
			r2inputs := ntu.MapBroadcastO2I(b, parties.Values(), r1broadcasts)
			r2broadcasts, r2unicasts, _ := tu.DoGennaroRound2(parties.Values(), r2inputs)
			r3broadcastInputs := ntu.MapBroadcastO2I(b, parties.Values(), r2broadcasts)
			r3unicastInputs := ntu.MapUnicastO2I(b, parties.Values(), r2unicasts)
			b.StartTimer()

			_, err := tu.DoGennaroRound3(parties.Values(), r3broadcastInputs, r3unicastInputs)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkDKGScaling benchmarks DKG with increasing participant counts
func BenchmarkDKGScaling(b *testing.B) {
	configs := []struct {
		name      string
		threshold uint
		total     uint
	}{
		{"small-3-of-5", 3, 5},
		{"medium-5-of-9", 5, 9},
		{"large-11-of-21", 11, 21},
	}

	for _, config := range configs {
		b.Run(config.name, func(b *testing.B) {
			group := k256.NewCurve()
			sid := network.SID(sha3.Sum256([]byte("benchmark")))
			tape := hagrid.NewTranscript("Benchmark")
			prng := pcg.NewRandomised()

			b.ResetTimer()
			for range b.N {
				_, parties := setupBench(b, config.threshold, config.total, group, sid, tape, prng)
				_, err := tu.DoGennaroDKG(b, parties.Values())
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkShareReconstruction benchmarks share reconstruction
func BenchmarkShareReconstruction(b *testing.B) {
	threshold := uint(2)
	total := uint(3)
	group := k256.NewCurve()
	sid := network.SID(sha3.Sum256([]byte("benchmark-recon")))
	tape := hagrid.NewTranscript("BenchmarkRecon")
	prng := pcg.NewRandomised()

	// Setup and run DKG once
	ac, parties := setupBench(b, threshold, total, group, sid, tape, prng)
	outputs, err := tu.DoGennaroDKG(b, parties.Values())
	if err != nil {
		b.Fatal(err)
	}

	// Collect shares
	shares := make([]*feldman.Share[*k256.Scalar], 0, total)
	for _, output := range outputs.Values() {
		shares = append(shares, output.Share())
	}

	feldmanScheme, err := feldman.NewScheme(group.Generator(), ac)
	if err != nil {
		b.Fatal(err)
	}

	// Get verification vector from first output
	referenceVV := outputs.Values()[0].VerificationVector()

	b.ResetTimer()
	for range b.N {
		_, err := feldmanScheme.ReconstructAndVerify(referenceVV, shares[:threshold]...)
		if err != nil {
			b.Fatal(err)
		}
	}
}
