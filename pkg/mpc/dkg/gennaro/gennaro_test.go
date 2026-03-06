package gennaro_test

import (
	"io"
	"maps"
	"slices"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/dkg/gennaro"
	tu "github.com/bronlabs/bron-crypto/pkg/mpc/dkg/gennaro/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/feldman"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
)

func setup[E gennaro.GroupElement[E, S], S gennaro.Scalar[S]](tb testing.TB, accessStructure *accessstructures.Threshold, group gennaro.Group[E, S], prng io.Reader) map[sharing.ID]*gennaro.Participant[E, S] {
	tb.Helper()
	ctxs := session_testutils.MakeRandomContexts(tb, accessStructure.Shareholders(), prng)
	parties := make(map[sharing.ID]*gennaro.Participant[E, S])
	for id, ctx := range ctxs {
		p, err := gennaro.NewParticipant(ctx, group, accessStructure, fiatshamir.Name, prng)
		require.NoError(tb, err)
		parties[id] = p
	}
	return parties
}

// TestDKGWithVariousThresholds tests DKG with different threshold configurations
func TestDKGWithVariousThresholds(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
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

			quorum := ntu.MakeRandomQuorum(t, prng, int(tc.total))
			ac, err := accessstructures.NewThresholdAccessStructure(tc.threshold, quorum)
			require.NoError(t, err)
			parties := setup(t, ac, group, prng)

			// Run complete DKG
			outputs := tu.DoGennaroDKG(t, parties)

			// Verify all outputs have correct access structure
			for id, output := range outputs {
				require.NotNil(t, output.AccessStructure())
				require.Equal(t, tc.threshold, output.AccessStructure().Threshold())
				require.Equal(t, int(tc.total), output.AccessStructure().Shareholders().Size())
				require.Equal(t, id, output.Share().ID())
			}

			// Collect shares and verify reconstruction
			shares := make([]*feldman.Share[*k256.Scalar], 0, tc.total)
			var referenceVV feldman.VerificationVector[*k256.Point, *k256.Scalar]

			for _, output := range outputs {
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

func TestDKGPublicKeyFields(t *testing.T) {
	t.Parallel()

	threshold := uint(2)
	total := uint(3)
	group := k256.NewCurve()
	prng := pcg.NewRandomised()
	quorum := ntu.MakeRandomQuorum(t, prng, int(total))
	ac, err := accessstructures.NewThresholdAccessStructure(threshold, quorum)
	require.NoError(t, err)

	parties := setup(t, ac, group, prng)
	outputs := tu.DoGennaroDKG(t, parties)

	t.Run("public key consistency", func(t *testing.T) {
		t.Parallel()

		var commonPublicKey *k256.Point
		for id, output := range outputs {
			pk := output.PublicKeyValue()
			require.NotNil(t, pk, "participant %d has nil public key", id)
			require.False(t, pk.IsZero(), "participant %d has zero public key", id)

			if commonPublicKey == nil {
				commonPublicKey = pk
			} else {
				require.True(t, commonPublicKey.Equal(pk), "participant %d has different public key", id)
			}
		}
	})

	t.Run("partial public keys properties", func(t *testing.T) {
		t.Parallel()

		allPartialPKs := make(map[sharing.ID]map[sharing.ID]*k256.Point)
		for id, output := range outputs {
			partialPKs := output.PartialPublicKeyValues()
			require.NotNil(t, partialPKs)
			require.Equal(t, int(total), partialPKs.Size())

			allPartialPKs[id] = make(map[sharing.ID]*k256.Point, partialPKs.Size())
			for pid, ppk := range partialPKs.Iter() {
				require.NotNil(t, ppk)
				require.False(t, ppk.IsZero())
				allPartialPKs[id][pid] = ppk
			}
		}

		for _, targetID := range quorum.List() {
			var referencePPK *k256.Point
			for holderID, holderPartialPKs := range allPartialPKs {
				ppk := holderPartialPKs[targetID]
				if referencePPK == nil {
					referencePPK = ppk
					continue
				}
				require.True(t, referencePPK.Equal(ppk), "inconsistent partial public key for participant %d held by %d", targetID, holderID)
			}
		}
	})

	t.Run("partial public keys match verification vector evaluations", func(t *testing.T) {
		t.Parallel()

		output0 := firstOutput(outputs)
		require.NotNil(t, output0)
		verificationVector := output0.VerificationVector()
		scalarField := k256.NewScalarField()

		for id, ppk := range output0.PartialPublicKeyValues().Iter() {
			x := scalarField.FromUint64(uint64(id))
			expectedPPK := verificationVector.Eval(x)
			require.True(t, expectedPPK.Equal(ppk), "partial public key for id %d does not match verification vector evaluation", id)
		}

		expectedPublicKey := verificationVector.Eval(scalarField.Zero())
		require.True(t, expectedPublicKey.Equal(output0.PublicKeyValue()))
	})
}

func TestDKGShareProperties(t *testing.T) {
	t.Parallel()

	threshold := uint(2)
	total := uint(3)
	group := k256.NewCurve()
	prng := pcg.NewRandomised()
	quorum := ntu.MakeRandomQuorum(t, prng, int(total))
	ac, err := accessstructures.NewThresholdAccessStructure(threshold, quorum)
	require.NoError(t, err)

	parties := setup(t, ac, group, prng)
	outputs := tu.DoGennaroDKG(t, parties)

	sharesByID := make(map[sharing.ID]*feldman.Share[*k256.Scalar], len(outputs))
	for id, output := range outputs {
		sharesByID[id] = output.Share()
	}

	t.Run("share uniqueness", func(t *testing.T) {
		t.Parallel()

		shareValues := make(map[string]sharing.ID, len(sharesByID))
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
		for _, output := range outputs {
			if referenceVV == nil {
				referenceVV = output.VerificationVector()
				continue
			}
			require.True(t, referenceVV.Equal(output.VerificationVector()))
		}
	})

	t.Run("share reconstruction subsets", func(t *testing.T) {
		t.Parallel()

		feldmanScheme, err := feldman.NewScheme(group.Generator(), ac)
		require.NoError(t, err)
		referenceVV := firstOutput(outputs).VerificationVector()

		shares := make([]*feldman.Share[*k256.Scalar], 0, len(sharesByID))
		for _, s := range sharesByID {
			shares = append(shares, s)
		}

		var reconstructedSecrets []*feldman.Secret[*k256.Scalar]
		for combo := range sliceutils.KCoveringCombinations(shares, threshold) {
			secret, err := feldmanScheme.ReconstructAndVerify(referenceVV, combo...)
			require.NoError(t, err)
			reconstructedSecrets = append(reconstructedSecrets, secret)
		}
		require.NotEmpty(t, reconstructedSecrets)
		for i := 1; i < len(reconstructedSecrets); i++ {
			require.True(t, reconstructedSecrets[0].Equal(reconstructedSecrets[i]))
		}
	})
}

func TestDKGRoundMessages(t *testing.T) {
	t.Parallel()

	threshold := uint(2)
	total := uint(3)
	group := k256.NewCurve()
	prng := pcg.NewRandomised()
	quorum := ntu.MakeRandomQuorum(t, prng, int(total))
	ac, err := accessstructures.NewThresholdAccessStructure(threshold, quorum)
	require.NoError(t, err)

	t.Run("round 1 message properties", func(t *testing.T) {
		t.Parallel()

		parties := setup(t, ac, group, prng)
		r1broadcasts := tu.DoGennaroRound1(t, parties)
		require.Len(t, r1broadcasts, int(total))
		for _, broadcast := range r1broadcasts {
			require.NotNil(t, broadcast)
			require.NotNil(t, broadcast.PedersenVerificationVector)
		}
	})

	t.Run("round 2 broadcasts and unicasts", func(t *testing.T) {
		t.Parallel()

		parties := setup(t, ac, group, prng)
		participants := slices.Collect(maps.Values(parties))
		r1broadcasts := tu.DoGennaroRound1(t, parties)
		r2inputs := ntu.MapBroadcastO2I(t, participants, r1broadcasts)
		r2broadcasts, r2unicasts := tu.DoGennaroRound2(t, parties, r2inputs)

		require.Len(t, r2broadcasts, int(total))
		require.Len(t, r2unicasts, int(total))
		for _, broadcast := range r2broadcasts {
			require.NotNil(t, broadcast)
			require.NotNil(t, broadcast.FeldmanVerificationVector)
		}
		for senderID, unicasts := range r2unicasts {
			require.Equal(t, int(total-1), unicasts.Size())
			for receiverID, share := range unicasts.Iter() {
				require.NotNil(t, share)
				require.NotNil(t, share.Share)
				require.NotEqual(t, senderID, receiverID)
			}
		}
	})
}

func TestRoundOutOfOrder(t *testing.T) {
	t.Parallel()

	group := k256.NewCurve()
	prng := pcg.NewRandomised()
	quorum := ntu.MakeRandomQuorum(t, prng, 3)
	ac, err := accessstructures.NewThresholdAccessStructure(2, quorum)
	require.NoError(t, err)
	parties := setup(t, ac, group, prng)

	participant := slices.Collect(maps.Values(parties))[0]

	t.Run("cannot execute round 2 before round 1", func(t *testing.T) {
		t.Parallel()
		_, _, err := participant.Round2(nil)
		require.Error(t, err)
		require.ErrorIs(t, err, gennaro.ErrRound)
	})

	t.Run("cannot execute round 3 before completing previous rounds", func(t *testing.T) {
		t.Parallel()
		_, err := participant.Round3(nil, nil)
		require.Error(t, err)
		require.ErrorIs(t, err, gennaro.ErrRound)
	})

	t.Run("cannot re-execute round 1", func(t *testing.T) {
		t.Parallel()
		_, err := participant.Round1()
		require.NoError(t, err)
		_, err = participant.Round1()
		require.Error(t, err)
		require.ErrorIs(t, err, gennaro.ErrRound)
	})
}

func TestParticipantCreation(t *testing.T) {
	t.Parallel()

	group := k256.NewCurve()
	prng := pcg.NewRandomised()
	quorum := sharing.NewOrdinalShareholderSet(3)
	ac, err := accessstructures.NewThresholdAccessStructure(2, quorum)
	require.NoError(t, err)
	ctxs := session_testutils.MakeRandomContexts(t, quorum, prng)
	ctx := ctxs[1]

	t.Run("valid participant creation", func(t *testing.T) {
		t.Parallel()
		p, err := gennaro.NewParticipant(ctx, group, ac, fiatshamir.Name, prng)
		require.NoError(t, err)
		require.NotNil(t, p)
		require.Equal(t, sharing.ID(1), p.SharingID())
		require.Equal(t, ac, p.AccessStructure())
	})

	t.Run("nil group", func(t *testing.T) {
		t.Parallel()
		p, err := gennaro.NewParticipant[*k256.Point, *k256.Scalar](ctx, nil, ac, fiatshamir.Name, prng)
		require.Error(t, err)
		require.ErrorIs(t, err, gennaro.ErrInvalidArgument)
		require.Nil(t, p)
	})

	t.Run("nil prng", func(t *testing.T) {
		t.Parallel()
		p, err := gennaro.NewParticipant(ctx, group, ac, fiatshamir.Name, nil)
		require.Error(t, err)
		require.ErrorIs(t, err, gennaro.ErrInvalidArgument)
		require.Nil(t, p)
	})

	t.Run("nil access structure", func(t *testing.T) {
		t.Parallel()
		p, err := gennaro.NewParticipant(ctx, group, nil, fiatshamir.Name, prng)
		require.Error(t, err)
		require.ErrorIs(t, err, gennaro.ErrInvalidArgument)
		require.Nil(t, p)
	})

	t.Run("access structure mismatch with context", func(t *testing.T) {
		t.Parallel()
		mismatch, err := accessstructures.NewThresholdAccessStructure(2, hashset.NewComparable[sharing.ID](1, 2, 4).Freeze())
		require.NoError(t, err)
		p, err := gennaro.NewParticipant(ctx, group, mismatch, fiatshamir.Name, prng)
		require.Error(t, err)
		require.ErrorIs(t, err, gennaro.ErrInvalidArgument)
		require.Nil(t, p)
	})
}

func firstOutput(outputs map[sharing.ID]*gennaro.DKGOutput[*k256.Point, *k256.Scalar]) *gennaro.DKGOutput[*k256.Point, *k256.Scalar] {
	keys := slices.Collect(maps.Keys(outputs))
	slices.Sort(keys)
	return outputs[keys[0]]
}
