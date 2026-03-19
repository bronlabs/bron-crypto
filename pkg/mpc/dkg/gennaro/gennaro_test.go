package gennaro_test

import (
	"io"
	"maps"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/mpc/dkg/gennaro"
	tu "github.com/bronlabs/bron-crypto/pkg/mpc/dkg/gennaro/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/threshold"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/feldman"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
)

func setup[E gennaro.GroupElement[E, S], S gennaro.Scalar[S]](tb testing.TB, accessStructure *threshold.Threshold, group gennaro.Group[E, S], prng io.Reader) map[sharing.ID]*gennaro.Participant[E, S] {
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

// TestDKGWithVariousThresholds tests DKG with different thresh configurations
func TestDKGWithVariousThresholds(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		thresh uint
		total  uint
	}{
		{"minimal 2-of-3", 2, 3},
		{"standard 3-of-5", 3, 5},
		{"unanimous 4-of-4", 4, 4},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			group := k256.NewCurve()
			prng := pcg.NewRandomised()
			quorum := ntu.MakeRandomQuorum(t, prng, int(tc.total))
			ac, err := threshold.NewThresholdAccessStructure(tc.thresh, quorum)
			require.NoError(t, err)
			parties := setup(t, ac, group, prng)

			// Run complete DKG
			outputs := tu.DoGennaroDKG(t, parties)

			// Verify all outputs have correct access structure
			for id, output := range outputs {
				require.NotNil(t, output.AccessStructure())
				require.Equal(t, tc.thresh, output.AccessStructure().Threshold())
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

			// Test reconstruction with exactly thresh shares
			if tc.thresh < tc.total {
				thresholdShares := shares[:tc.thresh]
				secretFromThreshold, err := feldmanScheme.ReconstructAndVerify(referenceVV, thresholdShares...)
				require.NoError(t, err)
				require.True(t, secret.Equal(secretFromThreshold))
			}
		})
	}
}

func TestDKGPublicKeyFields(t *testing.T) {
	t.Parallel()

	thresh := uint(2)
	total := uint(3)
	group := k256.NewCurve()
	prng := pcg.NewRandomised()
	quorum := ntu.MakeRandomQuorum(t, prng, int(total))
	ac, err := threshold.NewThresholdAccessStructure(thresh, quorum)
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

	thresh := uint(2)
	total := uint(3)
	group := k256.NewCurve()
	prng := pcg.NewRandomised()
	quorum := ntu.MakeRandomQuorum(t, prng, int(total))
	ac, err := threshold.NewThresholdAccessStructure(thresh, quorum)
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
		for combo := range sliceutils.KCoveringCombinations(shares, thresh) {
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

	thresh := uint(2)
	total := uint(3)
	group := k256.NewCurve()
	prng := pcg.NewRandomised()
	quorum := ntu.MakeRandomQuorum(t, prng, int(total))
	ac, err := threshold.NewThresholdAccessStructure(thresh, quorum)
	require.NoError(t, err)

	t.Run("round 1 broadcasts and unicasts", func(t *testing.T) {
		t.Parallel()

		parties := setup(t, ac, group, pcg.NewRandomised())
		r1broadcasts, r1unicasts := tu.DoGennaroRound1(t, parties)
		require.Len(t, r1broadcasts, int(total))
		require.Len(t, r1unicasts, int(total))
		for _, broadcast := range r1broadcasts {
			require.NotNil(t, broadcast)
			require.NotNil(t, broadcast.PedersenVerificationVector)
			require.NotNil(t, broadcast.Proof)
		}
		for senderID, unicasts := range r1unicasts {
			require.Equal(t, int(total-1), unicasts.Size())
			for receiverID, share := range unicasts.Iter() {
				require.NotNil(t, share)
				require.NotNil(t, share.Share)
				require.NotEqual(t, senderID, receiverID)
			}
		}
	})

	t.Run("round 2 broadcasts", func(t *testing.T) {
		t.Parallel()

		parties := setup(t, ac, group, pcg.NewRandomised())
		participants := slices.Collect(maps.Values(parties))
		r1broadcasts, r1unicasts := tu.DoGennaroRound1(t, parties)
		r2biInputs, r2uiInputs := ntu.MapO2I(t, participants, r1broadcasts, r1unicasts)
		r2broadcasts := tu.DoGennaroRound2(t, parties, r2biInputs, r2uiInputs)

		require.Len(t, r2broadcasts, int(total))
		for _, broadcast := range r2broadcasts {
			require.NotNil(t, broadcast)
			require.NotNil(t, broadcast.FeldmanVerificationVector)
		}
	})
}

func TestRoundOutOfOrder(t *testing.T) {
	t.Parallel()

	group := k256.NewCurve()
	prng := pcg.NewRandomised()
	quorum := ntu.MakeRandomQuorum(t, prng, 3)
	ac, err := threshold.NewThresholdAccessStructure(2, quorum)
	require.NoError(t, err)
	parties := setup(t, ac, group, prng)

	participant := slices.Collect(maps.Values(parties))[0]

	t.Run("cannot execute round 2 before round 1", func(t *testing.T) {
		t.Parallel()
		_, err := participant.Round2(nil, nil)
		require.Error(t, err)
		require.ErrorIs(t, err, gennaro.ErrRound)
	})

	t.Run("cannot execute round 3 before completing previous rounds", func(t *testing.T) {
		t.Parallel()
		_, err := participant.Round3(nil)
		require.Error(t, err)
		require.ErrorIs(t, err, gennaro.ErrRound)
	})

	t.Run("cannot re-execute round 1", func(t *testing.T) {
		t.Parallel()
		_, _, err := participant.Round1()
		require.NoError(t, err)
		_, _, err = participant.Round1()
		require.Error(t, err)
		require.ErrorIs(t, err, gennaro.ErrRound)
	})
}

func TestParticipantCreation(t *testing.T) {
	t.Parallel()

	group := k256.NewCurve()
	prng := pcg.NewRandomised()
	quorum := sharing.NewOrdinalShareholderSet(3)
	ac, err := threshold.NewThresholdAccessStructure(2, quorum)
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
		mismatch, err := threshold.NewThresholdAccessStructure(2, hashset.NewComparable[sharing.ID](1, 2, 4).Freeze())
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

// Security tests

type securityFixture struct {
	group   *k256.Curve
	ac      *threshold.Threshold
	quorum  network.Quorum
	parties map[sharing.ID]*gennaro.Participant[*k256.Point, *k256.Scalar]
	ids     []sharing.ID // sorted

	r1bo map[sharing.ID]*gennaro.Round1Broadcast[*k256.Point, *k256.Scalar]
	r1uo map[sharing.ID]network.OutgoingUnicasts[*gennaro.Round1Unicast[*k256.Point, *k256.Scalar]]
	r2bi map[sharing.ID]network.RoundMessages[*gennaro.Round1Broadcast[*k256.Point, *k256.Scalar]]
	r2ui map[sharing.ID]network.RoundMessages[*gennaro.Round1Unicast[*k256.Point, *k256.Scalar]]
}

func newSecurityFixture(t *testing.T) *securityFixture {
	t.Helper()
	group := k256.NewCurve()
	prng := pcg.NewRandomised()
	quorum := sharing.NewOrdinalShareholderSet(3)
	ac, err := threshold.NewThresholdAccessStructure(2, quorum)
	require.NoError(t, err)
	parties := setup(t, ac, group, prng)
	participants := slices.Collect(maps.Values(parties))
	r1bo, r1uo := tu.DoGennaroRound1(t, parties)
	r2bi, r2ui := ntu.MapO2I(t, participants, r1bo, r1uo)
	ids := slices.Sorted(maps.Keys(parties))
	return &securityFixture{
		group: group, ac: ac, quorum: quorum, parties: parties, ids: ids,
		r1bo: r1bo, r1uo: r1uo, r2bi: r2bi, r2ui: r2ui,
	}
}

// replaceBroadcastFrom returns a copy of victim's broadcast inputs with attacker's message replaced.
func replaceBroadcastFrom[M network.Message](
	original network.RoundMessages[M], attackerID sharing.ID, replacement M,
) network.RoundMessages[M] {
	m := hashmap.NewComparable[sharing.ID, M]()
	for id, msg := range original.Iter() {
		if id == attackerID {
			m.Put(id, replacement)
		} else {
			m.Put(id, msg)
		}
	}
	return m.Freeze()
}

// replaceUnicastFrom returns a copy of victim's unicast inputs with attacker's message replaced.
func replaceUnicastFrom[M network.Message](
	original network.RoundMessages[M], attackerID sharing.ID, replacement M,
) network.RoundMessages[M] {
	m := hashmap.NewComparable[sharing.ID, M]()
	for id, msg := range original.Iter() {
		if id == attackerID {
			m.Put(id, replacement)
		} else {
			m.Put(id, msg)
		}
	}
	return m.Freeze()
}

func TestProofsAreNonEmpty(t *testing.T) {
	t.Parallel()
	f := newSecurityFixture(t)

	t.Run("okamoto proofs in round 1", func(t *testing.T) {
		t.Parallel()
		for id, bc := range f.r1bo {
			require.NotEmpty(t, bc.Proof, "party %d produced empty okamoto proof", id)
		}
	})

	t.Run("batch schnorr proofs in round 2", func(t *testing.T) {
		t.Parallel()
		participants := slices.Collect(maps.Values(f.parties))
		r2bo := tu.DoGennaroRound2(t, f.parties, f.r2bi, f.r2ui)
		_ = participants
		for id, bc := range r2bo {
			require.NotEmpty(t, bc.Proof, "party %d produced empty schnorr proof", id)
		}
	})
}

func TestTamperedOkamotoProofRejected(t *testing.T) {
	t.Parallel()
	f := newSecurityFixture(t)
	victim, attacker := f.ids[0], f.ids[1]

	// Take attacker's broadcast, corrupt the okamoto proof
	originalBC, _ := f.r2bi[victim].Get(attacker)
	tampered := &gennaro.Round1Broadcast[*k256.Point, *k256.Scalar]{
		PedersenVerificationVector: originalBC.PedersenVerificationVector,
		Proof:                      compiler.NIZKPoKProof([]byte("forged proof")),
	}
	tamperedR2bi := replaceBroadcastFrom(f.r2bi[victim], attacker, tampered)

	_, err := f.parties[victim].Round2(tamperedR2bi, f.r2ui[victim])
	require.Error(t, err)
	require.True(t, base.IsIdentifiableAbortError(err), "expected identifiable abort, got: %v", err)
	culprits := base.GetMaliciousIdentities[sharing.ID](err)
	require.Contains(t, culprits, attacker)
}

func TestTamperedPedersenVVRejected(t *testing.T) {
	t.Parallel()
	f := newSecurityFixture(t)
	victim, attacker := f.ids[0], f.ids[1]

	// Replace attacker's pedersen VV with a different party's VV — proof won't match.
	differentVV := f.r1bo[f.ids[2]].PedersenVerificationVector
	originalBC, _ := f.r2bi[victim].Get(attacker)
	tampered := &gennaro.Round1Broadcast[*k256.Point, *k256.Scalar]{
		PedersenVerificationVector: differentVV,
		Proof:                      originalBC.Proof,
	}
	tamperedR2bi := replaceBroadcastFrom(f.r2bi[victim], attacker, tampered)

	_, err := f.parties[victim].Round2(tamperedR2bi, f.r2ui[victim])
	require.Error(t, err)
	require.True(t, base.IsIdentifiableAbortError(err))
	culprits := base.GetMaliciousIdentities[sharing.ID](err)
	require.Contains(t, culprits, attacker)
}

func TestTamperedPedersenShareRejected(t *testing.T) {
	t.Parallel()
	f := newSecurityFixture(t)
	victim, attacker, other := f.ids[0], f.ids[1], f.ids[2]

	// Replace attacker's share to victim with a share from a different dealer.
	// The share has the correct receiver ID but was computed from a different
	// polynomial, so it won't verify against the attacker's pedersen VV.
	wrongDealerShare, _ := f.r1uo[other].Get(victim) // other's share for victim
	tampered := &gennaro.Round1Unicast[*k256.Point, *k256.Scalar]{
		Share: wrongDealerShare.Share,
	}
	tamperedR2ui := replaceUnicastFrom(f.r2ui[victim], attacker, tampered)

	_, err := f.parties[victim].Round2(f.r2bi[victim], tamperedR2ui)
	require.Error(t, err)
	require.True(t, base.IsIdentifiableAbortError(err))
	culprits := base.GetMaliciousIdentities[sharing.ID](err)
	require.Contains(t, culprits, attacker)
}

func TestTamperedSchnorrProofRejected(t *testing.T) {
	t.Parallel()
	f := newSecurityFixture(t)
	victim, attacker := f.ids[0], f.ids[1]

	// Complete round 2 honestly
	r2bo := tu.DoGennaroRound2(t, f.parties, f.r2bi, f.r2ui)
	participants := slices.Collect(maps.Values(f.parties))
	r3bi := ntu.MapBroadcastO2I(t, participants, r2bo)

	// Corrupt attacker's batch schnorr proof in victim's R3 input
	originalBC, _ := r3bi[victim].Get(attacker)
	tampered := &gennaro.Round2Broadcast[*k256.Point, *k256.Scalar]{
		FeldmanVerificationVector: originalBC.FeldmanVerificationVector,
		Proof:                     compiler.NIZKPoKProof([]byte("forged schnorr proof")),
	}
	tamperedR3bi := replaceBroadcastFrom(r3bi[victim], attacker, tampered)

	_, err := f.parties[victim].Round3(tamperedR3bi)
	require.Error(t, err)
	require.True(t, base.IsIdentifiableAbortError(err))
	culprits := base.GetMaliciousIdentities[sharing.ID](err)
	require.Contains(t, culprits, attacker)
}

func TestTamperedFeldmanVVRejected(t *testing.T) {
	t.Parallel()
	f := newSecurityFixture(t)
	victim, attacker := f.ids[0], f.ids[1]

	r2bo := tu.DoGennaroRound2(t, f.parties, f.r2bi, f.r2ui)
	participants := slices.Collect(maps.Values(f.parties))
	r3bi := ntu.MapBroadcastO2I(t, participants, r2bo)

	// Replace attacker's feldman VV with a different party's — schnorr proof won't match.
	differentVV := r2bo[f.ids[2]].FeldmanVerificationVector
	originalBC, _ := r3bi[victim].Get(attacker)
	tampered := &gennaro.Round2Broadcast[*k256.Point, *k256.Scalar]{
		FeldmanVerificationVector: differentVV,
		Proof:                     originalBC.Proof,
	}
	tamperedR3bi := replaceBroadcastFrom(r3bi[victim], attacker, tampered)

	_, err := f.parties[victim].Round3(tamperedR3bi)
	require.Error(t, err)
	require.True(t, base.IsIdentifiableAbortError(err))
	culprits := base.GetMaliciousIdentities[sharing.ID](err)
	require.Contains(t, culprits, attacker)
}

func TestRogueKeyAttackPrevented(t *testing.T) {
	t.Parallel()

	// The okamoto proof in R1 is bound to the prover's identity via the transcript.
	// A rogue key attacker who tries to replay another party's valid broadcast
	// (VV + proof) under their own identity will be rejected because the verifier
	// derives the challenge using the claimed sender's ID, which won't match.
	f := newSecurityFixture(t)
	victim, attacker, other := f.ids[0], f.ids[1], f.ids[2]

	// Attacker replays the other party's broadcast (valid VV + valid proof, wrong identity)
	stolenBC := f.r1bo[other]
	tampered := &gennaro.Round1Broadcast[*k256.Point, *k256.Scalar]{
		PedersenVerificationVector: stolenBC.PedersenVerificationVector,
		Proof:                      stolenBC.Proof,
	}
	tamperedR2bi := replaceBroadcastFrom(f.r2bi[victim], attacker, tampered)

	_, err := f.parties[victim].Round2(tamperedR2bi, f.r2ui[victim])
	require.Error(t, err, "replayed proof under different identity should be detected")
	require.True(t, base.IsIdentifiableAbortError(err))
	culprits := base.GetMaliciousIdentities[sharing.ID](err)
	require.Contains(t, culprits, attacker)
}

func TestSwappedSchnorrProofIdentityRejected(t *testing.T) {
	t.Parallel()

	// Same identity-binding test for the batch Schnorr proof in R2.
	// Replaying another party's R2 broadcast under the attacker's ID should fail.
	f := newSecurityFixture(t)
	victim, attacker, other := f.ids[0], f.ids[1], f.ids[2]

	r2bo := tu.DoGennaroRound2(t, f.parties, f.r2bi, f.r2ui)
	participants := slices.Collect(maps.Values(f.parties))
	r3bi := ntu.MapBroadcastO2I(t, participants, r2bo)

	stolenBC := r2bo[other]
	tamperedR3bi := replaceBroadcastFrom(r3bi[victim], attacker, stolenBC)

	_, err := f.parties[victim].Round3(tamperedR3bi)
	require.Error(t, err)
	require.True(t, base.IsIdentifiableAbortError(err))
	culprits := base.GetMaliciousIdentities[sharing.ID](err)
	require.Contains(t, culprits, attacker)
}

func TestFeldmanPedersenConsistencyCheck(t *testing.T) {
	t.Parallel()

	// The Feldman VV in R2 must be consistent with the Pedersen VV in R1:
	// both encode the same secret polynomial. Round 3 verifies the Feldman share
	// (derived from the Pedersen share value) against the Feldman VV.
	// An attacker who sends a valid Feldman proof for a *different* polynomial
	// will be caught by the Feldman share verification.
	//
	// We simulate this: run two independent DKGs, take attacker's R2 broadcast
	// (feldman VV + proof) from the second DKG and inject it into the first.
	group := k256.NewCurve()
	prng := pcg.NewRandomised()
	quorum := sharing.NewOrdinalShareholderSet(3)
	ac, err := threshold.NewThresholdAccessStructure(2, quorum)
	require.NoError(t, err)

	// DKG 1: the real one
	parties1 := setup(t, ac, group, prng)
	participants1 := slices.Collect(maps.Values(parties1))
	r1bo1, r1uo1 := tu.DoGennaroRound1(t, parties1)
	r2bi1, r2ui1 := ntu.MapO2I(t, participants1, r1bo1, r1uo1)
	r2bo1 := tu.DoGennaroRound2(t, parties1, r2bi1, r2ui1)

	// DKG 2: independent, for the attacker's alternate polynomial
	parties2 := setup(t, ac, group, prng)
	participants2 := slices.Collect(maps.Values(parties2))
	r1bo2, r1uo2 := tu.DoGennaroRound1(t, parties2)
	r2bi2, r2ui2 := ntu.MapO2I(t, participants2, r1bo2, r1uo2)
	r2bo2 := tu.DoGennaroRound2(t, parties2, r2bi2, r2ui2)

	ids := slices.Sorted(maps.Keys(parties1))
	victim, attacker := ids[0], ids[1]

	// Inject attacker's R2 from DKG2 into DKG1's R3 inputs for victim
	r3bi1 := ntu.MapBroadcastO2I(t, participants1, r2bo1)
	tampered := r2bo2[attacker] // valid proof, but for a different polynomial
	tamperedR3bi := replaceBroadcastFrom(r3bi1[victim], attacker, tampered)

	_, err = parties1[victim].Round3(tamperedR3bi)
	require.Error(t, err, "feldman/pedersen inconsistency should be detected")
	require.True(t, base.IsIdentifiableAbortError(err))
	culprits := base.GetMaliciousIdentities[sharing.ID](err)
	require.Contains(t, culprits, attacker)
}

func TestShareReconstructionYieldsMatchingPublicKey(t *testing.T) {
	t.Parallel()

	// End-to-end check: the reconstructed secret key, when lifted to the group,
	// must equal the joint public key agreed upon by all parties. This is the
	// fundamental correctness property that rules out subtle manipulation.
	group := k256.NewCurve()
	prng := pcg.NewRandomised()
	quorum := sharing.NewOrdinalShareholderSet(3)
	ac, err := threshold.NewThresholdAccessStructure(2, quorum)
	require.NoError(t, err)

	parties := setup(t, ac, group, prng)
	outputs := tu.DoGennaroDKG(t, parties)

	feldmanScheme, err := feldman.NewScheme(group.Generator(), ac)
	require.NoError(t, err)

	shares := make([]*feldman.Share[*k256.Scalar], 0, len(outputs))
	var publicKey *k256.Point
	var vv feldman.VerificationVector[*k256.Point, *k256.Scalar]
	for _, out := range outputs {
		shares = append(shares, out.Share())
		if publicKey == nil {
			publicKey = out.PublicKeyValue()
			vv = out.VerificationVector()
		}
	}

	secret, err := feldmanScheme.ReconstructAndVerify(vv, shares...)
	require.NoError(t, err)
	reconstructedPK := group.ScalarBaseOp(secret.Value())
	require.True(t, reconstructedPK.Equal(publicKey),
		"reconstructed public key does not match DKG output")
	require.False(t, publicKey.IsZero(), "joint public key must not be the identity")
}
