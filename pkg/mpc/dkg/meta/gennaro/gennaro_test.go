package gennaro_test

import (
	"io"
	"maps"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/mat"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/mpc"
	"github.com/bronlabs/bron-crypto/pkg/mpc/dkg/meta/gennaro"
	tu "github.com/bronlabs/bron-crypto/pkg/mpc/dkg/meta/gennaro/testutils"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/boolexpr"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/cnf"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/threshold"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/unanimity"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/meta/feldman"
	"github.com/bronlabs/bron-crypto/pkg/network"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func shareholders(ids ...sharing.ID) ds.Set[sharing.ID] {
	return hashset.NewComparable(ids...).Freeze()
}

func setup(tb testing.TB, ac accessstructures.Linear, group *k256.Curve, prng io.Reader) map[sharing.ID]*gennaro.Participant[*k256.Point, *k256.Scalar] {
	tb.Helper()
	ctxs := session_testutils.MakeRandomContexts(tb, ac.Shareholders(), prng)
	parties := make(map[sharing.ID]*gennaro.Participant[*k256.Point, *k256.Scalar])
	for id, ctx := range ctxs {
		p, err := gennaro.NewParticipant(ctx, group, ac, fiatshamir.Name, prng)
		require.NoError(tb, err)
		parties[id] = p
	}
	return parties
}

func firstOutput(outputs map[sharing.ID]*mpc.BaseShard[*k256.Point, *k256.Scalar]) *mpc.BaseShard[*k256.Point, *k256.Scalar] {
	keys := slices.Collect(maps.Keys(outputs))
	slices.Sort(keys)
	return outputs[keys[0]]
}

// ---------------------------------------------------------------------------
// access-structure fixtures
// ---------------------------------------------------------------------------

type acFixture struct {
	name         string
	ac           accessstructures.Linear
	qualified    [][]sharing.ID
	unqualified  [][]sharing.ID
	shareholders []sharing.ID
}

func thresholdFixture(t *testing.T) acFixture {
	t.Helper()
	ac, err := threshold.NewThresholdAccessStructure(2, shareholders(1, 2, 3))
	require.NoError(t, err)
	return acFixture{
		name:         "threshold(2,3)",
		ac:           ac,
		qualified:    [][]sharing.ID{{1, 2}, {1, 3}, {2, 3}, {1, 2, 3}},
		unqualified:  [][]sharing.ID{{1}, {2}, {3}},
		shareholders: []sharing.ID{1, 2, 3},
	}
}

func unanimityFixture(t *testing.T) acFixture {
	t.Helper()
	ac, err := unanimity.NewUnanimityAccessStructure(shareholders(1, 2, 3))
	require.NoError(t, err)
	return acFixture{
		name:         "unanimity(3)",
		ac:           ac,
		qualified:    [][]sharing.ID{{1, 2, 3}},
		unqualified:  [][]sharing.ID{{1}, {2}, {1, 2}, {1, 3}, {2, 3}},
		shareholders: []sharing.ID{1, 2, 3},
	}
}

func cnfFixture(t *testing.T) acFixture {
	t.Helper()
	ac, err := cnf.NewCNFAccessStructure(
		shareholders(1, 2),
		shareholders(3, 4),
	)
	require.NoError(t, err)
	return acFixture{
		name:         "cnf({1,2},{3,4})",
		ac:           ac,
		qualified:    [][]sharing.ID{{1, 3}, {1, 4}, {2, 3}, {2, 4}, {1, 3, 4}, {2, 3, 4}, {1, 2, 3}, {1, 2, 4}, {1, 2, 3, 4}},
		unqualified:  [][]sharing.ID{{1, 2}, {3, 4}},
		shareholders: []sharing.ID{1, 2, 3, 4},
	}
}

func largeThresholdFixture(t *testing.T) acFixture {
	t.Helper()
	ac, err := threshold.NewThresholdAccessStructure(4, shareholders(1, 2, 3, 4, 5, 6, 7))
	require.NoError(t, err)
	return acFixture{
		name:         "threshold(4,7)",
		ac:           ac,
		qualified:    [][]sharing.ID{{1, 2, 3, 4}, {3, 4, 5, 6}, {1, 2, 3, 4, 5, 6, 7}},
		unqualified:  [][]sharing.ID{{1, 2, 3}, {5, 6, 7}},
		shareholders: []sharing.ID{1, 2, 3, 4, 5, 6, 7},
	}
}

// boolexprFixture builds AND(Threshold(2, {1,2,3}), OR(4,5)):
// qualified iff at least 2 of {1,2,3} present AND at least one of {4,5} present.
func boolexprFixture(t *testing.T) acFixture {
	t.Helper()
	tree := boolexpr.And(
		boolexpr.Threshold(2, boolexpr.ID(1), boolexpr.ID(2), boolexpr.ID(3)),
		boolexpr.Or(boolexpr.ID(4), boolexpr.ID(5)),
	)
	ac, err := boolexpr.NewThresholdGateAccessStructure(tree)
	require.NoError(t, err)
	return acFixture{
		name: "boolexpr(2of3 AND 1of2)",
		ac:   ac,
		qualified: [][]sharing.ID{
			{1, 2, 4}, {1, 3, 5}, {2, 3, 4}, {1, 2, 3, 4, 5},
		},
		unqualified: [][]sharing.ID{
			{1, 4}, {4, 5}, {1, 2, 3}, {3, 5},
		},
		shareholders: []sharing.ID{1, 2, 3, 4, 5},
	}
}

func allFixtures(t *testing.T) []acFixture {
	t.Helper()
	return []acFixture{
		thresholdFixture(t),
		unanimityFixture(t),
		cnfFixture(t),
		largeThresholdFixture(t),
		boolexprFixture(t),
	}
}

// ---------------------------------------------------------------------------
// Happy-path: complete DKG across access structures
// ---------------------------------------------------------------------------

func TestDKG_HappyPath(t *testing.T) {
	t.Parallel()

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			group := k256.NewCurve()
			prng := pcg.NewRandomised()
			parties := setup(t, fx.ac, group, prng)
			outputs := tu.DoGennaroDKG(t, parties)
			require.Len(t, outputs, len(fx.shareholders))

			for id, output := range outputs {
				require.NotNil(t, output.Share())
				require.Equal(t, id, output.Share().ID())
				require.NotNil(t, output.PublicKeyValue())
				require.False(t, output.PublicKeyValue().IsZero())
				require.NotNil(t, output.VerificationVector())
				require.NotNil(t, output.MSP())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Public key consistency: all participants agree on the joint public key
// ---------------------------------------------------------------------------

func TestDKG_PublicKeyConsistency(t *testing.T) {
	t.Parallel()

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			group := k256.NewCurve()
			prng := pcg.NewRandomised()
			parties := setup(t, fx.ac, group, prng)
			outputs := tu.DoGennaroDKG(t, parties)

			var commonPK *k256.Point
			var commonVV *feldman.VerificationVector[*k256.Point, *k256.Scalar]
			for id, output := range outputs {
				if commonPK == nil {
					commonPK = output.PublicKeyValue()
					commonVV = output.VerificationVector()
				} else {
					require.True(t, commonPK.Equal(output.PublicKeyValue()),
						"participant %d has different public key", id)
					require.True(t, commonVV.Equal(output.VerificationVector()),
						"participant %d has different verification vector", id)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Share uniqueness: no two participants hold the same share value
// ---------------------------------------------------------------------------

func TestDKG_ShareUniqueness(t *testing.T) {
	t.Parallel()

	group := k256.NewCurve()
	prng := pcg.NewRandomised()
	fx := thresholdFixture(t)
	parties := setup(t, fx.ac, group, prng)
	outputs := tu.DoGennaroDKG(t, parties)

	seen := make(map[sharing.ID]*kw.Share[*k256.Scalar])
	for id, output := range outputs {
		for existingID, existingShare := range seen {
			require.False(t, output.Share().Equal(existingShare),
				"shares for participants %d and %d are identical", id, existingID)
		}
		seen[id] = output.Share()
	}
}

// ---------------------------------------------------------------------------
// Reconstruction: qualified sets can reconstruct the secret via Feldman VSS
// ---------------------------------------------------------------------------

func TestDKG_ReconstructionQualifiedSets(t *testing.T) {
	t.Parallel()

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			group := k256.NewCurve()
			prng := pcg.NewRandomised()
			parties := setup(t, fx.ac, group, prng)
			outputs := tu.DoGennaroDKG(t, parties)

			feldmanScheme, err := feldman.NewScheme(group, fx.ac)
			require.NoError(t, err)

			ref := firstOutput(outputs)
			vv := ref.VerificationVector()

			// Collect shares
			sharesByID := make(map[sharing.ID]*kw.Share[*k256.Scalar])
			for id, output := range outputs {
				sharesByID[id] = output.Share()
			}

			var referenceSecret *kw.Secret[*k256.Scalar]
			for _, qset := range fx.qualified {
				shares := make([]*kw.Share[*k256.Scalar], len(qset))
				for i, id := range qset {
					shares[i] = sharesByID[id]
				}
				secret, err := feldmanScheme.ReconstructAndVerify(vv, shares...)
				require.NoError(t, err, "qualified set %v should reconstruct", qset)

				if referenceSecret == nil {
					referenceSecret = secret
				} else {
					require.True(t, referenceSecret.Equal(secret),
						"different qualified sets reconstructed different secrets")
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Reconstruction: unqualified sets cannot reconstruct
// ---------------------------------------------------------------------------

func TestDKG_ReconstructionUnqualifiedSets(t *testing.T) {
	t.Parallel()

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			group := k256.NewCurve()
			prng := pcg.NewRandomised()
			parties := setup(t, fx.ac, group, prng)
			outputs := tu.DoGennaroDKG(t, parties)

			feldmanScheme, err := feldman.NewScheme(group, fx.ac)
			require.NoError(t, err)

			sharesByID := make(map[sharing.ID]*kw.Share[*k256.Scalar])
			for id, output := range outputs {
				sharesByID[id] = output.Share()
			}

			// Get the true secret from a qualified set
			qset := fx.qualified[0]
			qShares := make([]*kw.Share[*k256.Scalar], len(qset))
			for i, id := range qset {
				qShares[i] = sharesByID[id]
			}
			trueSecret, err := feldmanScheme.Reconstruct(qShares...)
			require.NoError(t, err)

			for _, uset := range fx.unqualified {
				shares := make([]*kw.Share[*k256.Scalar], len(uset))
				for i, id := range uset {
					shares[i] = sharesByID[id]
				}
				// Reconstruction should either fail or produce the wrong secret
				result, err := feldmanScheme.Reconstruct(shares...)
				if err == nil {
					require.False(t, trueSecret.Equal(result),
						"unqualified set %v should not reconstruct the correct secret", uset)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Reconstructed secret matches public key: [s]G == PK
// ---------------------------------------------------------------------------

func TestDKG_ReconstructedSecretMatchesPublicKey(t *testing.T) {
	t.Parallel()

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			group := k256.NewCurve()
			prng := pcg.NewRandomised()
			parties := setup(t, fx.ac, group, prng)
			outputs := tu.DoGennaroDKG(t, parties)

			feldmanScheme, err := feldman.NewScheme(group, fx.ac)
			require.NoError(t, err)

			ref := firstOutput(outputs)
			vv := ref.VerificationVector()
			publicKey := ref.PublicKeyValue()

			qset := fx.qualified[0]
			shares := make([]*kw.Share[*k256.Scalar], len(qset))
			i := 0
			for _, id := range qset {
				shares[i] = outputs[id].Share()
				i++
			}

			secret, err := feldmanScheme.ReconstructAndVerify(vv, shares...)
			require.NoError(t, err)

			reconstructedPK := group.ScalarBaseOp(secret.Value())
			require.True(t, reconstructedPK.Equal(publicKey),
				"reconstructed public key does not match DKG output")
			require.False(t, publicKey.IsZero(), "joint public key must not be the identity")
		})
	}
}

// ---------------------------------------------------------------------------
// DKG output internal consistency: VV, partial public keys, and shares agree
// ---------------------------------------------------------------------------

func TestDKG_OutputConsistency(t *testing.T) {
	t.Parallel()

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			group := k256.NewCurve()
			sf := group.ScalarField()
			prng := pcg.NewRandomised()
			parties := setup(t, fx.ac, group, prng)
			outputs := tu.DoGennaroDKG(t, parties)

			ref := firstOutput(outputs)
			vv := ref.VerificationVector()

			// Build a LiftedDealerFunc from the agreed-upon VV and MSP.
			lsss, err := kw.NewScheme(sf, fx.ac)
			require.NoError(t, err)
			ldf, err := feldman.NewLiftedDealerFunc(vv, lsss.MSP())
			require.NoError(t, err)

			t.Run("lifted secret equals public key", func(t *testing.T) {
				t.Parallel()
				liftedSecret := ldf.LiftedSecret()
				require.True(t, liftedSecret.Value().Equal(ref.PublicKeyValue()),
					"LiftedDealerFunc.LiftedSecret() must equal the DKG public key")
			})
		})
	}
}

// ---------------------------------------------------------------------------
// Participant creation validation
// ---------------------------------------------------------------------------

func TestNewParticipant_Validation(t *testing.T) {
	t.Parallel()

	group := k256.NewCurve()
	prng := pcg.NewRandomised()
	quorum := sharing.NewOrdinalShareholderSet(3)
	ac, err := threshold.NewThresholdAccessStructure(2, quorum)
	require.NoError(t, err)
	ctxs := session_testutils.MakeRandomContexts(t, quorum, prng)
	ctx := ctxs[1]

	t.Run("valid creation", func(t *testing.T) {
		t.Parallel()
		p, err := gennaro.NewParticipant(ctx, group, ac, fiatshamir.Name, prng)
		require.NoError(t, err)
		require.NotNil(t, p)
		require.Equal(t, sharing.ID(1), p.SharingID())
	})

	t.Run("nil group", func(t *testing.T) {
		t.Parallel()
		p, err := gennaro.NewParticipant[*k256.Point](ctx, nil, ac, fiatshamir.Name, prng)
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

// ---------------------------------------------------------------------------
// Round ordering
// ---------------------------------------------------------------------------

func TestRoundOutOfOrder(t *testing.T) {
	t.Parallel()

	group := k256.NewCurve()
	prng := pcg.NewRandomised()
	quorum := sharing.NewOrdinalShareholderSet(3)
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
}

// ---------------------------------------------------------------------------
// Round 1: broadcasts and unicasts are well-formed
// ---------------------------------------------------------------------------

func TestDKG_Round1Messages(t *testing.T) {
	t.Parallel()

	group := k256.NewCurve()
	prng := pcg.NewRandomised()
	fx := thresholdFixture(t)
	parties := setup(t, fx.ac, group, prng)
	r1bo, r1uo := tu.DoGennaroRound1(t, parties)

	require.Len(t, r1bo, len(fx.shareholders))
	require.Len(t, r1uo, len(fx.shareholders))
	for _, bc := range r1bo {
		require.NotNil(t, bc.PedersenVerificationVector)
		require.NotEmpty(t, bc.Proof)
	}
	for senderID, unicasts := range r1uo {
		require.Equal(t, len(fx.shareholders)-1, unicasts.Size())
		for receiverID, uc := range unicasts.Iter() {
			require.NotNil(t, uc.Share)
			require.NotEqual(t, senderID, receiverID)
		}
	}
}

// ---------------------------------------------------------------------------
// Round 2: broadcasts are well-formed
// ---------------------------------------------------------------------------

func TestDKG_Round2Messages(t *testing.T) {
	t.Parallel()

	group := k256.NewCurve()
	prng := pcg.NewRandomised()
	fx := thresholdFixture(t)
	parties := setup(t, fx.ac, group, prng)
	participants := slices.Collect(maps.Values(parties))
	r1bo, r1uo := tu.DoGennaroRound1(t, parties)
	r2bi, r2ui := ntu.MapO2I(t, participants, r1bo, r1uo)
	r2bo := tu.DoGennaroRound2(t, parties, r2bi, r2ui)

	require.Len(t, r2bo, len(fx.shareholders))
	for _, bc := range r2bo {
		require.NotNil(t, bc.FeldmanVerificationVector)
		require.NotEmpty(t, bc.Proof)
	}
}

// ---------------------------------------------------------------------------
// Proofs are non-empty
// ---------------------------------------------------------------------------

func TestDKG_ProofsAreNonEmpty(t *testing.T) {
	t.Parallel()

	f := newSecurityFixture(t)

	for id, bc := range f.r1bo {
		require.NotEmpty(t, bc.Proof, "party %d produced empty okamoto proof", id)
	}

	r2bo := tu.DoGennaroRound2(t, f.parties, f.r2bi, f.r2ui)
	for id, bc := range r2bo {
		require.NotEmpty(t, bc.Proof, "party %d produced empty schnorr proof", id)
	}
}

// ---------------------------------------------------------------------------
// Security fixture
// ---------------------------------------------------------------------------

type securityFixture struct {
	group   *k256.Curve
	ac      accessstructures.Linear
	parties map[sharing.ID]*gennaro.Participant[*k256.Point, *k256.Scalar]
	ids     []sharing.ID // sorted

	r1bo map[sharing.ID]*gennaro.Round1Broadcast[*k256.Point, *k256.Scalar]
	r1uo map[sharing.ID]network.OutgoingUnicasts[*gennaro.Round1Unicast[*k256.Point, *k256.Scalar], *gennaro.Participant[*k256.Point, *k256.Scalar]]
	r2bi map[sharing.ID]network.RoundMessages[*gennaro.Round1Broadcast[*k256.Point, *k256.Scalar], *gennaro.Participant[*k256.Point, *k256.Scalar]]
	r2ui map[sharing.ID]network.RoundMessages[*gennaro.Round1Unicast[*k256.Point, *k256.Scalar], *gennaro.Participant[*k256.Point, *k256.Scalar]]
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
		group: group, ac: ac, parties: parties, ids: ids,
		r1bo: r1bo, r1uo: r1uo, r2bi: r2bi, r2ui: r2ui,
	}
}

func replaceBroadcastFrom[M network.Message[*gennaro.Participant[*k256.Point, *k256.Scalar]]](
	original network.RoundMessages[M, *gennaro.Participant[*k256.Point, *k256.Scalar]], attackerID sharing.ID, replacement M,
) network.RoundMessages[M, *gennaro.Participant[*k256.Point, *k256.Scalar]] {
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

func replaceUnicastFrom[M network.Message[*gennaro.Participant[*k256.Point, *k256.Scalar]]](
	original network.RoundMessages[M, *gennaro.Participant[*k256.Point, *k256.Scalar]], attackerID sharing.ID, replacement M,
) network.RoundMessages[M, *gennaro.Participant[*k256.Point, *k256.Scalar]] {
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

// ---------------------------------------------------------------------------
// Security: tampered Okamoto proof → identifiable abort
// ---------------------------------------------------------------------------

func TestTamperedOkamotoProofRejected(t *testing.T) {
	t.Parallel()
	f := newSecurityFixture(t)
	victim, attacker := f.ids[0], f.ids[1]

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

// ---------------------------------------------------------------------------
// Security: tampered Pedersen VV → identifiable abort
// ---------------------------------------------------------------------------

func TestTamperedPedersenVVRejected(t *testing.T) {
	t.Parallel()
	f := newSecurityFixture(t)
	victim, attacker := f.ids[0], f.ids[1]

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

// ---------------------------------------------------------------------------
// Security: tampered Pedersen share → identifiable abort
// ---------------------------------------------------------------------------

func TestTamperedPedersenShareRejected(t *testing.T) {
	t.Parallel()
	f := newSecurityFixture(t)
	victim, attacker, other := f.ids[0], f.ids[1], f.ids[2]

	// Replace attacker's share to victim with a share from a different dealer
	wrongDealerShare, _ := f.r1uo[other].Get(victim)
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

// ---------------------------------------------------------------------------
// Security: tampered batch Schnorr proof → identifiable abort
// ---------------------------------------------------------------------------

func TestTamperedSchnorrProofRejected(t *testing.T) {
	t.Parallel()
	f := newSecurityFixture(t)
	victim, attacker := f.ids[0], f.ids[1]

	r2bo := tu.DoGennaroRound2(t, f.parties, f.r2bi, f.r2ui)
	participants := slices.Collect(maps.Values(f.parties))
	r3bi := ntu.MapBroadcastO2I(t, participants, r2bo)

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

// ---------------------------------------------------------------------------
// Security: tampered Feldman VV → identifiable abort
// ---------------------------------------------------------------------------

func TestTamperedFeldmanVVRejected(t *testing.T) {
	t.Parallel()
	f := newSecurityFixture(t)
	victim, attacker := f.ids[0], f.ids[1]

	r2bo := tu.DoGennaroRound2(t, f.parties, f.r2bi, f.r2ui)
	participants := slices.Collect(maps.Values(f.parties))
	r3bi := ntu.MapBroadcastO2I(t, participants, r2bo)

	// Replace attacker's Feldman VV with a different party's
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

// ---------------------------------------------------------------------------
// Security: rogue key attack prevention
//
// The Okamoto proof in R1 is bound to the prover's identity via the
// transcript. A rogue-key attacker who replays another party's valid
// broadcast (VV + proof) under their own identity will be rejected
// because the Fiat-Shamir challenge is derived from the claimed sender's
// ID, which won't match.
// ---------------------------------------------------------------------------

func TestRogueKeyAttackPrevented(t *testing.T) {
	t.Parallel()
	f := newSecurityFixture(t)
	victim, attacker, other := f.ids[0], f.ids[1], f.ids[2]

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

// ---------------------------------------------------------------------------
// Security: swapped Schnorr proof identity
//
// Same identity-binding test for the batch Schnorr proof in R2.
// Replaying another party's R2 broadcast under the attacker's ID should fail.
// ---------------------------------------------------------------------------

func TestSwappedSchnorrProofIdentityRejected(t *testing.T) {
	t.Parallel()
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

// ---------------------------------------------------------------------------
// Security: Feldman/Pedersen consistency
//
// The Feldman VV in R2 must be consistent with the Pedersen VV in R1: both
// encode the same secret column vector. Round 3 verifies the Feldman share
// (derived from the Pedersen share) against the Feldman VV.
// An attacker who sends a valid Feldman proof for a *different* secret
// column vector will be caught by the Feldman share verification.
//
// We simulate this by running two independent DKGs: take attacker's R2
// broadcast (Feldman VV + proof) from the second DKG and inject it into
// the first.
// ---------------------------------------------------------------------------

func TestFeldmanPedersenConsistencyCheck(t *testing.T) {
	t.Parallel()

	group := k256.NewCurve()
	prng := pcg.NewRandomised()
	quorum := sharing.NewOrdinalShareholderSet(3)
	ac, err := threshold.NewThresholdAccessStructure(2, quorum)
	require.NoError(t, err)

	// DKG 1
	parties1 := setup(t, ac, group, prng)
	participants1 := slices.Collect(maps.Values(parties1))
	r1bo1, r1uo1 := tu.DoGennaroRound1(t, parties1)
	r2bi1, r2ui1 := ntu.MapO2I(t, participants1, r1bo1, r1uo1)
	r2bo1 := tu.DoGennaroRound2(t, parties1, r2bi1, r2ui1)

	// DKG 2 (independent)
	parties2 := setup(t, ac, group, prng)
	participants2 := slices.Collect(maps.Values(parties2))
	r1bo2, r1uo2 := tu.DoGennaroRound1(t, parties2)
	r2bi2, r2ui2 := ntu.MapO2I(t, participants2, r1bo2, r1uo2)
	r2bo2 := tu.DoGennaroRound2(t, parties2, r2bi2, r2ui2)
	_ = r2bo2

	ids := slices.Sorted(maps.Keys(parties1))
	victim, attacker := ids[0], ids[1]

	r3bi1 := ntu.MapBroadcastO2I(t, participants1, r2bo1)
	tampered := r2bo2[attacker] // valid proof, but for a different secret column
	tamperedR3bi := replaceBroadcastFrom(r3bi1[victim], attacker, tampered)

	_, err = parties1[victim].Round3(tamperedR3bi)
	require.Error(t, err, "Feldman/Pedersen inconsistency should be detected")
	require.True(t, base.IsIdentifiableAbortError(err))
	culprits := base.GetMaliciousIdentities[sharing.ID](err)
	require.Contains(t, culprits, attacker)
}

// ---------------------------------------------------------------------------
// Security: extended Feldman VV (Dahlgren-style dimension attack)
//
// An attacker extends the Feldman verification vector with extra group
// elements, hoping to inject additional degrees of freedom. The Feldman
// verification via left module action M * V enforces dim(V) == MSP.D(),
// so the extended vector must be rejected.
// ---------------------------------------------------------------------------

func TestDahlgrenAttack_ExtendedFeldmanVV(t *testing.T) {
	t.Parallel()

	group := k256.NewCurve()
	field := k256.NewScalarField()
	prng := pcg.NewRandomised()
	gen := group.Generator()

	// Use threshold(4,7) so D=4 and n_rows=7 — clear distinction
	fx := largeThresholdFixture(t)
	parties := setup(t, fx.ac, group, prng)
	participants := slices.Collect(maps.Values(parties))
	r1bo, r1uo := tu.DoGennaroRound1(t, parties)
	r2bi, r2ui := ntu.MapO2I(t, participants, r1bo, r1uo)
	r2bo := tu.DoGennaroRound2(t, parties, r2bi, r2ui)
	r3bi := ntu.MapBroadcastO2I(t, participants, r2bo)

	ids := slices.Sorted(maps.Keys(parties))
	victim, attacker := ids[0], ids[1]

	// Get attacker's honest VV and extend it with an extra row
	originalBC, _ := r3bi[victim].Get(attacker)
	honestVV := originalBC.FeldmanVerificationVector

	// Determine honest dimension from the VV
	honestD, _ := honestVV.Value().Dimensions()

	// Build extended column vector with D+1 entries
	extraScalar, err := field.Random(prng)
	require.NoError(t, err)
	extMod, err := mat.NewMatrixModule(uint(honestD+1), 1, field)
	require.NoError(t, err)
	entries := make([]*k256.Scalar, honestD+1)
	for i := range honestD {
		entries[i], err = field.Random(prng)
		require.NoError(t, err)
	}
	entries[honestD] = extraScalar
	extCol, err := extMod.NewRowMajor(entries...)
	require.NoError(t, err)
	extendedVVV, err := mat.Lift(extCol, gen)
	require.NoError(t, err)
	extendedVV, err := feldman.NewVerificationVector(extendedVVV, nil)
	require.NoError(t, err)

	tampered := &gennaro.Round2Broadcast[*k256.Point, *k256.Scalar]{
		FeldmanVerificationVector: extendedVV,
		Proof:                     originalBC.Proof,
	}
	tamperedR3bi := replaceBroadcastFrom(r3bi[victim], attacker, tampered)

	_, err = parties[victim].Round3(tamperedR3bi)
	require.Error(t, err, "extended VV must be rejected (Dahlgren-style dimension attack)")
}

// ---------------------------------------------------------------------------
// Security: truncated Feldman VV (dimension attack - too few entries)
// ---------------------------------------------------------------------------

func TestTruncatedFeldmanVV_Rejected(t *testing.T) {
	t.Parallel()

	group := k256.NewCurve()
	field := k256.NewScalarField()
	prng := pcg.NewRandomised()
	gen := group.Generator()

	fx := largeThresholdFixture(t) // D=4
	parties := setup(t, fx.ac, group, prng)
	participants := slices.Collect(maps.Values(parties))
	r1bo, r1uo := tu.DoGennaroRound1(t, parties)
	r2bi, r2ui := ntu.MapO2I(t, participants, r1bo, r1uo)
	r2bo := tu.DoGennaroRound2(t, parties, r2bi, r2ui)
	r3bi := ntu.MapBroadcastO2I(t, participants, r2bo)

	ids := slices.Sorted(maps.Keys(parties))
	victim, attacker := ids[0], ids[1]

	originalBC, _ := r3bi[victim].Get(attacker)

	// Build a truncated column vector with D-1 entries
	honestD, _ := originalBC.FeldmanVerificationVector.Value().Dimensions()
	require.Greater(t, honestD, 1, "need D>1 to truncate")
	truncMod, err := mat.NewMatrixModule(uint(honestD-1), 1, field)
	require.NoError(t, err)
	entries := make([]*k256.Scalar, honestD-1)
	for i := range honestD - 1 {
		entries[i], err = field.Random(prng)
		require.NoError(t, err)
	}
	truncCol, err := truncMod.NewRowMajor(entries...)
	require.NoError(t, err)
	truncatedVVV, err := mat.Lift(truncCol, gen)
	require.NoError(t, err)
	truncatedVV, err := feldman.NewVerificationVector(truncatedVVV, nil)
	require.NoError(t, err)

	tampered := &gennaro.Round2Broadcast[*k256.Point, *k256.Scalar]{
		FeldmanVerificationVector: truncatedVV,
		Proof:                     originalBC.Proof,
	}
	tamperedR3bi := replaceBroadcastFrom(r3bi[victim], attacker, tampered)

	_, err = parties[victim].Round3(tamperedR3bi)
	require.Error(t, err, "truncated VV must be rejected")
}

// ---------------------------------------------------------------------------
// Security: extended Pedersen VV (dimension attack on Round 2)
// ---------------------------------------------------------------------------

func TestDahlgrenAttack_ExtendedPedersenVV(t *testing.T) {
	t.Parallel()

	group := k256.NewCurve()
	field := k256.NewScalarField()
	prng := pcg.NewRandomised()

	fx := largeThresholdFixture(t) // D=4
	parties := setup(t, fx.ac, group, prng)
	participants := slices.Collect(maps.Values(parties))
	r1bo, r1uo := tu.DoGennaroRound1(t, parties)
	r2bi, r2ui := ntu.MapO2I(t, participants, r1bo, r1uo)
	_ = r2ui

	ids := slices.Sorted(maps.Keys(parties))
	victim, attacker := ids[0], ids[1]

	originalBC, _ := r2bi[victim].Get(attacker)

	// Get honest Pedersen VV dimension
	honestD, _ := originalBC.PedersenVerificationVector.Value().Dimensions()

	// Build an extended Pedersen VV by appending a random commitment
	extPedMod, err := mat.NewModuleValuedColumnVectorModule(uint(honestD+1), group)
	require.NoError(t, err)
	entries := make([]*k256.Point, honestD+1)
	for i := range honestD {
		e, err := originalBC.PedersenVerificationVector.Value().Get(i, 0)
		require.NoError(t, err)
		entries[i] = e
	}
	// Add a random extra entry
	extraScalar, err := field.Random(prng)
	require.NoError(t, err)
	entries[honestD] = group.Generator().ScalarOp(extraScalar)
	extendedPedVVV, err := extPedMod.NewRowMajor(entries...)
	require.NoError(t, err)
	extendedPedVV, err := feldman.NewVerificationVector(extendedPedVVV, nil)
	require.NoError(t, err)

	tampered := &gennaro.Round1Broadcast[*k256.Point, *k256.Scalar]{
		PedersenVerificationVector: extendedPedVV,
		Proof:                      originalBC.Proof,
	}
	tamperedR2bi := replaceBroadcastFrom(r2bi[victim], attacker, tampered)

	// The Okamoto proof was composed for D instances, but the VV now has D+1
	// elements. Verification should fail (either proof mismatch or share
	// verification against mismatched VV).
	_, err = parties[victim].Round2(tamperedR2bi, r2ui[victim])
	require.Error(t, err, "extended Pedersen VV must be rejected")
}

// ---------------------------------------------------------------------------
// Two independent DKG runs produce different keys
// ---------------------------------------------------------------------------

func TestDKG_Freshness(t *testing.T) {
	t.Parallel()

	group := k256.NewCurve()
	prng := pcg.NewRandomised()
	fx := thresholdFixture(t)

	parties1 := setup(t, fx.ac, group, prng)
	outputs1 := tu.DoGennaroDKG(t, parties1)

	parties2 := setup(t, fx.ac, group, prng)
	outputs2 := tu.DoGennaroDKG(t, parties2)

	pk1 := firstOutput(outputs1).PublicKeyValue()
	pk2 := firstOutput(outputs2).PublicKeyValue()
	require.False(t, pk1.Equal(pk2), "independent DKG runs should produce different public keys")
}

// ---------------------------------------------------------------------------
// Non-threshold access structures: CNF
// ---------------------------------------------------------------------------

func TestDKG_CNF(t *testing.T) {
	t.Parallel()

	group := k256.NewCurve()
	prng := pcg.NewRandomised()
	fx := cnfFixture(t)
	parties := setup(t, fx.ac, group, prng)
	outputs := tu.DoGennaroDKG(t, parties)

	feldmanScheme, err := feldman.NewScheme(group, fx.ac)
	require.NoError(t, err)
	vv := firstOutput(outputs).VerificationVector()

	sharesByID := make(map[sharing.ID]*kw.Share[*k256.Scalar])
	for id, out := range outputs {
		sharesByID[id] = out.Share()
	}

	// All qualified sets reconstruct the same secret
	var ref *kw.Secret[*k256.Scalar]
	for _, qset := range fx.qualified {
		shares := make([]*kw.Share[*k256.Scalar], len(qset))
		for i, id := range qset {
			shares[i] = sharesByID[id]
		}
		secret, err := feldmanScheme.ReconstructAndVerify(vv, shares...)
		require.NoError(t, err, "qualified set %v should reconstruct", qset)
		if ref == nil {
			ref = secret
		} else {
			require.True(t, ref.Equal(secret))
		}
	}

	// Unqualified sets cannot
	for _, uset := range fx.unqualified {
		shares := make([]*kw.Share[*k256.Scalar], len(uset))
		for i, id := range uset {
			shares[i] = sharesByID[id]
		}
		result, err := feldmanScheme.Reconstruct(shares...)
		if err == nil {
			require.False(t, ref.Equal(result),
				"unqualified set %v should not reconstruct the correct secret", uset)
		}
	}
}
