package gjkr07_test

import (
	"fmt"
	"io"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"github.com/bronlabs/bron-crypto/pkg/mpc/dkg/meta/gjkr07"
	tu "github.com/bronlabs/bron-crypto/pkg/mpc/dkg/meta/gjkr07/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/isn"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/shamir"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/meta/feldman"
	pedersenVSS "github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/meta/pedersen"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
)

// ---------------------------------------------------------------------------
// Shamir type aliases & helpers
// ---------------------------------------------------------------------------

type shamirParticipant = gjkr07.Participant[
	*shamir.Share[*k256.Scalar], *k256.Scalar,
	*shamir.Secret[*k256.Scalar], *k256.Scalar,
	*shamir.DealerOutput[*k256.Scalar],
	*accessstructures.Threshold,
	*shamir.DealerFunc[*k256.Scalar],
	*shamir.LiftedDealerFunc[*k256.Point, *k256.Scalar],
	*shamir.LiftedShare[*k256.Point, *k256.Scalar],
	*k256.Point,
	*shamir.LiftedSecret[*k256.Point, *k256.Scalar],
	*k256.Point,
]

type shamirDKGOutput = gjkr07.DKGOutput[
	*shamir.LiftedDealerFunc[*k256.Point, *k256.Scalar],
	*shamir.LiftedShare[*k256.Point, *k256.Scalar],
	*k256.Point,
	*shamir.Share[*k256.Scalar],
	*k256.Scalar,
	*accessstructures.Threshold,
]

func setupShamir(
	t *testing.T, threshold, total uint, group *k256.Curve, prng io.Reader,
) (
	ac *accessstructures.Threshold,
	parties ds.MutableMap[sharing.ID, *shamirParticipant],
) {
	t.Helper()
	shareholders := sharing.NewOrdinalShareholderSet(total)
	ac, err := accessstructures.NewThresholdAccessStructure(threshold, shareholders)
	require.NoError(t, err)

	liftableScheme, err := shamir.NewLiftableScheme(group, ac)
	require.NoError(t, err)

	ctxs := session_testutils.MakeRandomContexts(t, shareholders, prng)
	parties = hashmap.NewComparable[sharing.ID, *shamirParticipant]()
	for id, ctx := range ctxs {
		p, err := gjkr07.NewParticipant(ctx, group, liftableScheme, ac, fiatshamir.Name, prng)
		require.NoError(t, err)
		parties.Put(id, p)
	}
	return ac, parties
}

func doShamirDKG(t *testing.T, parties ds.MutableMap[sharing.ID, *shamirParticipant]) (ds.MutableMap[sharing.ID, *shamirDKGOutput], error) {
	t.Helper()
	return tu.DoDKG(t, parties.Values())
}

func newShamirFeldmanScheme(t *testing.T, group *k256.Curve, ac *accessstructures.Threshold) *feldman.Scheme[
	*shamir.Share[*k256.Scalar], *k256.Scalar,
	*shamir.Secret[*k256.Scalar], *k256.Scalar,
	*shamir.DealerOutput[*k256.Scalar],
	*accessstructures.Threshold,
	*shamir.DealerFunc[*k256.Scalar],
	*shamir.LiftedDealerFunc[*k256.Point, *k256.Scalar],
	*shamir.LiftedShare[*k256.Point, *k256.Scalar],
	*k256.Point,
	*shamir.LiftedSecret[*k256.Point, *k256.Scalar],
	*k256.Point,
] {
	t.Helper()
	liftableScheme, err := shamir.NewLiftableScheme(group, ac)
	require.NoError(t, err)
	feldmanScheme, err := feldman.NewScheme(group.Generator(), liftableScheme)
	require.NoError(t, err)
	return feldmanScheme
}

// ---------------------------------------------------------------------------
// ISN type aliases & helpers
// ---------------------------------------------------------------------------

type isnParticipant = gjkr07.Participant[
	*isn.Share[*k256.Scalar], *k256.Scalar,
	*isn.Secret[*k256.Scalar], *k256.Scalar,
	*isn.DealerOutput[*k256.Scalar],
	*accessstructures.CNF,
	isn.DealerFunc[*k256.Scalar],
	isn.LiftedDealerFunc[*k256.Point, *k256.Scalar],
	*isn.LiftedShare[*k256.Point],
	*k256.Point,
	*isn.LiftedSecret[*k256.Point, *k256.Scalar],
	*k256.Point,
]

type isnDKGOutput = gjkr07.DKGOutput[
	isn.LiftedDealerFunc[*k256.Point, *k256.Scalar],
	*isn.LiftedShare[*k256.Point],
	*k256.Point,
	*isn.Share[*k256.Scalar],
	*k256.Scalar,
	*accessstructures.CNF,
]

// makeThresholdCNF builds a CNF access structure equivalent to a t-of-n threshold
// by enumerating all (t-1)-element subsets of {1..n} as maximal unqualified sets.
func makeThresholdCNF(threshold, total uint) *accessstructures.CNF {
	ids := make([]sharing.ID, total)
	for i := range total {
		ids[i] = sharing.ID(i + 1)
	}
	subsetSize := int(threshold - 1)
	var sets []ds.Set[sharing.ID]
	var generate func(start, depth int, current []sharing.ID)
	generate = func(start, depth int, current []sharing.ID) {
		if depth == subsetSize {
			sets = append(sets, hashset.NewComparable(current...).Freeze())
			return
		}
		for i := start; i < len(ids); i++ {
			generate(i+1, depth+1, append(current, ids[i]))
		}
	}
	generate(0, 0, nil)
	cnf, err := accessstructures.NewCNFAccessStructure(sets...)
	if err != nil {
		panic(fmt.Sprintf("makeThresholdCNF(%d, %d): %v", threshold, total, err))
	}
	return cnf
}

func setupISN(
	t *testing.T, cnf *accessstructures.CNF, group *k256.Curve, prng io.Reader,
) (
	*accessstructures.CNF,
	ds.MutableMap[sharing.ID, *isnParticipant],
) {
	t.Helper()

	liftableScheme, err := isn.NewFiniteLiftableScheme(group, cnf)
	require.NoError(t, err)

	ctxs := session_testutils.MakeRandomContexts(t, cnf.Shareholders(), prng)
	parties := hashmap.NewComparable[sharing.ID, *isnParticipant]()
	for id, ctx := range ctxs {
		p, err := gjkr07.NewParticipant(ctx, group, liftableScheme, cnf, fiatshamir.Name, prng)
		require.NoError(t, err)
		parties.Put(id, p)
	}
	return cnf, parties
}

func doISNDKG(t *testing.T, parties ds.MutableMap[sharing.ID, *isnParticipant]) (ds.MutableMap[sharing.ID, *isnDKGOutput], error) {
	t.Helper()
	return tu.DoDKG(t, parties.Values())
}

func newISNFeldmanScheme(t *testing.T, group *k256.Curve, cnf *accessstructures.CNF) *feldman.Scheme[
	*isn.Share[*k256.Scalar], *k256.Scalar,
	*isn.Secret[*k256.Scalar], *k256.Scalar,
	*isn.DealerOutput[*k256.Scalar],
	*accessstructures.CNF,
	isn.DealerFunc[*k256.Scalar],
	isn.LiftedDealerFunc[*k256.Point, *k256.Scalar],
	*isn.LiftedShare[*k256.Point],
	*k256.Point,
	*isn.LiftedSecret[*k256.Point, *k256.Scalar],
	*k256.Point,
] {
	t.Helper()
	liftableScheme, err := isn.NewFiniteLiftableScheme(group, cnf)
	require.NoError(t, err)
	feldmanScheme, err := feldman.NewScheme(group.Generator(), liftableScheme)
	require.NoError(t, err)
	return feldmanScheme
}

// ---------------------------------------------------------------------------
// Type-erased result + suite definition
// ---------------------------------------------------------------------------

type dkgOutputEntry struct {
	ID               sharing.ID
	PublicKey        *k256.Point
	ShareID          sharing.ID
	ShareholderCount int
}

type dkgResult struct {
	Entries                      []dkgOutputEntry
	VVsConsistent                bool
	ReconstructAll               func(t *testing.T)
	ReconstructSubsets           func(t *testing.T, combos [][]sharing.ID)
	ReconstructInExponentSubsets func(t *testing.T, combos [][]sharing.ID)
}

type dkgSuite struct {
	name                  string
	total                 int
	qualifiedSubsets      [][]sharing.ID // subsets that should all reconstruct to the same secret
	run                   func(t *testing.T, prng io.Reader) *dkgResult
	checkDeterminism      func(t *testing.T)
	checkRound1Broadcasts func(t *testing.T)
	checkValidation       func(t *testing.T)
	checkRoundOrdering    func(t *testing.T)
	checkMalicious        func(t *testing.T)
}

// ---------------------------------------------------------------------------
// Shamir dkgResult builder
// ---------------------------------------------------------------------------

func shamirDKGResult(
	t *testing.T,
	group *k256.Curve,
	ac *accessstructures.Threshold,
	outputs ds.MutableMap[sharing.ID, *shamirDKGOutput],
) *dkgResult {
	t.Helper()

	var entries []dkgOutputEntry
	var referenceVV *shamir.LiftedDealerFunc[*k256.Point, *k256.Scalar]
	vvsConsistent := true
	shares := make([]*shamir.Share[*k256.Scalar], 0, outputs.Size())

	for id, output := range outputs.Iter() {
		entries = append(entries, dkgOutputEntry{
			ID:               id,
			PublicKey:        output.PublicKeyValue(),
			ShareID:          output.Share().ID(),
			ShareholderCount: output.AccessStructure().Shareholders().Size(),
		})
		shares = append(shares, output.Share())
		if referenceVV == nil {
			referenceVV = output.VerificationVector()
		} else if !sharing.DealerFuncsAreEqual(referenceVV, output.VerificationVector()) {
			vvsConsistent = false
		}
	}

	feldmanScheme := newShamirFeldmanScheme(t, group, ac)
	liftableScheme, err := shamir.NewLiftableScheme(group, ac)
	require.NoError(t, err)
	capturedVV := referenceVV
	capturedShares := shares
	expectedPK := entries[0].PublicKey

	return &dkgResult{
		Entries:       entries,
		VVsConsistent: vvsConsistent,
		ReconstructAll: func(t *testing.T) {
			t.Helper()
			secret, err := feldmanScheme.ReconstructAndVerify(capturedVV, capturedShares...)
			require.NoError(t, err)
			require.NotNil(t, secret)
			require.False(t, secret.Value().IsZero())
		},
		ReconstructSubsets: func(t *testing.T, combos [][]sharing.ID) {
			t.Helper()
			sharesByID := make(map[sharing.ID]*shamir.Share[*k256.Scalar])
			for _, s := range capturedShares {
				sharesByID[s.ID()] = s
			}
			var secrets []*shamir.Secret[*k256.Scalar]
			for _, combo := range combos {
				subset := make([]*shamir.Share[*k256.Scalar], 0, len(combo))
				for _, id := range combo {
					subset = append(subset, sharesByID[id])
				}
				secret, err := feldmanScheme.ReconstructAndVerify(capturedVV, subset...)
				require.NoError(t, err)
				secrets = append(secrets, secret)
			}
			for i := 1; i < len(secrets); i++ {
				require.True(t, secrets[0].Equal(secrets[i]),
					"all threshold subsets should reconstruct to the same secret")
			}
		},
		ReconstructInExponentSubsets: func(t *testing.T, combos [][]sharing.ID) {
			t.Helper()
			for _, combo := range combos {
				liftedShares := make([]*shamir.LiftedShare[*k256.Point, *k256.Scalar], 0, len(combo))
				for _, id := range combo {
					liftedShares = append(liftedShares, capturedVV.ShareOf(id))
				}
				liftedSecret, err := liftableScheme.ReconstructInExponent(liftedShares...)
				require.NoError(t, err, "ReconstructInExponent failed for combo %v", combo)
				require.True(t, expectedPK.Equal(liftedSecret.Value()),
					"ReconstructInExponent for combo %v should yield the public key", combo)
			}
		},
	}
}

// ---------------------------------------------------------------------------
// ISN dkgResult builder
// ---------------------------------------------------------------------------

func isnDKGResult(
	t *testing.T,
	group *k256.Curve,
	cnf *accessstructures.CNF,
	outputs ds.MutableMap[sharing.ID, *isnDKGOutput],
) *dkgResult {
	t.Helper()

	var entries []dkgOutputEntry
	var referenceVV isn.LiftedDealerFunc[*k256.Point, *k256.Scalar]
	vvsConsistent := true
	first := true
	shares := make([]*isn.Share[*k256.Scalar], 0, outputs.Size())

	for id, output := range outputs.Iter() {
		entries = append(entries, dkgOutputEntry{
			ID:               id,
			PublicKey:        output.PublicKeyValue(),
			ShareID:          output.Share().ID(),
			ShareholderCount: output.AccessStructure().Shareholders().Size(),
		})
		shares = append(shares, output.Share())
		if first {
			referenceVV = output.VerificationVector()
			first = false
		} else if !sharing.DealerFuncsAreEqual(referenceVV, output.VerificationVector()) {
			vvsConsistent = false
		}
	}

	feldmanScheme := newISNFeldmanScheme(t, group, cnf)
	liftableScheme, err := isn.NewFiniteLiftableScheme(group, cnf)
	require.NoError(t, err)
	capturedVV := referenceVV
	capturedShares := shares
	expectedPK := entries[0].PublicKey

	return &dkgResult{
		Entries:       entries,
		VVsConsistent: vvsConsistent,
		ReconstructAll: func(t *testing.T) {
			t.Helper()
			secret, err := feldmanScheme.ReconstructAndVerify(capturedVV, capturedShares...)
			require.NoError(t, err)
			require.NotNil(t, secret)
			require.False(t, secret.Value().IsZero())
		},
		ReconstructSubsets: func(t *testing.T, combos [][]sharing.ID) {
			t.Helper()
			sharesByID := make(map[sharing.ID]*isn.Share[*k256.Scalar])
			for _, s := range capturedShares {
				sharesByID[s.ID()] = s
			}
			var secrets []*isn.Secret[*k256.Scalar]
			for _, combo := range combos {
				subset := make([]*isn.Share[*k256.Scalar], 0, len(combo))
				for _, id := range combo {
					subset = append(subset, sharesByID[id])
				}
				secret, err := feldmanScheme.ReconstructAndVerify(capturedVV, subset...)
				require.NoError(t, err)
				secrets = append(secrets, secret)
			}
			for i := 1; i < len(secrets); i++ {
				require.True(t, secrets[0].Equal(secrets[i]),
					"all threshold subsets should reconstruct to the same secret")
			}
		},
		ReconstructInExponentSubsets: func(t *testing.T, combos [][]sharing.ID) {
			t.Helper()
			for _, combo := range combos {
				liftedShares := make([]*isn.LiftedShare[*k256.Point], 0, len(combo))
				for _, id := range combo {
					liftedShares = append(liftedShares, capturedVV.ShareOf(id))
				}
				liftedSecret, err := liftableScheme.ReconstructInExponent(liftedShares...)
				require.NoError(t, err, "ReconstructInExponent failed for combo %v", combo)
				require.True(t, expectedPK.Equal(liftedSecret.Value()),
					"ReconstructInExponent for combo %v should yield the public key", combo)
			}
		},
	}
}

// ---------------------------------------------------------------------------
// Suite constructors
// ---------------------------------------------------------------------------

func shamirSuite(threshold, total uint) dkgSuite {
	name := fmt.Sprintf("shamir/%d-of-%d", threshold, total)

	// All k-combinations for k in [threshold..total] are qualified.
	ids := make([]sharing.ID, total)
	for i := range total {
		ids[i] = sharing.ID(i + 1)
	}
	subsets := slices.Collect(sliceutils.KCoveringCombinations(ids, threshold))

	return dkgSuite{
		name:             name,
		total:            int(total),
		qualifiedSubsets: subsets,
		run: func(t *testing.T, prng io.Reader) *dkgResult {
			t.Helper()
			group := k256.NewCurve()
			ac, parties := setupShamir(t, threshold, total, group, prng)
			outputs, err := doShamirDKG(t, parties)
			require.NoError(t, err)
			return shamirDKGResult(t, group, ac, outputs)
		},
		checkDeterminism: func(t *testing.T) {
			t.Helper()
			group := k256.NewCurve()
			seed1, seed2 := uint64(42), uint64(1337)

			prng1 := pcg.New(seed1, seed2)
			_, parties1 := setupShamir(t, threshold, total, group, prng1)
			outputs1, err := doShamirDKG(t, parties1)
			require.NoError(t, err)

			prng2 := pcg.New(seed1, seed2)
			_, parties2 := setupShamir(t, threshold, total, group, prng2)
			outputs2, err := doShamirDKG(t, parties2)
			require.NoError(t, err)

			for id, output1 := range outputs1.Iter() {
				output2, ok := outputs2.Get(id)
				require.True(t, ok)
				require.True(t, output1.Share().Value().Equal(output2.Share().Value()))
				require.True(t, sharing.DealerFuncsAreEqual(output1.VerificationVector(), output2.VerificationVector()))
			}
		},
		checkRound1Broadcasts: func(t *testing.T) {
			t.Helper()
			group := k256.NewCurve()
			prng := pcg.NewRandomised()

			_, parties := setupShamir(t, threshold, total, group, prng)
			r1broadcasts, err := tu.DoRound1(parties.Values())
			require.NoError(t, err)
			require.Len(t, r1broadcasts, int(total))

			for i, broadcast := range r1broadcasts {
				require.NotNil(t, broadcast.PedersenVerificationVector)
				for j, other := range r1broadcasts {
					if i != j {
						require.False(t, sharing.DealerFuncsAreEqual(broadcast.PedersenVerificationVector, other.PedersenVerificationVector))
					}
				}
			}
		},
		checkValidation: func(t *testing.T) {
			t.Helper()
			group := k256.NewCurve()
			prng := pcg.NewRandomised()

			shareholders := sharing.NewOrdinalShareholderSet(total)
			ac, err := accessstructures.NewThresholdAccessStructure(threshold, shareholders)
			require.NoError(t, err)
			liftableScheme, err := shamir.NewLiftableScheme(group, ac)
			require.NoError(t, err)

			ctxs := session_testutils.MakeRandomContexts(t, shareholders, prng)
			ctx := ctxs[sharing.ID(1)]

			newParticipant := func(ctx *session.Context, grp *k256.Curve, lsss *shamir.LiftableScheme[*k256.Point, *k256.Scalar], ac *accessstructures.Threshold, prng io.Reader) (*shamirParticipant, error) {
				return gjkr07.NewParticipant(ctx, grp, lsss, ac, fiatshamir.Name, prng)
			}

			t.Run("nil context", func(t *testing.T) {
				t.Parallel()
				_, err := newParticipant(nil, group, liftableScheme, ac, prng)
				require.Error(t, err)
				require.ErrorIs(t, err, gjkr07.ErrInvalidArgument)
			})

			t.Run("nil group", func(t *testing.T) {
				t.Parallel()
				_, err := newParticipant(ctx, nil, liftableScheme, ac, prng)
				require.Error(t, err)
				require.ErrorIs(t, err, gjkr07.ErrInvalidArgument)
			})

			t.Run("nil prng", func(t *testing.T) {
				t.Parallel()
				_, err := newParticipant(ctx, group, liftableScheme, ac, nil)
				require.Error(t, err)
				require.ErrorIs(t, err, gjkr07.ErrInvalidArgument)
			})

			t.Run("nil access structure", func(t *testing.T) {
				t.Parallel()
				_, err := newParticipant(ctx, group, liftableScheme, nil, prng)
				require.Error(t, err)
				require.ErrorIs(t, err, gjkr07.ErrInvalidArgument)
			})

			t.Run("access structure mismatch with context", func(t *testing.T) {
				t.Parallel()
				mismatch, err := accessstructures.NewThresholdAccessStructure(threshold, hashset.NewComparable[sharing.ID](1, 2, 4).Freeze())
				require.NoError(t, err)
				_, err = newParticipant(ctx, group, liftableScheme, mismatch, prng)
				require.Error(t, err)
				require.ErrorIs(t, err, gjkr07.ErrInvalidArgument)
			})

			t.Run("minimum participants", func(t *testing.T) {
				t.Parallel()
				minShareholders := sharing.NewOrdinalShareholderSet(threshold)
				minAC, err := accessstructures.NewThresholdAccessStructure(threshold, minShareholders)
				require.NoError(t, err)
				lsss, err := shamir.NewLiftableScheme(group, minAC)
				require.NoError(t, err)

				minCtxs := session_testutils.MakeRandomContexts(t, minShareholders, prng)
				parties := hashmap.NewComparable[sharing.ID, *shamirParticipant]()
				for id, minCtx := range minCtxs {
					p, err := newParticipant(minCtx, group, lsss, minAC, prng)
					require.NoError(t, err)
					parties.Put(id, p)
				}
				outputs, err := doShamirDKG(t, parties)
				require.NoError(t, err)
				require.Equal(t, int(threshold), outputs.Size())
			})
		},
		checkRoundOrdering: func(t *testing.T) {
			t.Helper()
			group := k256.NewCurve()
			prng := pcg.NewRandomised()

			_, parties := setupShamir(t, threshold, total, group, prng)
			participant := parties.Values()[0]

			t.Run("cannot execute round 2 before round 1", func(t *testing.T) {
				dummyR2Input := hashmap.NewComparable[sharing.ID, *gjkr07.Round1Broadcast[
					*shamir.LiftedDealerFunc[*k256.Point, *k256.Scalar],
					*shamir.LiftedShare[*k256.Point, *k256.Scalar],
					*k256.Point, *k256.Scalar,
					*accessstructures.Threshold,
				]]().Freeze()

				_, _, err := participant.Round2(dummyR2Input)
				require.Error(t, err)
				require.ErrorIs(t, err, gjkr07.ErrRound)
			})

			t.Run("cannot execute round 3 before completing previous rounds", func(t *testing.T) {
				dummyR3Broadcast := hashmap.NewComparable[sharing.ID, *gjkr07.Round2Broadcast[
					*shamir.LiftedDealerFunc[*k256.Point, *k256.Scalar],
					*shamir.LiftedShare[*k256.Point, *k256.Scalar],
					*k256.Point, *k256.Scalar,
					*accessstructures.Threshold,
				]]().Freeze()
				dummyR3Unicast := hashmap.NewComparable[sharing.ID, *gjkr07.Round2Unicast[
					*shamir.Share[*k256.Scalar], *k256.Scalar,
				]]().Freeze()

				_, err := participant.Round3(dummyR3Broadcast, dummyR3Unicast)
				require.Error(t, err)
				require.ErrorIs(t, err, gjkr07.ErrRound)
			})

			t.Run("cannot re-execute round 1", func(t *testing.T) {
				_, err := participant.Round1()
				require.NoError(t, err)

				_, err = participant.Round1()
				require.Error(t, err)
				require.ErrorIs(t, err, gjkr07.ErrRound)
			})
		},
		checkMalicious: func(t *testing.T) {
			t.Helper()
			group := k256.NewCurve()
			prng := pcg.NewRandomised()

			_, parties := setupShamir(t, threshold, total, group, prng)

			r1broadcasts, err := tu.DoRound1(parties.Values())
			require.NoError(t, err)
			r2inputs := ntu.MapBroadcastO2I(t, parties.Values(), r1broadcasts)

			r2broadcasts, r2unicasts, err := tu.DoRound2(parties.Values(), r2inputs)
			require.NoError(t, err)

			maliciousID := sharing.ID(1)
			victimID := sharing.ID(2)

			maliciousUnicasts := hashmap.NewComparable[sharing.ID, *gjkr07.Round2Unicast[*shamir.Share[*k256.Scalar], *k256.Scalar]]()
			for id, msg := range r2unicasts[maliciousID].Iter() {
				if id == victimID {
					originalShare := msg.Share
					scalarField := k256.NewScalarField()

					corruptedSecretValue := originalShare.Secret().Value().Add(scalarField.One())
					corruptedSecret, err := shamir.NewShare(originalShare.Secret().ID(), corruptedSecretValue, nil)
					require.NoError(t, err)

					corruptedPedersenShare, err := pedersenVSS.NewShare(corruptedSecret, originalShare.Blinding())
					require.NoError(t, err)

					maliciousUnicasts.Put(id, &gjkr07.Round2Unicast[*shamir.Share[*k256.Scalar], *k256.Scalar]{
						Share: corruptedPedersenShare,
					})
				} else {
					maliciousUnicasts.Put(id, msg)
				}
			}
			r2unicasts[maliciousID] = maliciousUnicasts.Freeze()

			r3broadcastInputs := ntu.MapBroadcastO2I(t, parties.Values(), r2broadcasts)
			r3unicastInputs := ntu.MapUnicastO2I(t, parties.Values(), r2unicasts)

			for _, participant := range parties.Values() {
				output, err := participant.Round3(r3broadcastInputs[participant.SharingID()], r3unicastInputs[participant.SharingID()])
				if participant.SharingID() == victimID {
					require.Error(t, err)
					require.ErrorIs(t, err, commitments.ErrVerificationFailed)
					require.True(t, base.IsIdentifiableAbortError(err))
					culprits := base.GetMaliciousIdentities[sharing.ID](err)
					require.Len(t, culprits, 1)
					require.Contains(t, culprits, maliciousID)
					require.Nil(t, output)
				} else if participant.SharingID() != maliciousID {
					require.NoError(t, err)
					require.NotNil(t, output)
				}
			}
		},
	}
}

func isnThresholdSuite(threshold, total uint) dkgSuite {
	name := fmt.Sprintf("isn/%d-of-%d-cnf", threshold, total)
	cnf := makeThresholdCNF(threshold, total)
	return isnSuiteFromCNF(name, cnf)
}

func isnCustomSuite(name string, cnf *accessstructures.CNF) dkgSuite {
	return isnSuiteFromCNF("isn/"+name, cnf)
}

// qualifiedSubsetsForCNF enumerates all subsets of size >= 2 from the CNF's
// shareholders and returns those that are qualified (i.e. not contained in any
// maximal unqualified set). Used to build reconstruction test cases.
func qualifiedSubsetsForCNF(cnf *accessstructures.CNF) [][]sharing.ID {
	ids := make([]sharing.ID, 0, cnf.Shareholders().Size())
	for id := range cnf.Shareholders().Iter() {
		ids = append(ids, id)
	}
	slices.Sort(ids)

	var result [][]sharing.ID
	for combo := range sliceutils.KCoveringCombinations(ids, 2) {
		if cnf.IsQualified(combo...) {
			result = append(result, combo)
		}
	}
	return result
}

func isnSuiteFromCNF(name string, cnf *accessstructures.CNF) dkgSuite {
	totalShareholders := cnf.Shareholders().Size()
	return dkgSuite{
		name:             name,
		total:            totalShareholders,
		qualifiedSubsets: qualifiedSubsetsForCNF(cnf),
		run: func(t *testing.T, prng io.Reader) *dkgResult {
			t.Helper()
			group := k256.NewCurve()
			cnf, parties := setupISN(t, cnf, group, prng)
			outputs, err := doISNDKG(t, parties)
			require.NoError(t, err)
			return isnDKGResult(t, group, cnf, outputs)
		},
		checkDeterminism: func(t *testing.T) {
			t.Helper()
			group := k256.NewCurve()
			seed1, seed2 := uint64(42), uint64(1337)

			prng1 := pcg.New(seed1, seed2)
			_, parties1 := setupISN(t, cnf, group, prng1)
			outputs1, err := doISNDKG(t, parties1)
			require.NoError(t, err)

			prng2 := pcg.New(seed1, seed2)
			_, parties2 := setupISN(t, cnf, group, prng2)
			outputs2, err := doISNDKG(t, parties2)
			require.NoError(t, err)

			for id, output1 := range outputs1.Iter() {
				output2, ok := outputs2.Get(id)
				require.True(t, ok)
				require.True(t, output1.Share().Equal(output2.Share()))
				require.True(t, sharing.DealerFuncsAreEqual(output1.VerificationVector(), output2.VerificationVector()))
			}
		},
		checkRound1Broadcasts: func(t *testing.T) {
			t.Helper()
			group := k256.NewCurve()
			prng := pcg.NewRandomised()

			_, parties := setupISN(t, cnf, group, prng)
			r1broadcasts, err := tu.DoRound1(parties.Values())
			require.NoError(t, err)
			require.Len(t, r1broadcasts, totalShareholders)

			for i, broadcast := range r1broadcasts {
				require.NotNil(t, broadcast.PedersenVerificationVector)
				for j, other := range r1broadcasts {
					if i != j {
						require.False(t, sharing.DealerFuncsAreEqual(broadcast.PedersenVerificationVector, other.PedersenVerificationVector))
					}
				}
			}
		},
		checkValidation: func(t *testing.T) {
			t.Helper()
			group := k256.NewCurve()
			prng := pcg.NewRandomised()

			liftableScheme, err := isn.NewFiniteLiftableScheme(group, cnf)
			require.NoError(t, err)

			ctxs := session_testutils.MakeRandomContexts(t, cnf.Shareholders(), prng)
			ctx := ctxs[sharing.ID(1)]

			newParticipant := func(ctx *session.Context, grp *k256.Curve, lsss *isn.LiftableScheme[*k256.Point, *k256.Scalar], ac *accessstructures.CNF, prng io.Reader) (*isnParticipant, error) {
				return gjkr07.NewParticipant(ctx, grp, lsss, ac, fiatshamir.Name, prng)
			}

			t.Run("nil context", func(t *testing.T) {
				t.Parallel()
				_, err := newParticipant(nil, group, liftableScheme, cnf, prng)
				require.Error(t, err)
				require.ErrorIs(t, err, gjkr07.ErrInvalidArgument)
			})

			t.Run("nil group", func(t *testing.T) {
				t.Parallel()
				_, err := newParticipant(ctx, nil, liftableScheme, cnf, prng)
				require.Error(t, err)
				require.ErrorIs(t, err, gjkr07.ErrInvalidArgument)
			})

			t.Run("nil prng", func(t *testing.T) {
				t.Parallel()
				_, err := newParticipant(ctx, group, liftableScheme, cnf, nil)
				require.Error(t, err)
				require.ErrorIs(t, err, gjkr07.ErrInvalidArgument)
			})

			t.Run("nil access structure", func(t *testing.T) {
				t.Parallel()
				_, err := newParticipant(ctx, group, liftableScheme, nil, prng)
				require.Error(t, err)
				require.ErrorIs(t, err, gjkr07.ErrInvalidArgument)
			})

			t.Run("access structure mismatch with context", func(t *testing.T) {
				t.Parallel()
				mismatchCNF, err := accessstructures.NewCNFAccessStructure(
					hashset.NewComparable[sharing.ID](5, 6).Freeze(),
				)
				require.NoError(t, err)
				_, err = newParticipant(ctx, group, liftableScheme, mismatchCNF, prng)
				require.Error(t, err)
				require.ErrorIs(t, err, gjkr07.ErrInvalidArgument)
			})
		},
		checkRoundOrdering: func(t *testing.T) {
			t.Helper()
			group := k256.NewCurve()
			prng := pcg.NewRandomised()

			_, parties := setupISN(t, cnf, group, prng)
			participant := parties.Values()[0]

			t.Run("cannot execute round 2 before round 1", func(t *testing.T) {
				dummyR2Input := hashmap.NewComparable[sharing.ID, *gjkr07.Round1Broadcast[
					isn.LiftedDealerFunc[*k256.Point, *k256.Scalar],
					*isn.LiftedShare[*k256.Point],
					*k256.Point, *k256.Scalar,
					*accessstructures.CNF,
				]]().Freeze()

				_, _, err := participant.Round2(dummyR2Input)
				require.Error(t, err)
				require.ErrorIs(t, err, gjkr07.ErrRound)
			})

			t.Run("cannot execute round 3 before completing previous rounds", func(t *testing.T) {
				dummyR3Broadcast := hashmap.NewComparable[sharing.ID, *gjkr07.Round2Broadcast[
					isn.LiftedDealerFunc[*k256.Point, *k256.Scalar],
					*isn.LiftedShare[*k256.Point],
					*k256.Point, *k256.Scalar,
					*accessstructures.CNF,
				]]().Freeze()
				dummyR3Unicast := hashmap.NewComparable[sharing.ID, *gjkr07.Round2Unicast[
					*isn.Share[*k256.Scalar], *k256.Scalar,
				]]().Freeze()

				_, err := participant.Round3(dummyR3Broadcast, dummyR3Unicast)
				require.Error(t, err)
				require.ErrorIs(t, err, gjkr07.ErrRound)
			})

			t.Run("cannot re-execute round 1", func(t *testing.T) {
				_, err := participant.Round1()
				require.NoError(t, err)

				_, err = participant.Round1()
				require.Error(t, err)
				require.ErrorIs(t, err, gjkr07.ErrRound)
			})
		},
		checkMalicious: func(t *testing.T) {
			t.Helper()
			group := k256.NewCurve()
			prng := pcg.NewRandomised()

			_, parties := setupISN(t, cnf, group, prng)

			r1broadcasts, err := tu.DoRound1(parties.Values())
			require.NoError(t, err)
			r2inputs := ntu.MapBroadcastO2I(t, parties.Values(), r1broadcasts)

			r2broadcasts, r2unicasts, err := tu.DoRound2(parties.Values(), r2inputs)
			require.NoError(t, err)

			maliciousID := sharing.ID(1)
			victimID := sharing.ID(2)

			maliciousUnicasts := hashmap.NewComparable[sharing.ID, *gjkr07.Round2Unicast[*isn.Share[*k256.Scalar], *k256.Scalar]]()
			for id, msg := range r2unicasts[maliciousID].Iter() {
				if id == victimID {
					originalShare := msg.Share
					scalarField := k256.NewScalarField()

					originalISNShare := originalShare.Secret()
					reprValues := slices.Collect(originalISNShare.Repr())
					reprValues[0] = reprValues[0].Add(scalarField.One())

					isnScheme, err := isn.NewFiniteScheme(scalarField, cnf)
					require.NoError(t, err)
					corruptedISNShare, err := isnScheme.NewShareFromRepr(originalISNShare.ID(), slices.Values(reprValues))
					require.NoError(t, err)

					corruptedPedersenShare, err := pedersenVSS.NewShare(corruptedISNShare, originalShare.Blinding())
					require.NoError(t, err)

					maliciousUnicasts.Put(id, &gjkr07.Round2Unicast[*isn.Share[*k256.Scalar], *k256.Scalar]{
						Share: corruptedPedersenShare,
					})
				} else {
					maliciousUnicasts.Put(id, msg)
				}
			}
			r2unicasts[maliciousID] = maliciousUnicasts.Freeze()

			r3broadcastInputs := ntu.MapBroadcastO2I(t, parties.Values(), r2broadcasts)
			r3unicastInputs := ntu.MapUnicastO2I(t, parties.Values(), r2unicasts)

			for _, participant := range parties.Values() {
				output, err := participant.Round3(r3broadcastInputs[participant.SharingID()], r3unicastInputs[participant.SharingID()])
				if participant.SharingID() == victimID {
					require.Error(t, err)
					require.ErrorIs(t, err, commitments.ErrVerificationFailed)
					require.True(t, base.IsIdentifiableAbortError(err))
					culprits := base.GetMaliciousIdentities[sharing.ID](err)
					require.Len(t, culprits, 1)
					require.Contains(t, culprits, maliciousID)
					require.Nil(t, output)
				} else if participant.SharingID() != maliciousID {
					require.NoError(t, err)
					require.NotNil(t, output)
				}
			}
		},
	}
}

// ---------------------------------------------------------------------------
// Default suites
// ---------------------------------------------------------------------------

var defaultNonThresholdCNF = func() *accessstructures.CNF {
	// Non-threshold over 4 shareholders: max unqualified = {1}, {2,3}.
	// Qualified sets must include someone outside {1} AND outside {2,3},
	// i.e. must include one of {2,3,4} AND one of {1,4}.
	// Examples: {1,2} ✓, {1,3} ✓, {2,4} ✓, {1,2,3} ✓, but {2,3} ✗, {4} ✗.
	cnf, err := accessstructures.NewCNFAccessStructure(
		hashset.NewComparable[sharing.ID](1).Freeze(),
		hashset.NewComparable[sharing.ID](2, 3).Freeze(),
	)
	if err != nil {
		panic(err)
	}
	return cnf
}()

var defaultSuites = []dkgSuite{
	shamirSuite(2, 3),
	isnThresholdSuite(2, 3),
	isnCustomSuite("non-threshold-3", defaultNonThresholdCNF),
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestDKGWithVariousConfigurations(t *testing.T) {
	t.Parallel()

	customCNF, err := accessstructures.NewCNFAccessStructure(
		hashset.NewComparable[sharing.ID](1, 2).Freeze(),
		hashset.NewComparable[sharing.ID](3, 4, 5).Freeze(),
	)
	require.NoError(t, err)

	suites := []dkgSuite{
		shamirSuite(2, 3),
		shamirSuite(3, 5),
		shamirSuite(4, 4),
		isnThresholdSuite(2, 3),
		isnCustomSuite("custom-cnf", customCNF),
	}
	for _, s := range suites {
		t.Run(s.name, func(t *testing.T) {
			t.Parallel()
			r := s.run(t, pcg.NewRandomised())
			require.Len(t, r.Entries, s.total)
			require.True(t, r.VVsConsistent)
			for _, e := range r.Entries {
				require.Equal(t, e.ID, e.ShareID)
			}
			r.ReconstructAll(t)

			// For threshold-like structures with 3 shareholders, test subset reconstruction
			if s.total == 3 {
				r.ReconstructSubsets(t, [][]sharing.ID{
					{1, 2},
					{1, 3},
					{2, 3},
					{1, 2, 3},
				})
			}
		})
	}
}

func TestDKGPublicKeyFields(t *testing.T) {
	t.Parallel()
	for _, s := range defaultSuites {
		t.Run(s.name, func(t *testing.T) {
			t.Parallel()
			r := s.run(t, pcg.NewRandomised())
			var commonPK *k256.Point
			for _, e := range r.Entries {
				require.NotNil(t, e.PublicKey, "participant %d has nil public key", e.ID)
				require.False(t, e.PublicKey.IsZero(), "participant %d has zero public key", e.ID)
				if commonPK == nil {
					commonPK = e.PublicKey
				} else {
					require.True(t, commonPK.Equal(e.PublicKey), "participant %d has different public key", e.ID)
				}
			}
		})
	}
}

func TestDKGShareProperties(t *testing.T) {
	t.Parallel()
	for _, s := range defaultSuites {
		t.Run(s.name, func(t *testing.T) {
			t.Parallel()
			r := s.run(t, pcg.NewRandomised())

			t.Run("share IDs match participant IDs", func(t *testing.T) {
				t.Parallel()
				for _, e := range r.Entries {
					require.Equal(t, e.ID, e.ShareID)
				}
			})

			t.Run("verification vectors consistency", func(t *testing.T) {
				t.Parallel()
				require.True(t, r.VVsConsistent, "all outputs should have identical verification vectors")
			})

			t.Run("share reconstruction subsets", func(t *testing.T) {
				t.Parallel()
				r.ReconstructSubsets(t, s.qualifiedSubsets)
			})

			t.Run("partial public keys reconstruct to public key", func(t *testing.T) {
				t.Parallel()
				r.ReconstructInExponentSubsets(t, s.qualifiedSubsets)
			})
		})
	}
}

func TestDKGRoundMessages(t *testing.T) {
	t.Parallel()
	for _, s := range defaultSuites {
		t.Run(s.name, func(t *testing.T) {
			t.Parallel()
			s.checkRound1Broadcasts(t)
		})
	}
}

func TestDKGDeterminism(t *testing.T) {
	t.Parallel()
	for _, s := range defaultSuites {
		t.Run(s.name, func(t *testing.T) {
			t.Parallel()
			s.checkDeterminism(t)
		})
	}
}

func TestDKGParticipantValidation(t *testing.T) {
	t.Parallel()
	for _, s := range defaultSuites {
		t.Run(s.name, func(t *testing.T) {
			t.Parallel()
			s.checkValidation(t)
		})
	}
}

func TestRoundOutOfOrder(t *testing.T) {
	t.Parallel()
	for _, s := range defaultSuites {
		t.Run(s.name, func(t *testing.T) {
			t.Parallel()
			s.checkRoundOrdering(t)
		})
	}
}

func TestMaliciousParticipants(t *testing.T) {
	t.Parallel()
	for _, s := range defaultSuites {
		t.Run(s.name, func(t *testing.T) {
			t.Parallel()
			s.checkMalicious(t)
		})
	}
}
