package gennaro_test

import (
	"bytes"
	"maps"
	"slices"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/iterutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc"
	tu "github.com/bronlabs/bron-crypto/pkg/mpc/dkg/meta/gennaro/testutils"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/meta/feldman"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
	"github.com/stretchr/testify/require"
)

func TestRunnerHappyPath(t *testing.T) {
	t.Parallel()

	testNiCompilers := []compiler.Name{
		fiatshamir.Name,
	}

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()

			for _, niCompiler := range testNiCompilers {
				t.Run(string(niCompiler), func(t *testing.T) {
					t.Parallel()
					t.Run("p256", func(t *testing.T) {
						t.Parallel()
						testRunnerHappyPath(t, p256.NewCurve(), fx.ac, niCompiler)
					})
					t.Run("BLS12381G2", func(t *testing.T) {
						t.Parallel()
						testRunnerHappyPath(t, bls12381.NewG2(), fx.ac, niCompiler)
					})
				})
			}
		})
	}
}

func testRunnerHappyPath[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](t *testing.T, group algebra.PrimeGroup[G, S], ac accessstructures.Monotone, niCompiler compiler.Name) {
	t.Helper()

	prng := pcg.NewRandomised()
	quorum := ac.Shareholders()
	ctxs := session_testutils.MakeRandomContexts(t, quorum, prng)

	runners := tu.MakeGennaroDKGRunners(t, ctxs, ac, niCompiler, group)
	dkgOutputs := ntu.TestExecuteRunners(t, runners)

	t.Run("public materials are consistent", func(t *testing.T) {
		t.Parallel()

		var commonPublicMaterial *mpc.BasePublicMaterial[G, S]
		for id := range quorum.Iter() {
			publicMaterial := dkgOutputs[id].BasePublicMaterial
			require.NotNil(t, publicMaterial)

			if commonPublicMaterial == nil {
				commonPublicMaterial = &publicMaterial
			} else {
				require.True(t, commonPublicMaterial.VerificationVector().Equal(publicMaterial.VerificationVector()))
				require.True(t, commonPublicMaterial.PublicKeyValue().Equal(publicMaterial.PublicKeyValue()))
				require.True(t, commonPublicMaterial.MSP().Shareholders().Equal(publicMaterial.MSP().Shareholders()))
			}
		}
	})

	t.Run("secret shares are consistent", func(t *testing.T) {
		t.Parallel()

		publicKeyValue := dkgOutputs[quorum.List()[0]].PublicKeyValue()
		feldmanScheme, err := feldman.NewScheme(group, ac)
		require.NoError(t, err)

		vv := dkgOutputs[quorum.List()[0]].VerificationVector()
		shares := slices.Collect(iterutils.Map(maps.Values(dkgOutputs), func(output *mpc.BaseShard[G, S]) *kw.Share[S] { return output.Share() }))

		// Reconstruct from all shares and verify against public key.
		secret, err := feldmanScheme.ReconstructAndVerify(vv, shares...)
		require.NoError(t, err)
		reconstructedPublicKeyValue := group.ScalarBaseOp(secret.Value())
		require.True(t, reconstructedPublicKeyValue.Equal(publicKeyValue))
	})

	t.Run("output consistency", func(t *testing.T) {
		t.Parallel()

		ref := dkgOutputs[quorum.List()[0]]
		vv := ref.VerificationVector()
		sf := algebra.StructureMustBeAs[algebra.PrimeField[S]](group.ScalarStructure())
		lsss, err := kw.NewScheme(sf, ac)
		require.NoError(t, err)
		ldf, err := feldman.NewLiftedDealerFunc(vv, lsss.MSP())
		require.NoError(t, err)

		// Lifted secret from VV must equal the public key.
		require.True(t, ldf.LiftedSecret().Value().Equal(ref.PublicKeyValue()))

		for id := range quorum.Iter() {
			output := dkgOutputs[id]

			// Partial public key must match VV-derived lifted share.
			expectedPPK, err := ldf.ShareOf(id)
			require.NoError(t, err)
			actualPPK, ok := ref.PublicKeyShares().Get(id)
			require.True(t, ok)
			require.True(t, expectedPPK.Equal(actualPPK),
				"partial public key for %d doesn't match VV-derived lifted share", id)

			// Partial public key must match the manually lifted scalar share.
			lifted, err := feldman.LiftShare(output.Share(), group.Generator())
			require.NoError(t, err)
			require.True(t, lifted.Equal(actualPPK),
				"LiftShare(share) for %d doesn't match partial public key", id)
		}
	})

	t.Run("transcripts are consistent", func(t *testing.T) {
		t.Parallel()

		tapeSamples := [][]byte{}
		for id := range quorum.Iter() {
			tape := ctxs[id].Transcript()
			tapeSample, err := tape.ExtractBytes("test", 32)
			require.NoError(t, err)
			tapeSamples = append(tapeSamples, tapeSample)
		}

		for s := 1; s < len(tapeSamples); s++ {
			require.True(t, bytes.Equal(tapeSamples[s-1], tapeSamples[s]))
		}
	})
}
