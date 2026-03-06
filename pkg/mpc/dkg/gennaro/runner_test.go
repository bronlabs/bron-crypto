package gennaro_test

import (
	"bytes"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/curve25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/iterutils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/dkg/gennaro"
	tu "github.com/bronlabs/bron-crypto/pkg/mpc/dkg/gennaro/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/feldman"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
	"github.com/stretchr/testify/require"
)

func TestHappyPath(t *testing.T) {
	t.Parallel()

	const iters = 1
	testAccessStructures := []struct{ threshold, total int }{
		{2, 3},
		{3, 5},
		{6, 6},
	}
	testNiCompilers := []compiler.Name{
		fiatshamir.Name,
	}

	for _, as := range testAccessStructures {
		t.Run(fmt.Sprintf("%d/%d", as.threshold, as.total), func(t *testing.T) {
			t.Parallel()

			for _, niCompiler := range testNiCompilers {
				t.Run(string(niCompiler), func(t *testing.T) {
					t.Parallel()

					t.Run("k256", func(t *testing.T) {
						t.Parallel()
						testHappyPathRunner(t, iters, k256.NewCurve(), as.threshold, as.total, niCompiler)
					})

					t.Run("p256", func(t *testing.T) {
						t.Parallel()
						testHappyPathRunner(t, iters, p256.NewCurve(), as.threshold, as.total, niCompiler)
					})

					t.Run("edwards25519", func(t *testing.T) {
						t.Parallel()
						testHappyPathRunner(t, iters, edwards25519.NewPrimeSubGroup(), as.threshold, as.total, niCompiler)
					})

					t.Run("curve25519", func(t *testing.T) {
						t.Parallel()
						testHappyPathRunner(t, iters, curve25519.NewPrimeSubGroup(), as.threshold, as.total, niCompiler)
					})

					t.Run("pallas", func(t *testing.T) {
						t.Parallel()
						testHappyPathRunner(t, iters, pasta.NewPallasCurve(), as.threshold, as.total, niCompiler)
					})

					t.Run("vesta", func(t *testing.T) {
						t.Parallel()
						testHappyPathRunner(t, iters, pasta.NewVestaCurve(), as.threshold, as.total, niCompiler)
					})

					t.Run("BLS12381G1", func(t *testing.T) {
						t.Parallel()
						testHappyPathRunner(t, iters, bls12381.NewG1(), as.threshold, as.total, niCompiler)
					})

					t.Run("BLS12381G2", func(t *testing.T) {
						t.Parallel()
						testHappyPathRunner(t, iters, bls12381.NewG2(), as.threshold, as.total, niCompiler)
					})
				})
			}
		})
	}
}

func testHappyPathRunner[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](t *testing.T, iters int, group algebra.PrimeGroup[G, S], threshold, total int, niCompiler compiler.Name) {
	t.Helper()

	for i := range iters {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			prng := pcg.NewRandomised()
			quorum := ntu.MakeRandomQuorum(t, prng, total)
			ctxs := session_testutils.MakeRandomContexts(t, quorum, prng)
			accessStructure, err := accessstructures.NewThresholdAccessStructure(uint(threshold), quorum)
			require.NoError(t, err)

			runners := tu.MakeGennaroDKGRunners(t, ctxs, accessStructure, niCompiler, group)
			dkgOutputs := ntu.TestExecuteRunners(t, runners)

			t.Run("public materials are consistent", func(t *testing.T) {
				t.Parallel()

				var commonPublicMaterial *gennaro.DKGPublicOutput[G, S]
				for id := range quorum.Iter() {
					publicMaterial := dkgOutputs[id].PublicMaterial()
					require.NotNil(t, publicMaterial)

					if commonPublicMaterial == nil {
						commonPublicMaterial = publicMaterial
					} else {
						require.True(t, commonPublicMaterial.AccessStructure().Equal(publicMaterial.AccessStructure()))
						require.True(t, commonPublicMaterial.VerificationVector().Equal(publicMaterial.VerificationVector()))
						require.True(t, commonPublicMaterial.PublicKeyValue().Equal(publicMaterial.PublicKeyValue()))
						for id2 := range quorum.Iter() {
							l, ok := commonPublicMaterial.PartialPublicKeyValues().Get(id2)
							require.True(t, ok)
							r, ok := commonPublicMaterial.PartialPublicKeyValues().Get(id2)
							require.True(t, ok)
							require.True(t, l.Equal(r))
						}
					}
				}
			})

			t.Run("secret shares are consistent", func(t *testing.T) {
				t.Parallel()

				publicKeyValue := dkgOutputs[quorum.List()[0]].PublicKeyValue()
				ac, err := accessstructures.NewThresholdAccessStructure(uint(threshold), quorum)
				require.NoError(t, err)
				dealer, err := feldman.NewScheme(group.Generator(), ac)
				require.NoError(t, err)

				shares := slices.Collect(iterutils.Map(maps.Values(dkgOutputs), func(output *gennaro.DKGOutput[G, S]) *feldman.Share[S] { return output.Share() }))
				for sharesSubset := range sliceutils.KCoveringCombinations(shares, uint(threshold)) {
					reconstructedSecretKey, err := dealer.Reconstruct(sharesSubset...)
					require.NoError(t, err)
					reconstructedPublicKeyValue := group.ScalarBaseOp(reconstructedSecretKey.Value())

					require.True(t, reconstructedPublicKeyValue.Equal(publicKeyValue))
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
		})
	}
}
