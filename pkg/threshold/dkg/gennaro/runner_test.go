package gennaro_test

import (
	crand "crypto/rand"
	"fmt"
	"io"
	"maps"
	"reflect"
	"slices"
	"strconv"
	"sync"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/curve25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/iterutils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/dkg/gennaro"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/shamir"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

func TestHappyPath(t *testing.T) {
	t.Parallel()

	testAccessStructures := []struct{ threshold, total int }{
		{2, 2},
		{2, 3},
		{2, 4},
		{3, 5},
		{6, 6},
	}

	for _, as := range testAccessStructures {
		t.Run(fmt.Sprintf("%d/%d", as.threshold, as.total), func(t *testing.T) {
			t.Parallel()

			t.Run("k256", func(t *testing.T) {
				t.Parallel()
				testHappyPathRunner(t, k256.NewCurve(), as.threshold, as.total)
			})

			t.Run("p256", func(t *testing.T) {
				t.Parallel()
				testHappyPathRunner(t, p256.NewCurve(), as.threshold, as.total)
			})

			t.Run("edwards25519", func(t *testing.T) {
				t.Parallel()
				testHappyPathRunner(t, edwards25519.NewPrimeSubGroup(), as.threshold, as.total)
			})

			t.Run("curve25519", func(t *testing.T) {
				t.Parallel()
				testHappyPathRunner(t, curve25519.NewPrimeSubGroup(), as.threshold, as.total)
			})

			t.Run("pallas", func(t *testing.T) {
				t.Parallel()
				testHappyPathRunner(t, pasta.NewPallasCurve(), as.threshold, as.total)
			})

			t.Run("vesta", func(t *testing.T) {
				t.Parallel()
				testHappyPathRunner(t, pasta.NewVestaCurve(), as.threshold, as.total)
			})

			t.Run("BLS12381G1", func(t *testing.T) {
				t.Parallel()
				testHappyPathRunner(t, bls12381.NewG1(), as.threshold, as.total)
			})

			t.Run("BLS12381G2", func(t *testing.T) {
				t.Parallel()
				testHappyPathRunner(t, bls12381.NewG2(), as.threshold, as.total)
			})
		})
	}
}

func testHappyPathRunner[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](t *testing.T, group algebra.PrimeGroup[G, S], threshold, total int) {
	t.Helper()
	const reps = 16

	for i := range reps {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			t.Parallel()

			prng := crand.Reader
			var sessionId network.SID
			_, err := io.ReadFull(prng, sessionId[:])
			require.NoError(t, err)

			ids := sharing.NewOrdinalShareholderSet(uint(total))
			accessStructure, err := shamir.NewAccessStructure(uint(threshold), ids)
			require.NoError(t, err)
			tapes := make(map[sharing.ID]transcripts.Transcript)
			for id := range ids.Iter() {
				tapes[id] = hagrid.NewTranscript("test")
			}
			coordinator := testutils.NewMockCoordinator(slices.Collect(ids.Iter())...)
			dkgOutputs := make(map[sharing.ID]*gennaro.DKGOutput[G, S])
			dkgOutputsMutex := sync.Mutex{}

			runner := func(sharingId sharing.ID) error {
				router := coordinator.RouterFor(sharingId)
				dkgOutput, err := gennaro.RunGennaroDKG(router, sessionId, group, sharingId, accessStructure, tapes[sharingId], prng)
				if err != nil {
					return err
				}
				dkgOutputsMutex.Lock()
				defer dkgOutputsMutex.Unlock()
				dkgOutputs[sharingId] = dkgOutput
				return nil
			}

			var errGroup errgroup.Group
			for id := range ids.Iter() {
				errGroup.Go(func() error { return runner(id) })
			}
			err = errGroup.Wait()
			require.NoError(t, err)

			t.Run("public keys are consistent", func(t *testing.T) {
				t.Parallel()

				var commonPublicKey G
				for _, output := range dkgOutputs {
					pk := output.PublicKeyValue()
					require.False(t, pk.IsOpIdentity())

					if reflect.ValueOf(commonPublicKey).IsNil() {
						commonPublicKey = pk
					} else {
						require.True(t, commonPublicKey.Equal(pk))
					}
				}
			})

			t.Run("secret keys are consistent", func(t *testing.T) {
				t.Parallel()

				publicKey := dkgOutputs[ids.List()[0]].PublicKeyValue()
				dealer, err := feldman.NewScheme(group.Generator(), uint(threshold), ids)
				require.NoError(t, err)

				shares := slices.Collect(iterutils.Map(maps.Values(dkgOutputs), func(output *gennaro.DKGOutput[G, S]) *feldman.Share[S] { return output.Share() }))
				for sharesSubset := range sliceutils.KCoveringCombinations(shares, uint(threshold)) {
					reconstructedSecretKey, err := dealer.Reconstruct(sharesSubset...)
					require.NoError(t, err)
					require.True(t, group.ScalarBaseOp(reconstructedSecretKey.Value()).Equal(publicKey))
				}
			})
		})
	}
}
