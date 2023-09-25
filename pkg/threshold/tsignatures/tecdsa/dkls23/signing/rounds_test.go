package signing_test

import (
	"crypto/sha256"
	"fmt"
	"hash"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
	"gonum.org/v1/gonum/stat/combin"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/protocols"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	testutils_integration "github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/csprng/chacha20"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls23"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls23/testutils"
)

func testHappyPath(t *testing.T, protocol protocols.Protocol, curve curves.Curve, h func() hash.Hash, threshold, n int, message []byte) {
	t.Helper()

	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  h,
	}

	allIdentities, err := testutils_integration.MakeIdentities(cipherSuite, n)
	require.NoError(t, err)

	cohortConfig, err := testutils_integration.MakeCohortProtocol(cipherSuite, protocol, allIdentities, threshold, allIdentities)
	require.NoError(t, err)

	shards, err := testutils.RunDKG(curve, cohortConfig, allIdentities)
	require.NoError(t, err)

	seededPrng, err := chacha20.NewChachaPRNG(nil, nil)
	require.NoError(t, err)

	combinations := combin.Combinations(n, threshold)
	for _, combinationIndices := range combinations {
		identities := make([]integration.IdentityKey, threshold)
		selectedShards := make([]*dkls23.Shard, threshold)
		for i, index := range combinationIndices {
			identities[i] = allIdentities[index]
			selectedShards[i] = shards[index]
		}
		t.Run(fmt.Sprintf("running the happy path with identities %v", identities), func(t *testing.T) {
			t.Parallel()
			err := testutils.RunInteractiveSign(cohortConfig, identities, selectedShards, message, seededPrng)
			require.NoError(t, err)
		})
	}
}

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	for _, curve := range []curves.Curve{k256.New(), p256.New()} {
		for _, h := range []func() hash.Hash{sha256.New, sha3.New256} {
			for _, thresholdConfig := range []struct {
				t int
				n int
			}{
				{t: 2, n: 3},
				{t: 2, n: 2},
				{t: 3, n: 5},
			} {
				boundedCurve := curve
				boundedHash := h
				boundedHashName := runtime.FuncForPC(reflect.ValueOf(h).Pointer()).Name()
				boundedThresholdConfig := thresholdConfig
				t.Run(fmt.Sprintf("Interactive sign happy path with curve=%s and hash=%s and t=%d and n=%d", boundedCurve.Name(), boundedHashName[strings.LastIndex(boundedHashName, "/")+1:], boundedThresholdConfig.t, boundedThresholdConfig.n), func(t *testing.T) {
					t.Parallel()
					testHappyPath(t, protocols.DKLS23, boundedCurve, boundedHash, boundedThresholdConfig.t, boundedThresholdConfig.n, []byte("Hello World!"))
				})
			}
		}
	}
}
