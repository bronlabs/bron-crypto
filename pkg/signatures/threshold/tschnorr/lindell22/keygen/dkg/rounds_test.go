package dkg_test

import (
	"crypto/sha512"
	"fmt"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/lindell22/test_utils"
	"hash"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/edwards25519"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/k256"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	test_utils_integration "github.com/copperexchange/knox-primitives/pkg/core/integration/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/core/protocols"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

func TestRunProfile(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping profiling test in short mode")
	}
	if os.Getenv("PROFILE_T") == "" || os.Getenv("PROFILE_N") == "" {
		t.Skip("skipping profiling test missing parameter")
	}
	var curve curves.Curve
	var h func() hash.Hash
	th, _ := strconv.Atoi(os.Getenv("PROFILE_T"))
	n, _ := strconv.Atoi(os.Getenv("PROFILE_N"))
	if os.Getenv("PROFILE_CURVE") == "ED25519" {
		curve = edwards25519.New()
	} else {
		curve = k256.New()
	}
	if os.Getenv("PROFILE_HASH") == "SHA3" {
		h = sha3.New256
	} else {
		h = sha512.New
	}
	for i := 0; i < 1000; i++ {
		testHappyPath(t, curve, h, th, n)
	}
}

func testHappyPath(t *testing.T, curve curves.Curve, h func() hash.Hash, threshold int, n int) {
	t.Helper()

	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  h,
	}

	identities, err := test_utils_integration.MakeIdentities(cipherSuite, n)
	require.NoError(t, err)
	cohortConfig, err := test_utils_integration.MakeCohortProtocol(cipherSuite, protocols.FROST, identities, threshold, identities)
	require.NoError(t, err)

	shards, err := test_utils.DoKeygen(curve, identities, cohortConfig)
	require.NoError(t, err)
	for _, shard := range shards {
		err = shard.Validate(cohortConfig)
		require.NoError(t, err)
	}
}

func Test_HappyPath(t *testing.T) {
	t.Parallel()
	for _, curve := range []curves.Curve{k256.New(), edwards25519.New()} {
		for _, h := range []func() hash.Hash{sha3.New256, sha512.New} {
			for _, thresholdConfig := range []struct {
				t int
				n int
			}{
				{t: 2, n: 2},
				{t: 2, n: 3},
				{t: 3, n: 3},
			} {
				boundedCurve := curve
				boundedHash := h
				boundedHashName := runtime.FuncForPC(reflect.ValueOf(h).Pointer()).Name()
				boundedThresholdConfig := thresholdConfig
				t.Run(fmt.Sprintf("Happy path with curve=%s and hash=%s and t=%d and n=%d", boundedCurve.Name(), boundedHashName[strings.LastIndex(boundedHashName, "/")+1:], boundedThresholdConfig.t, boundedThresholdConfig.n), func(t *testing.T) {
					t.Parallel()
					testHappyPath(t, boundedCurve, boundedHash, boundedThresholdConfig.t, boundedThresholdConfig.n)
				})
			}
		}
	}
}
