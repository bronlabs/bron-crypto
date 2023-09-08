package dkg_test

import (
	crand "crypto/rand"
	"crypto/sha512"
	"fmt"
	"github.com/copperexchange/krypton/pkg/base/types/integration"
	testutils_integration "github.com/copperexchange/krypton/pkg/base/types/integration/testutils"
	"hash"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/copperexchange/krypton/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton/pkg/base/curves/k256"

	"github.com/copperexchange/krypton/pkg/base/curves"
	"github.com/copperexchange/krypton/pkg/base/protocols"
	agreeonrandom_testutils "github.com/copperexchange/krypton/pkg/threshold/agreeonrandom/testutils"
	"github.com/copperexchange/krypton/pkg/threshold/tsignatures/tschnorr/lindell22/testutils"
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

	identities, err := testutils_integration.MakeIdentities(cipherSuite, n)
	require.NoError(t, err)
	cohortConfig, err := testutils_integration.MakeCohortProtocol(cipherSuite, protocols.FROST, identities, threshold, identities)
	require.NoError(t, err)

	uniqueSessionId, err := agreeonrandom_testutils.ProduceSharedRandomValue(curve, identities, crand.Reader)
	require.NoError(t, err)

	participants, err := testutils.MakeParticipants(uniqueSessionId, cohortConfig, identities, nil)
	require.NoError(t, err)

	r1OutsB, r1OutsU, err := testutils.DoDkgRound1(participants)
	require.NoError(t, err)
	for _, out := range r1OutsU {
		require.Len(t, out, cohortConfig.Protocol.TotalParties-1)
	}

	r2InsB, r2InsU := testutils.MapDkgRound1OutputsToRound2Inputs(participants, r1OutsB, r1OutsU)
	r2Outs, err := testutils.DoDkgRound2(participants, r2InsB, r2InsU)

	r3Ins := testutils.MapDkgRound2OutputsToRound3Inputs(participants, r2Outs)
	shards, err := testutils.DoDkgRound3(participants, r3Ins)
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
