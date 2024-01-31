package noninteractiveSigning_test

import (
	crand "crypto/rand"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
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
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	integration_testutils "github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24/signing"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24/testutils"
)

var testCurves = []curves.Curve{k256.NewCurve(), p256.NewCurve()}
var testHashFunctions = []func() hash.Hash{sha256.New, sha3.New256}
var testThresholdConfigs = []struct{ t, n int }{
	{t: 2, n: 3},
	{t: 2, n: 2},
	{t: 3, n: 3},
	{t: 3, n: 5},
}

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	sessionId := []byte("testSessionId")
	nTau := 4

	for _, curve := range testCurves {
		for _, h := range testHashFunctions {
			for _, thresholdConfig := range testThresholdConfigs {
				curve := curve
				h := h
				hashName := runtime.FuncForPC(reflect.ValueOf(h).Pointer()).Name()
				threshold := thresholdConfig.t
				n := thresholdConfig.n
				cipherSuite := &integration.CipherSuite{
					Curve: k256.NewCurve(),
					Hash:  sha256.New,
				}
				t.Run(fmt.Sprintf("NonInteractive sign happy path with curve=%s and hash=%s and t=%d and n=%d", curve.Name(), hashName[strings.LastIndex(hashName, "/")+1:], threshold, n), func(t *testing.T) {
					t.Parallel()

					allIdentities, err := integration_testutils.MakeTestIdentities(cipherSuite, n)
					require.NoError(t, err)

					cohortConfig, err := integration_testutils.MakeCohortProtocol(cipherSuite, protocols.DKLS24, allIdentities, threshold, allIdentities)
					require.NoError(t, err)

					shards, err := testutils.RunDKG(cipherSuite.Curve, cohortConfig, allIdentities)
					require.NoError(t, err)

					preGenParties := testutils.MakePreGenParticipants(t, nTau, sessionId, cohortConfig, allIdentities, shards, nil, nil)
					batches := testutils.RunPreGen(t, preGenParties)
					require.NotNil(t, batches)
					require.Len(t, batches, n)

					for tau := 0; tau < nTau; tau++ {
						combinations := combin.Combinations(n, threshold)
						for _, combination := range combinations {
							cosignerIdentities := make([]integration.IdentityKey, len(combination))
							cosignerShards := make([]*dkls24.Shard, len(combination))
							preSignatures := make([]*dkls24.PreSignature, len(combination))
							for idx, c := range combination {
								preSignatures[idx] = batches[c].PreSignatures[tau]
								cosignerIdentities[idx] = allIdentities[c]
								cosignerShards[idx] = shards[c]
							}

							cosigners := testutils.MakeNonInteractiveCosigners(t, cohortConfig, cosignerIdentities, cosignerShards, preSignatures)
							var message [32]byte
							_, err = io.ReadFull(crand.Reader, message[:])
							require.NoError(t, err)

							partialSignatures := make(map[types.IdentityHash]*dkls24.PartialSignature)
							for _, cosigner := range cosigners {
								partialSignatures[cosigner.GetAuthKey().Hash()], err = cosigner.ProducePartialSignature(message[:])
								require.NoError(t, err)
							}

							signature, err := signing.Aggregate(cohortConfig.CipherSuite, shards[0].SigningKeyShare.PublicKey, partialSignatures, message[:])
							require.NoError(t, err)
							require.NotNil(t, signature)
						}
					}
				})
			}
		}
	}
}
