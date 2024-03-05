package noninteractive_test

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

	"github.com/copperexchange/krypton-primitives/pkg/base/combinatorics"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	ttu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
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
	for _, curve := range testCurves {
		for _, h := range testHashFunctions {
			for _, thresholdConfig := range testThresholdConfigs {
				curve := curve
				h := h
				hashName := runtime.FuncForPC(reflect.ValueOf(h).Pointer()).Name()
				threshold := thresholdConfig.t
				n := thresholdConfig.n
				N := make([]int, n)
				for i := range n {
					N[i] = i
				}
				cipherSuite, err := ttu.MakeSignatureProtocol(curve, h)
				require.NoError(t, err)
				t.Run(fmt.Sprintf("NonInteractive sign happy path with curve=%s and hash=%s and t=%d and n=%d", curve.Name(), hashName[strings.LastIndex(hashName, "/")+1:], threshold, n), func(t *testing.T) {
					t.Parallel()

					allIdentities, err := ttu.MakeTestIdentities(cipherSuite, n)
					require.NoError(t, err)

					protocol, err := ttu.MakeThresholdSignatureProtocol(cipherSuite, allIdentities, threshold, allIdentities)
					require.NoError(t, err)

					_, shards, err := testutils.RunDKG(cipherSuite.Curve(), protocol, allIdentities)
					require.NoError(t, err)

					combinations, err := combinatorics.Combinations(N, uint(threshold))
					require.NoError(t, err)
					for _, combination := range combinations {
						selectedIdentities := make([]types.IdentityKey, threshold)
						selectedShards := make([]*dkls24.Shard, threshold)
						for i, idx := range combination {
							selectedIdentities[i] = allIdentities[idx]
							selectedShards[i] = shards[idx]
						}
						preGenParties := testutils.MakePreGenParticipants(t, sessionId, protocol, selectedIdentities, selectedShards, nil, nil)
						ppms := testutils.RunPreGen(t, preGenParties)
						require.NotNil(t, ppms)
						require.Len(t, ppms, threshold)

						selectedPpm := ppms[:threshold]

						cosigners := testutils.MakeNonInteractiveCosigners(t, protocol, selectedIdentities, selectedShards, selectedPpm)
						message := []byte("Hello World!")

						partialSignatures := types.NewRoundMessages[*dkls24.PartialSignature]()
						for _, cosigner := range cosigners {
							msg, err := cosigner.ProducePartialSignature(message)
							require.NoError(t, err)
							partialSignatures.Put(cosigner.IdentityKey(), msg)
						}

						signature, err := signing.Aggregate(protocol.CipherSuite(), selectedShards[0].SigningKeyShare.PublicKey, partialSignatures, message)
						require.NoError(t, err)
						require.NotNil(t, signature)
					}
				})
			}
		}
	}
}
