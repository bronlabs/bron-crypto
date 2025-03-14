package feldman_test

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pallas"
	"github.com/bronlabs/bron-crypto/pkg/proofs/dlog/batch_schnorr"
	randomisedFischlin "github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/randfischlin"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
)

var allCurves = []curves.Curve{k256.NewCurve(), p256.NewCurve(), edwards25519.NewCurve(), pallas.NewCurve()}

func Fuzz_Test(f *testing.F) {
	f.Add(uint(0), []byte("secret"), int64(0))
	f.Fuzz(func(t *testing.T, curveIndex uint, secretBytes []byte, randomSeed int64) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		prng := rand.New(rand.NewSource(randomSeed))

		scheme, err := feldman.NewDealer(3, 5, curve)
		require.NoError(t, err)
		secret, err := curve.ScalarField().Hash(secretBytes)
		require.NoError(t, err)
		protocol, err := batch_schnorr.NewSigmaProtocol(curve.Generator(), prng)
		require.NoError(t, err)
		comp, err := randomisedFischlin.NewCompiler(protocol, prng)
		require.NoError(t, err)
		prover, err := comp.NewProver([]byte("test"), nil)
		require.NoError(t, err)

		commitments, shares, proof, err := scheme.Split(secret, prover, prng)
		require.NoError(t, err)
		require.NotNil(t, shares)
		for _, s := range shares {
			verifier, err := comp.NewVerifier([]byte("test"), nil) // Fresh verifier for each share, to avoid transcript mixing.
			require.NoError(t, err)
			err = feldman.Verify(s, commitments, verifier, proof)
			require.NoError(t, err)
		}
		secret2, err := scheme.Combine(shares...)
		require.NoError(t, err)
		require.Equal(t, secret2, secret)
	})
}
