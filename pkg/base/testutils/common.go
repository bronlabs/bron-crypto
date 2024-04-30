package testutils

import (
	crand "crypto/rand"
	"io"
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/pallas"
	"github.com/copperexchange/krypton-primitives/pkg/csprng/fkechacha20"
	"github.com/stretchr/testify/require"
)

// PickReader returns a random reader for testing purposes. If the test is short,
// it returns a deterministic reader seeded with the provided seed.
// Otherwise it returns a random reader.
func PickReader(t *testing.T, seed []byte) io.Reader {
	if testing.Short() {
		rng, err := fkechacha20.NewPrng(seed, nil)
		require.NoError(t, err)
		return rng
	} else {
		return crand.Reader
	}
}

func SkipIfShort(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test in short mode.")
	}
}

func PickCurve(curveIndex int) curves.Curve {
	switch curveIndex {
	case 0:
		return bls12381.NewG1()
	case 1:
		return bls12381.NewG2()
	case 2:
		return edwards25519.NewCurve()
	case 3:
		return k256.NewCurve()
	case 4:
		return p256.NewCurve()
	case 5:
		return pallas.NewCurve()
	}
	return nil
}

func PickNonPairingCurve(curveIndex int) curves.Curve {
	return PickCurve(curveIndex%4 + 2)
}

func GetCurveIndex(curve curves.Curve) int {
	switch curve.Name() {
	case bls12381.NameG1:
		return 0
	case bls12381.NameG2:
		return 1
	case edwards25519.Name:
		return 2
	case k256.Name:
		return 3
	case p256.Name:
		return 4
	case pallas.Name:
		return 5
	}
	return -1
}

func SampleSessionId(rng io.Reader) []byte {
	sessionId := make([]byte, 32)
	_, err := io.ReadFull(rng, sessionId)
	if err != nil {
		panic(err)
	}
	return sessionId
}
