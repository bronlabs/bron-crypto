package interactive_signing_test

import (
	crand "crypto/rand"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/k256"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/tsignatures/tecdsa/cggmp21/keygen/trusted_dealer"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	const threshold = 3
	const total = 5
	prng := crand.Reader

	curve := k256.NewCurve()
	shards, err := trusted_dealer.KeyGen(threshold, total, curve, prng)
	require.NoError(t, err)
	require.Len(t, shards, total)
}
