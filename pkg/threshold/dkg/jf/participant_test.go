package jf_test

import (
	crand "crypto/rand"
	"crypto/sha512"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	"github.com/bronlabs/krypton-primitives/pkg/base/types/testutils"
	randomisedFischlin "github.com/bronlabs/krypton-primitives/pkg/proofs/sigma/compiler/randfischlin"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/dkg/jf"
)

func Test_CanInitialize(t *testing.T) {
	t.Parallel()
	curve := edwards25519.NewCurve()
	h := sha512.New512_256
	threshold := 2
	cipherSuite, err := testutils.MakeSigningSuite(curve, h)
	require.NoError(t, err)
	identities, err := testutils.MakeTestIdentities(cipherSuite, threshold)
	require.NoError(t, err)

	protocol, err := testutils.MakeThresholdProtocol(curve, identities, threshold)
	require.NoError(t, err)
	alice, err := jf.NewParticipant([]byte("sid"), identities[0].(types.AuthKey), protocol, randomisedFischlin.Name, crand.Reader, nil)
	require.NoError(t, err)
	bob, err := jf.NewParticipant([]byte("sid"), identities[1].(types.AuthKey), protocol, randomisedFischlin.Name, crand.Reader, nil)
	require.NoError(t, err)
	require.NotEqual(t, alice.SharingId(), bob.SharingId())
	require.True(t, alice.H.Equal(bob.H))
}
