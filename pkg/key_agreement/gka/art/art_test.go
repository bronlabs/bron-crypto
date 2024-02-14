package art_test

import (
	crand "crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/pallas"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/key_agreement/gka/art"
)

func Test_HappyPathArt(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		curve curves.Curve
		n     int
	}{
		{k256.NewCurve(), 6},
		{p256.NewCurve(), 11},
		{pallas.NewCurve(), 3},
		{edwards25519.NewCurve(), 5},
		{bls12381.NewG2(), 7},
		{bls12381.NewG2(), 10},
	}

	for _, testCase := range testCases {
		curve := testCase.curve
		n := testCase.n
		t.Run(fmt.Sprintf("ART %s %d", curve.Name(), n), func(t *testing.T) {
			t.Parallel()
			var err error

			secretIdentityKeys := make([]curves.Scalar, n)
			secretEphemeralKeys := make([]curves.Scalar, n)
			publicIdentityKeys := make([]curves.Point, n)
			publicEphemeralKeys := make([]curves.Point, n)

			for i := 0; i < n; i++ {
				secretIdentityKeys[i], err = curve.ScalarField().Random(crand.Reader)
				require.NoError(t, err)
				secretEphemeralKeys[i], err = curve.ScalarField().Random(crand.Reader)
				require.NoError(t, err)
				publicIdentityKeys[i] = curve.ScalarBaseMult(secretIdentityKeys[i])
				publicEphemeralKeys[i] = curve.ScalarBaseMult(secretEphemeralKeys[i])
			}

			members := make([]*art.AsynchronousRatchetTree, n)
			for i := 0; i < n; i++ {
				members[i], err = art.NewAsynchronousRatchetTree(secretIdentityKeys[i], secretEphemeralKeys[i], publicIdentityKeys, publicEphemeralKeys)
				require.NoError(t, err)
			}

			leader := -1
			for i, member := range members {
				if member.IsLeader() {
					leader = i
					break
				}
			}
			allPublicKeys := members[leader].SetupGroup()
			for _, member := range members {
				err := member.ProcessSetup(allPublicKeys)
				require.NoError(t, err)
			}

			for i := 1; i < len(members); i++ {
				secretA := members[i-1].DeriveStageKey()
				secretB := members[i].DeriveStageKey()
				require.NotNil(t, secretA)
				require.NotNil(t, secretB)
				require.Zero(t, secretA.Cmp(secretB))
			}
		})
	}
}

func Test_ArtFailOnInvalidSetupMessage(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	n := 3
	var err error

	secretIdentityKeys := make([]curves.Scalar, n)
	secretEphemeralKeys := make([]curves.Scalar, n)
	publicIdentityKeys := make([]curves.Point, n)
	publicEphemeralKeys := make([]curves.Point, n)

	for i := 0; i < n; i++ {
		secretIdentityKeys[i], err = curve.ScalarField().Random(crand.Reader)
		require.NoError(t, err)
		secretEphemeralKeys[i], err = curve.ScalarField().Random(crand.Reader)
		require.NoError(t, err)
		publicIdentityKeys[i] = curve.ScalarBaseMult(secretIdentityKeys[i])
		publicEphemeralKeys[i] = curve.ScalarBaseMult(secretEphemeralKeys[i])
	}

	members := make([]*art.AsynchronousRatchetTree, n)
	for i := 0; i < n; i++ {
		members[i], err = art.NewAsynchronousRatchetTree(secretIdentityKeys[i], secretEphemeralKeys[i], publicIdentityKeys, publicEphemeralKeys)
		require.NoError(t, err)
	}

	leader := -1
	for i, member := range members {
		if member.IsLeader() {
			leader = i
			break
		}
	}
	allPublicKeys := members[leader].SetupGroup()

	// let's do something sketchy here
	// change the public key to some random and expect errors from every node
	allPublicKeys[0], err = curve.Random(crand.Reader)
	require.NoError(t, err)

	for _, member := range members {
		err := member.ProcessSetup(allPublicKeys)
		require.Error(t, err)
		require.True(t, errs.IsArgument(err))
	}
}

func Test_HappyPathArtRatchet(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		curve curves.Curve
		n     int
	}{
		{k256.NewCurve(), 11},
		{p256.NewCurve(), 3},
		{pallas.NewCurve(), 41},
		{edwards25519.NewCurve(), 17},
		{bls12381.NewG2(), 3},
		{bls12381.NewG2(), 40},
	}

	for _, testCase := range testCases {
		curve := testCase.curve
		n := testCase.n
		t.Run(fmt.Sprintf("ART %s %d", curve.Name(), n), func(t *testing.T) {
			t.Parallel()
			var err error

			secretIdentityKeys := make([]curves.Scalar, n)
			secretEphemeralKeys := make([]curves.Scalar, n)
			publicIdentityKeys := make([]curves.Point, n)
			publicEphemeralKeys := make([]curves.Point, n)

			for i := 0; i < n; i++ {
				secretIdentityKeys[i], err = curve.ScalarField().Random(crand.Reader)
				require.NoError(t, err)
				secretEphemeralKeys[i], err = curve.ScalarField().Random(crand.Reader)
				require.NoError(t, err)
				publicIdentityKeys[i] = curve.ScalarBaseMult(secretIdentityKeys[i])
				publicEphemeralKeys[i] = curve.ScalarBaseMult(secretEphemeralKeys[i])
			}

			members := make([]*art.AsynchronousRatchetTree, n)
			for i := 0; i < n; i++ {
				members[i], err = art.NewAsynchronousRatchetTree(secretIdentityKeys[i], secretEphemeralKeys[i], publicIdentityKeys, publicEphemeralKeys)
				require.NoError(t, err)
			}

			leader := -1
			for i, member := range members {
				if member.IsLeader() {
					leader = i
					break
				}
			}
			allPublicKeys := members[leader].SetupGroup()
			for _, member := range members {
				err := member.ProcessSetup(allPublicKeys)
				require.NoError(t, err)
			}

			for i := 1; i < len(members); i++ {
				secretA := members[i-1].DeriveStageKey()
				secretB := members[i].DeriveStageKey()
				require.NotNil(t, secretA)
				require.NotNil(t, secretB)
				require.Zero(t, secretA.Cmp(secretB))
			}

			ratchetingMember := n / 2 // because why not
			newPrivateKey, err := curve.ScalarField().Random(crand.Reader)
			require.NoError(t, err)
			newPublicKeys, err := members[ratchetingMember].UpdateKey(newPrivateKey)
			require.NoError(t, err)

			for i := 0; i < n; i++ {
				if i != ratchetingMember {
					err = members[i].ProcessUpdate(newPublicKeys, members[ratchetingMember].GetMyPublicIdentityKey())
					require.NoError(t, err)
				}
			}

			for i := 1; i < len(members); i++ {
				secretA := members[i-1].DeriveStageKey()
				secretB := members[i].DeriveStageKey()
				require.NotNil(t, secretA)
				require.NotNil(t, secretB)
				require.Zero(t, secretA.Cmp(secretB))
			}
		})
	}
}
