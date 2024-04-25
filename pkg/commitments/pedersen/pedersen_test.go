package pedersen_test

import (
	crand "crypto/rand"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/commitments/pedersen"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_BreakBinding(t *testing.T) {
	// create generators
	curve := k256.NewCurve()
	g, err := curve.Random(crand.Reader)
	require.NoError(t, err)
	h, err := curve.Random(crand.Reader)
	require.NoError(t, err)

	committer := pedersen.NewCommitter(g, h)
	verifier := pedersen.NewVerifier(g, h)

	m1, err := curve.ScalarField().Random(crand.Reader)
	require.NoError(t, err)
	m2, err := curve.ScalarField().Random(crand.Reader)
	require.NoError(t, err)

	// commit to (m1, m2)
	commitment, opening := committer.Commit([]curves.Scalar{m1, m2})

	// verify to (m1, m2)
	err = verifier.Verify(commitment, opening)
	require.NoError(t, err)

	// fake opening to different values vector (hence break binding property)
	m3, err := curve.ScalarField().Random(crand.Reader)
	require.NoError(t, err)
	m4 := m1.Add(m2).Sub(m3)

	fakeOpening := &pedersen.Opening{
		Messages: []curves.Scalar{m3, m4},
		Nonces:   opening.Nonces,
	}

	err = verifier.Verify(commitment, fakeOpening)
	require.NoError(t, err)
	require.False(t, m1.Equal(m3))
	require.False(t, m3.Equal(m4))

	// there you go, commitment not bound to (m1, m2) vector
}
