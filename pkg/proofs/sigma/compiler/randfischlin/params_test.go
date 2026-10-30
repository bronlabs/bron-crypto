//nolint:testpackage // Parameters are derived internally; the table below pins them.
package randfischlin

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/proofs"
	"github.com/bronlabs/bron-crypto/pkg/proofs/dlog/schnorr"
)

// TestParams pins the parameter rule r * (l - log2(n - 1)) >= Lambda with r = 16 and
// t = ceil(log2 Lambda) * l rounded up to bytes ([KS22] Figure 9, [CL24] Section 5.1).
func TestParams(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		n      uint
		l      uint
		lBytes int
		tBytes int
	}{
		{n: 2, l: 8, lBytes: 1, tBytes: 7},
		{n: 3, l: 9, lBytes: 2, tBytes: 8},
		{n: 4, l: 10, lBytes: 2, tBytes: 9},
		{n: 5, l: 10, lBytes: 2, tBytes: 9},
		{n: 6, l: 11, lBytes: 2, tBytes: 10},
		{n: 17, l: 12, lBytes: 2, tBytes: 11},
		{n: 257, l: 16, lBytes: 2, tBytes: 14},
		{n: 1025, l: 18, lBytes: 3, tBytes: 16},
	} {
		p, err := newParams(tc.n, 16)
		require.NoError(t, err, "n = %d", tc.n)
		require.Equal(t, R, p.r, "n = %d", tc.n)
		require.Equal(t, tc.l, p.l, "n = %d", tc.n)
		require.Equal(t, tc.lBytes, p.lBytes, "n = %d", tc.n)
		require.Equal(t, tc.tBytes, p.tBytes, "n = %d", tc.n)
		// Knowledge error 2^-(r * (l - ceil(log2(n - 1)))) <= 2^-Lambda.
		var log2 uint
		for (uint(1) << log2) < tc.n-1 {
			log2++
		}
		require.GreaterOrEqual(t, uint(p.r)*(p.l-log2), uint(Lambda), "n = %d", tc.n)
		// Completeness: 2^t >= Lambda * 2^l ([KS22], proof of Theorem 6.4).
		require.GreaterOrEqual(t, 8*p.tBytes, int(p.l)+LambdaLog2, "n = %d", tc.n)
	}
}

func TestParams_Rejections(t *testing.T) {
	t.Parallel()

	// Nothing can be extracted from fewer than two transcripts.
	_, err := newParams(1, 16)
	require.ErrorIs(t, err, proofs.ErrInvalidArgument)
	_, err = newParams(0, 16)
	require.ErrorIs(t, err, proofs.ErrInvalidArgument)

	// The t-bit challenge must fit the sigma protocol's challenge.
	_, err = newParams(2, 6)
	require.ErrorIs(t, err, proofs.ErrInvalidArgument)
	_, err = newParams(1026, 16)
	require.ErrorIs(t, err, proofs.ErrInvalidArgument)
	_, err = newParams(1026, 17)
	require.NoError(t, err)
}

// TestHash_TruncatesToLBits checks that the row hash keeps exactly l bits.
func TestHash_TruncatesToLBits(t *testing.T) {
	t.Parallel()

	p, err := newParams(3, 16) // l = 9
	require.NoError(t, err)
	seenHighBit := false
	for i := range 512 {
		digest, err := p.hash([]byte{byte(i), byte(i >> 8)})
		require.NoError(t, err)
		require.Len(t, digest, 2)
		require.LessOrEqual(t, digest[1], byte(1))
		seenHighBit = seenHighBit || digest[1] == 1
	}
	require.True(t, seenHighBit)

	p, err = newParams(2, 16) // l = 8
	require.NoError(t, err)
	digest, err := p.hash([]byte{1})
	require.NoError(t, err)
	require.Len(t, digest, 1)
}

type oneSpecialSound struct {
	*schnorr.Protocol[*k256.Point, *k256.Scalar]
}

func (*oneSpecialSound) SpecialSoundness() uint { return 1 }

type shortChallenge struct {
	*schnorr.Protocol[*k256.Point, *k256.Scalar]
}

func (*shortChallenge) GetChallengeBytesLength() int { return 4 }

func TestNewCompiler_RejectsUnsupportedProtocols(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	schnorrProtocol, err := schnorr.NewProtocol(k256.NewCurve().Generator(), prng)
	require.NoError(t, err)

	_, err = NewCompiler(&oneSpecialSound{schnorrProtocol}, prng)
	require.ErrorIs(t, err, proofs.ErrInvalidArgument)

	_, err = NewCompiler(&shortChallenge{schnorrProtocol}, prng)
	require.ErrorIs(t, err, proofs.ErrInvalidArgument)
}
