package crt_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/crt"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
)

func TestRecombine(t *testing.T) {
	t.Parallel()
	// p=5, q=7, N=35
	// m=23 => mp = 23 mod 5 = 3, mq = 23 mod 7 = 2
	p := numct.NewNat(5)
	q := numct.NewNat(7)
	mp := numct.NewNat(3)
	mq := numct.NewNat(2)

	m, ok := crt.Recombine(mp, mq, p, q)
	require.Equal(t, ct.True, ok)
	require.Equal(t, int64(23), m.Big().Int64())
}

func TestPrecompute(t *testing.T) {
	t.Parallel()
	p := numct.NewNat(5)
	q := numct.NewNat(7)

	params, ok := crt.Precompute(p, q)
	require.Equal(t, ct.True, ok)
	require.NotNil(t, params)
	require.NotNil(t, params.P)
	require.NotNil(t, params.QNat)
	require.NotNil(t, params.QInv)
}

func TestPrecompute_NotCoprime(t *testing.T) {
	t.Parallel()
	p := numct.NewNat(6)
	q := numct.NewNat(9) // gcd(6,9)=3

	_, ok := crt.Precompute(p, q)
	require.Equal(t, ct.False, ok)
}

func TestParams_Recombine(t *testing.T) {
	t.Parallel()
	p := numct.NewNat(5)
	q := numct.NewNat(7)

	params, ok := crt.Precompute(p, q)
	require.Equal(t, ct.True, ok)

	// Test multiple values
	tests := []struct {
		m  int64
		mp int64
		mq int64
	}{
		{0, 0, 0},
		{1, 1, 1},
		{12, 2, 5},
		{23, 3, 2},
		{34, 4, 6},
	}

	for _, tc := range tests {
		mp := numct.NewNat(uint64(tc.mp))
		mq := numct.NewNat(uint64(tc.mq))
		m := params.Recombine(mp, mq)
		require.Equal(t, tc.m, m.Big().Int64(), "m=%d", tc.m)
	}
}

func TestParamsExtended(t *testing.T) {
	t.Parallel()
	p := numct.NewNat(5)
	q := numct.NewNat(7)

	params, ok := crt.Precompute(p, q)
	require.Equal(t, ct.True, ok)

	prmx, ok := params.Extended()
	require.Equal(t, ct.True, ok)
	require.NotNil(t, prmx.Q)
	require.NotNil(t, prmx.PNat)
}

func TestPrecomputePairExtended(t *testing.T) {
	t.Parallel()
	p := numct.NewNat(5)
	q := numct.NewNat(7)

	prmx, ok := crt.PrecomputePairExtended(p, q)
	require.Equal(t, ct.True, ok)
	require.NotNil(t, prmx)
}

func TestNewParamsExtended(t *testing.T) {
	t.Parallel()
	p, okP := numct.NewModulus(numct.NewNat(5))
	q, okQ := numct.NewModulus(numct.NewNat(7))
	require.Equal(t, ct.True, okP)
	require.Equal(t, ct.True, okQ)

	prmx, ok := crt.NewParamsExtended(p, q)
	require.Equal(t, ct.True, ok)
	require.NotNil(t, prmx.M)
	require.Equal(t, int64(35), prmx.M.Big().Int64())
}

func TestParamsExtended_Decompose(t *testing.T) {
	t.Parallel()
	p, _ := numct.NewModulus(numct.NewNat(5))
	q, _ := numct.NewModulus(numct.NewNat(7))

	prmx, ok := crt.NewParamsExtended(p, q)
	require.Equal(t, ct.True, ok)

	// Decompose 23: 23 mod 5 = 3, 23 mod 7 = 2
	m, _ := numct.NewModulus(numct.NewNat(23))
	mp, mq := prmx.Decompose(m)
	require.Equal(t, int64(3), mp.Big().Int64())
	require.Equal(t, int64(2), mq.Big().Int64())
}

func TestParamsExtended_DecomposeSerial(t *testing.T) {
	t.Parallel()
	p, _ := numct.NewModulus(numct.NewNat(5))
	q, _ := numct.NewModulus(numct.NewNat(7))

	prmx, ok := crt.NewParamsExtended(p, q)
	require.Equal(t, ct.True, ok)

	m, _ := numct.NewModulus(numct.NewNat(23))
	mp, mq := prmx.DecomposeSerial(m)
	require.Equal(t, int64(3), mp.Big().Int64())
	require.Equal(t, int64(2), mq.Big().Int64())
}

func TestParamsExtended_DecomposeParallel(t *testing.T) {
	t.Parallel()
	p, _ := numct.NewModulus(numct.NewNat(5))
	q, _ := numct.NewModulus(numct.NewNat(7))

	prmx, ok := crt.NewParamsExtended(p, q)
	require.Equal(t, ct.True, ok)

	m, _ := numct.NewModulus(numct.NewNat(23))
	mp, mq := prmx.DecomposeParallel(m)
	require.Equal(t, int64(3), mp.Big().Int64())
	require.Equal(t, int64(2), mq.Big().Int64())
}

func TestParamsExtended_RoundTrip(t *testing.T) {
	t.Parallel()
	p, _ := numct.NewModulus(numct.NewNat(5))
	q, _ := numct.NewModulus(numct.NewNat(7))

	prmx, ok := crt.NewParamsExtended(p, q)
	require.Equal(t, ct.True, ok)

	// Decompose and recombine (starting at 1 since NewModulus rejects 0)
	for m := int64(1); m < 35; m++ {
		mMod, _ := numct.NewModulus(numct.NewNat(uint64(m)))
		mp, mq := prmx.Decompose(mMod)
		result := prmx.Recombine(mp, mq)
		require.Equal(t, m, result.Big().Int64(), "m=%d", m)
	}
}

// Multi-factor CRT tests

func TestPrecomputeMulti(t *testing.T) {
	t.Parallel()
	f1 := numct.NewNat(3)
	f2 := numct.NewNat(5)
	f3 := numct.NewNat(7)

	params, ok := crt.PrecomputeMulti(f1, f2, f3)
	require.Equal(t, ct.True, ok)
	require.Equal(t, 3, params.NumFactors)
	require.Equal(t, int64(105), params.Modulus.Big().Int64()) // 3*5*7=105
}

func TestPrecomputeMulti_NotCoprime(t *testing.T) {
	t.Parallel()
	f1 := numct.NewNat(6)
	f2 := numct.NewNat(9) // gcd(6,9)=3

	_, ok := crt.PrecomputeMulti(f1, f2)
	require.Equal(t, ct.False, ok)
}

func TestNewParamsMulti(t *testing.T) {
	t.Parallel()
	f1, _ := numct.NewModulus(numct.NewNat(3))
	f2, _ := numct.NewModulus(numct.NewNat(5))
	f3, _ := numct.NewModulus(numct.NewNat(7))

	params, ok := crt.NewParamsMulti(f1, f2, f3)
	require.Equal(t, ct.True, ok)
	require.Equal(t, 3, params.NumFactors)
}

func TestNewParamsMulti_TooFewFactors(t *testing.T) {
	t.Parallel()
	f1, _ := numct.NewModulus(numct.NewNat(3))

	_, ok := crt.NewParamsMulti(f1)
	require.Equal(t, ct.False, ok)
}

func TestParamsMulti_RecombineSerial(t *testing.T) {
	t.Parallel()
	f1, _ := numct.NewModulus(numct.NewNat(3))
	f2, _ := numct.NewModulus(numct.NewNat(5))
	f3, _ := numct.NewModulus(numct.NewNat(7))

	params, ok := crt.NewParamsMulti(f1, f2, f3)
	require.Equal(t, ct.True, ok)

	// x=23 => x mod 3 = 2, x mod 5 = 3, x mod 7 = 2
	r1 := numct.NewNat(2)
	r2 := numct.NewNat(3)
	r3 := numct.NewNat(2)

	result, ok := params.RecombineSerial(r1, r2, r3)
	require.Equal(t, ct.True, ok)
	require.Equal(t, int64(23), result.Big().Int64())
}

func TestParamsMulti_RecombineParallel(t *testing.T) {
	t.Parallel()
	f1, _ := numct.NewModulus(numct.NewNat(3))
	f2, _ := numct.NewModulus(numct.NewNat(5))
	f3, _ := numct.NewModulus(numct.NewNat(7))

	params, ok := crt.NewParamsMulti(f1, f2, f3)
	require.Equal(t, ct.True, ok)

	r1 := numct.NewNat(2)
	r2 := numct.NewNat(3)
	r3 := numct.NewNat(2)

	result, ok := params.RecombineParallel(r1, r2, r3)
	require.Equal(t, ct.True, ok)
	require.Equal(t, int64(23), result.Big().Int64())
}

func TestParamsMulti_Recombine_WrongCount(t *testing.T) {
	t.Parallel()
	f1, _ := numct.NewModulus(numct.NewNat(3))
	f2, _ := numct.NewModulus(numct.NewNat(5))

	params, ok := crt.NewParamsMulti(f1, f2)
	require.Equal(t, ct.True, ok)

	r1 := numct.NewNat(1)
	_, ok = params.Recombine(r1) // only 1 residue, need 2
	require.Equal(t, ct.False, ok)
}

func TestParamsMulti_DecomposeSerial(t *testing.T) {
	t.Parallel()
	f1, _ := numct.NewModulus(numct.NewNat(3))
	f2, _ := numct.NewModulus(numct.NewNat(5))
	f3, _ := numct.NewModulus(numct.NewNat(7))

	params, ok := crt.NewParamsMulti(f1, f2, f3)
	require.Equal(t, ct.True, ok)

	m, _ := numct.NewModulus(numct.NewNat(23))
	residues := params.DecomposeSerial(m)
	require.Len(t, residues, 3)
	require.Equal(t, int64(2), residues[0].Big().Int64()) // 23 mod 3 = 2
	require.Equal(t, int64(3), residues[1].Big().Int64()) // 23 mod 5 = 3
	require.Equal(t, int64(2), residues[2].Big().Int64()) // 23 mod 7 = 2
}

func TestParamsMulti_DecomposeParallel(t *testing.T) {
	t.Parallel()
	f1, _ := numct.NewModulus(numct.NewNat(3))
	f2, _ := numct.NewModulus(numct.NewNat(5))
	f3, _ := numct.NewModulus(numct.NewNat(7))

	params, ok := crt.NewParamsMulti(f1, f2, f3)
	require.Equal(t, ct.True, ok)

	m, _ := numct.NewModulus(numct.NewNat(23))
	residues := params.DecomposeParallel(m)
	require.Len(t, residues, 3)
	require.Equal(t, int64(2), residues[0].Big().Int64())
	require.Equal(t, int64(3), residues[1].Big().Int64())
	require.Equal(t, int64(2), residues[2].Big().Int64())
}

func TestParamsMulti_RoundTrip(t *testing.T) {
	t.Parallel()
	f1, _ := numct.NewModulus(numct.NewNat(3))
	f2, _ := numct.NewModulus(numct.NewNat(5))
	f3, _ := numct.NewModulus(numct.NewNat(7))

	params, ok := crt.NewParamsMulti(f1, f2, f3)
	require.Equal(t, ct.True, ok)

	// Test round-trip for all values in range [1, 105) (starting at 1 since NewModulus rejects 0)
	for m := int64(1); m < 105; m++ {
		mMod, _ := numct.NewModulus(numct.NewNat(uint64(m)))
		residues := params.Decompose(mMod)
		result, ok := params.Recombine(residues...)
		require.Equal(t, ct.True, ok)
		require.Equal(t, m, result.Big().Int64(), "m=%d", m)
	}
}
