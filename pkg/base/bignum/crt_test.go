package bignum_test

import (
	crand "crypto/rand"
	"github.com/copperexchange/krypton-primitives/pkg/base/bignum"
	"github.com/copperexchange/krypton-primitives/pkg/encryptions/paillier"
	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestExp(t *testing.T) {
	n := 1
	prng := crand.Reader
	pBig, err := crand.Prime(prng, 512)
	require.NoError(t, err)
	p := new(saferith.Nat).SetBig(pBig, 512)

	qBig, err := crand.Prime(prng, 512)
	require.NoError(t, err)
	q := new(saferith.Nat).SetBig(qBig, 512)
	if b, _, _ := p.Cmp(q); b == 1 {
		p, q = q, p
	}

	secretKey, err := paillier.NewSecretKey(p, q)
	require.NoError(t, err)

	eBig, err := crand.Int(prng, secretKey.N.Big())
	require.NoError(t, err)
	e := new(saferith.Nat).SetBig(eBig, 1024)

	bases := make([]*saferith.Nat, n)
	for i := range bases {
		baseBig, err := crand.Int(prng, secretKey.N.Big())
		require.NoError(t, err)
		bases[i] = new(saferith.Nat).SetBig(baseBig, 1024)
	}

	expectedResults := make([]*saferith.Nat, len(bases))
	for i := range bases {
		expectedResults[i] = new(saferith.Nat).Exp(bases[i], e, secretKey.GetNModulus())
	}

	multiCrtResults := bignum.FastFixedExponentMultiExpCrt(secretKey.GetCrtNParams(), bases, e, secretKey.N)
	for i, result := range expectedResults {
		require.True(t, result.Eq(multiCrtResults[i]) == 1)
	}
}
