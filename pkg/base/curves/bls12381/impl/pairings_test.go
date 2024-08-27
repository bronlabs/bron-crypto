package bls12381impl_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	bls12381impl "github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl/arithmetic/limb4"
)

func TestSinglePairing(t *testing.T) {
	t.Parallel()
	g := new(bls12381impl.G1).Generator()
	h := new(bls12381impl.G2).Generator()

	e := new(bls12381impl.Engine)
	e.AddPair(g, h)
	p := e.Result()
	p.Neg(p)

	e.Reset()
	e.AddPairInvG2(g, h)
	q := e.Result()
	e.Reset()
	e.AddPairInvG1(g, h)
	r := e.Result()

	require.Equal(t, ctTrue, p.Equal(q))
	require.Equal(t, ctTrue, q.Equal(r))
}

func TestMultiPairing(t *testing.T) {
	t.Parallel()
	const Tests = 10
	e1 := new(bls12381impl.Engine)
	e2 := new(bls12381impl.Engine)

	g1s := make([]*bls12381impl.G1, Tests)
	g2s := make([]*bls12381impl.G2, Tests)
	sc := make([]*limb4.FieldValue, Tests)
	res := make([]*bls12381impl.Gt, Tests)
	expected := new(bls12381impl.Gt).SetOne()

	for i := 0; i < Tests; i++ {
		var bytes [64]byte
		g1s[i] = new(bls12381impl.G1).Generator()
		g2s[i] = new(bls12381impl.G2).Generator()
		sc[i] = bls12381impl.FqNew()
		_, _ = crand.Read(bytes[:])
		sc[i].SetBytesWide(&bytes)
		if i&1 == 0 {
			g1s[i].Mul(g1s[i], sc[i])
		} else {
			g2s[i].Mul(g2s[i], sc[i])
		}
		e1.AddPair(g1s[i], g2s[i])
		e2.AddPair(g1s[i], g2s[i])
		res[i] = e1.Result()
		e1.Reset()
		expected.Add(expected, res[i])
	}

	actual := e2.Result()
	require.Equal(t, ctTrue, expected.Equal(actual))
}
