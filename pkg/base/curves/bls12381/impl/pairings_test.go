package impl_test

import (
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	bls12381Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/bls12381/impl"
	fieldsTu "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/fields/testutils"
	pointsImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/points"
	pointsTu "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/points/testutils"

	_ "embed"
)

//go:embed testvectors/optimal_ate_pairing.json
var testVectorsJson string

type g1Json = pointsTu.PointJson[*bls12381Impl.Fp, *bls12381Impl.G1Point, bls12381Impl.Fp, bls12381Impl.G1Point]
type g2Json = pointsTu.PointJson[*bls12381Impl.Fp2, *bls12381Impl.G2Point, bls12381Impl.Fp2, bls12381Impl.G2Point]
type gtJson = fieldsTu.FiniteFieldElementJson[*bls12381Impl.Fp12, bls12381Impl.Fp12]

type testVectors struct {
	Vectors []testVector `json:"vectors"`
}

type testVector struct {
	G1 g1Json `json:"g1"`
	G2 g2Json `json:"g2"`
	Gt gtJson `json:"gt"`
}

func Test_TestVectors(t *testing.T) {
	t.Parallel()

	var vectors testVectors
	err := json.Unmarshal([]byte(testVectorsJson), &vectors)
	require.NoError(t, err)

	engine := new(bls12381Impl.Engine)
	for _, vector := range vectors.Vectors {
		gt := engine.
			Reset().
			AddPair(&vector.G1.V, &vector.G2.V).
			Result()

		//ok := gt.V.Equals(&vector.Gt.V)
		println(hex.EncodeToString(gt.U0.U0.U0.Bytes()))
		// b68917caaa0543a808c53908f694d1b6e7b38de90ce9d83d505ca1ef1b442d2727d7d06831d8b2a7920afc71d8eb5012
	}
}

func TestSinglePairing(t *testing.T) {
	t.Parallel()
	var g bls12381Impl.G1Point
	var h bls12381Impl.G2Point
	g.SetGenerator()
	h.SetGenerator()

	e := new(bls12381Impl.Engine)
	e.AddPair(&g, &h)
	p := e.Result()
	p.Inv(p)

	e.Reset()
	e.AddPairInvG2(&g, &h)
	q := e.Result()
	e.Reset()
	e.AddPairInvG1(&g, &h)
	r := e.Result()

	require.True(t, p.Equals(q) == 1)
	require.True(t, q.Equals(r) == 1)
}

func TestMultiPairing(t *testing.T) {
	t.Parallel()
	const tests = 10
	e1 := new(bls12381Impl.Engine)
	e2 := new(bls12381Impl.Engine)

	g1s := make([]*bls12381Impl.G1Point, tests)
	g2s := make([]*bls12381Impl.G2Point, tests)
	sc := make([][]byte, tests)
	res := make([]bls12381Impl.Gt, tests)
	expected := new(bls12381Impl.Gt)
	expected.SetOne()

	for i := 0; i < tests; i++ {
		g1s[i] = new(bls12381Impl.G1Point)
		g1s[i].SetGenerator()
		g2s[i] = new(bls12381Impl.G2Point)
		g2s[i].SetGenerator()
		sc[i] = make([]byte, 32)
		_, err := io.ReadFull(crand.Reader, sc[i])
		require.NoError(t, err)

		if i&1 == 0 {
			pointsImpl.ScalarMul[*bls12381Impl.Fp](g1s[i], g1s[i], sc[i])
		} else {
			pointsImpl.ScalarMul[*bls12381Impl.Fp2](g2s[i], g2s[i], sc[i])
		}
		e1.AddPair(g1s[i], g2s[i])
		e2.AddPair(g1s[i], g2s[i])
		res[i].Set(e1.Result())
		e1.Reset()
		expected.Mul(&expected.Fp12, &res[i].Fp12)
	}

	actual := e2.Result()
	require.True(t, expected.Equals(actual) == 1)
}
