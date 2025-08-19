package k256_test

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/stretchr/testify/require"
)

func TestGobInvalid(t *testing.T) {
	k256.RegisterForGob()

	t.Parallel()
	curve := k256.NewCurve()
	gen := curve.Generator()
	zeroBaseField := curve.BaseField().Zero()
	zero := curve.ScalarField().Zero()

	invalid_point, _, _ := curve.DeriveFromAffineX(zeroBaseField)

	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(invalid_point)
	require.NoError(t, err)
	dec := gob.NewDecoder(&buf)
	var out *k256.Point
	err = dec.Decode(&out)
	require.NoError(t, err)
	out_mul_2 := out.Add(out)
	fmt.Printf("out_mul_2.x: %v\n", out_mul_2.AffineX().Nat().Big())
	fmt.Printf("out_mul_2.y: %v\n", out_mul_2.AffineY().Nat().Big())
	gen_mul_0 := gen.ScalarMul(zero)
	fmt.Printf("gen_mul_0.x: %v\n", gen_mul_0.AffineX().Nat().Big())
	fmt.Printf("gen_mul_0.y: %v\n", gen_mul_0.AffineY().Nat().Big())
	require.True(t, out_mul_2.Equal(gen_mul_0))
}
