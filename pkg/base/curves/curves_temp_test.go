package curves_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/stretchr/testify/require"
	"hash"
	"slices"
	"testing"
)

func GetGenerator[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](curve C) P {
	return curve.Generator()
}

func MakeGenericSchnorrChallenge[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](curve C, hashFunc func() hash.Hash, xs ...[]byte) (S, error) {
	for _, x := range xs {
		if x == nil {
			return *new(S), errs.NewIsNil("an input is nil")
		}
	}

	// TODO: use hashing package
	h := hashFunc()
	digest := h.Sum(slices.Concat(xs...))

	// TODO(aalireza): add methods on curve to return scalar field
	var dummyScalar S
	scalarField, err := fields.GetPrimeField(dummyScalar)
	if err != nil {
		return *new(S), err
	}
	challenge, err := scalarField.FromWideBytes(digest)
	if err != nil {
		return *new(S), err
	}

	return challenge, nil
}

func Test_Dummy(t *testing.T) {
	curve := k256.NewCurve()
	gen := GetGenerator(curve)
	genX, err := gen.AffineX()
	require.NoError(t, err)
	println(genX.HashCode())
}
