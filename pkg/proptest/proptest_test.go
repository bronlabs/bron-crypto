package proptest_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/proptest"
)

func Test_Test(t *testing.T) {
	k256ScalarField := k256.NewScalarField()
	k256ScalarFieldGen := proptest.NewUniformDomainGenerator(k256ScalarField)
	k256ScalarFieldProperty := proptest.NewFieldProperty(k256ScalarFieldGen, k256ScalarField)

	ctx := proptest.NewContext(65536, crand.Reader)
	proptest.RunPropertyCheck[*k256.Scalar](t, ctx, k256ScalarFieldProperty)
}
