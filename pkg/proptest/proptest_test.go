package proptest_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/proptest"
	"github.com/stretchr/testify/require"
)

func Test_Test(t *testing.T) {
	prng := crand.Reader

	field := k256.NewScalarField()
	fieldProp := proptest.NewFieldProperty[*k256.Scalar]()
	fieldGen := proptest.NewDomainGenerator(field)
	ok := fieldProp.Check(t, fieldGen, prng)
	require.True(t, ok)
}
