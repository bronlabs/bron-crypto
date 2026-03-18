package constructions

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
)

func TestTryOpInvReturnsErrorOnFailure(t *testing.T) {
	t.Parallel()

	scalarField := k256.NewScalarField()

	// Bypass the constructor to create a zero element, which is
	// not invertible. This lets us test the error path of TryOpInv.
	zeroElem := FieldUnitSubGroupElement[*k256.Scalar]{
		fe: scalarField.Zero(),
	}

	// TryOpInv must return an error, not panic.
	// Before the fix, TryOpInv called Inv() which panics on failure.
	result, err := zeroElem.TryOpInv()
	require.Error(t, err)
	require.Nil(t, result)
}
