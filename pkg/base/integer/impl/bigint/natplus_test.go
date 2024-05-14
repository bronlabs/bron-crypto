package bigint_test

import (
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/integer/impl/bigint"
	"github.com/stretchr/testify/require"
)

func TestBigInt(t *testing.T) {
	t.Parallel()

	two := bigint.New(2)
	twoTimesTo := two.Mul(two)
	four := bigint.New(4)
	require.True(t, four.Equal(twoTimesTo))
}
