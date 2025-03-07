package hss_test

import (
	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/k256"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/sharing/hss"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_Determinant(t *testing.T) {
	field := k256.NewScalarField()

	m := hss.NewMatrix([][]curves.Scalar{
		{field.New(9), field.New(2), field.New(3), field.New(4), field.New(6)},
		{field.New(2), field.New(3), field.New(2), field.New(5), field.New(6)},
		{field.New(1), field.New(4), field.New(5), field.New(6), field.New(7)},
		{field.New(4), field.New(0), field.New(6), field.New(7), field.New(8)},
		{field.New(5), field.New(6), field.New(7), field.New(8), field.New(11)},
	})

	actual := m.Determinant()
	expected := field.New(450)
	require.True(t, actual.Equal(expected))
}
