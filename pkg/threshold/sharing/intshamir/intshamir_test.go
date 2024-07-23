package intshamir_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/intshamir"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	maxInt, err := crand.Prime(crand.Reader, 2048)
	require.NoError(t, err)
	maxNat := new(saferith.Nat).SetBig(maxInt, 2048)
	yInt, err := crand.Int(crand.Reader, maxInt)
	require.NoError(t, err)
	yNat := new(saferith.Nat).SetBig(yInt, 2048)

	dealer := intshamir.NewDealer(2, 3)
	shares, err := dealer.Deal(yNat, maxNat, crand.Reader)
	require.Len(t, shares, 3)
	require.NoError(t, err)

	y0Combined := dealer.Combine([]*intshamir.Share{shares[1], shares[2]})
	require.Equal(t, yNat.Eq(y0Combined), saferith.Choice(1))
}
