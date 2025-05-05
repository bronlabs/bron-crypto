package testutils

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/stretchr/testify/require"
	"testing"
)

func MakeThresholdProtocol[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](tb testing.TB, curve C, threshold uint, participants ...types.IdentityKey) types.ThresholdProtocol[C, P, F, S] {
	tb.Helper()
	p, err := types.NewThresholdProtocol(curve, hashset.NewHashableHashSet[types.IdentityKey](participants...), threshold)
	require.NoError(tb, err)
	return p
}
