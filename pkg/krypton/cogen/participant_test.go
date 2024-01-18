package cogen_test

import (
	"crypto/rand"
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/krypton/cogen"
	"github.com/stretchr/testify/require"
)

func TestHashingGroupBySortingPubkeys(t *testing.T) {
	curve := p256.NewCurve()
	pk1, err := curve.Random(rand.Reader)
	require.NoError(t, err)
	pk2, err := curve.Random(rand.Reader)
	require.NoError(t, err)
	group1 := &cogen.CohortCertificateMessage{
		Groups: []curves.Point{pk1, pk2},
	}
	group2 := &cogen.CohortCertificateMessage{
		Groups: []curves.Point{pk2, pk1},
	}
	bytes1 := group1.Encode()
	bytes2 := group2.Encode()
	require.Equal(t, bytes1, bytes2)
}
