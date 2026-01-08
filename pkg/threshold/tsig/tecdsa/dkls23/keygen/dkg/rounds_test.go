package dkg_test

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa/dkls23/keygen/dkg/testutils"
	"github.com/stretchr/testify/require"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	const THRESHOLD = 2
	const TOTAL = 3

	curve := k256.NewCurve()
	shareholders := hashset.NewComparable[sharing.ID]()
	for i := 1; i <= TOTAL; i++ {
		shareholders.Add(sharing.ID(i))
	}
	accessStructure, err := sharing.NewThresholdAccessStructure(THRESHOLD, shareholders.Freeze())
	require.NoError(t, err)

	// everything is checked inside testutils
	shards := testutils.RunDKLs23DKG(t, curve, accessStructure)
	require.Len(t, shards, TOTAL)
}
