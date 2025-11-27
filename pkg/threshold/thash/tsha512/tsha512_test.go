package tsha512_test

import (
	crand "crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"maps"
	"slices"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/network"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/binrep3"
	"github.com/bronlabs/bron-crypto/pkg/threshold/thash/tsha512"
	"github.com/stretchr/testify/require"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	shareholders := sharing.NewOrdinalShareholderSet(3)
	runners := make(map[sharing.ID]network.Runner[*tsha512.Output])
	for id := range shareholders.Iter() {
		participant, err := tsha512.NewParticipant(id, shareholders, prng)
		require.NoError(t, err)
		runners[id] = participant.NewRunner()
	}
	results := ntu.TestExecuteRunners(t, runners)

	dealer, err := binrep3.NewScheme(shareholders)
	require.NoError(t, err)
	preImageBytes := reconstructPreImage(t, dealer, results)
	imageBytes := reconstructImage(t, dealer, results)
	expected := sha512.Sum512(preImageBytes)
	require.Equal(t, imageBytes, expected[:])
}

func reconstructPreImage(tb testing.TB, scheme *binrep3.Scheme, results map[sharing.ID]*tsha512.Output) []byte {
	tb.Helper()

	resultValues := slices.Collect(maps.Values(results))
	preimageShares := sliceutils.Map(resultValues, func(in *tsha512.Output) [4]*binrep3.Share { return in.PreImageShares })
	var preimage [4]uint64
	for i := range 4 {
		var err error
		preimage[i], err = scheme.Reconstruct(preimageShares[0][i], preimageShares[1][i], preimageShares[2][i])
		require.NoError(tb, err)
	}
	preImageBytes := slices.Concat(
		binary.BigEndian.AppendUint64(nil, preimage[0]),
		binary.BigEndian.AppendUint64(nil, preimage[1]),
		binary.BigEndian.AppendUint64(nil, preimage[2]),
		binary.BigEndian.AppendUint64(nil, preimage[3]),
	)

	return preImageBytes
}

func reconstructImage(tb testing.TB, scheme *binrep3.Scheme, results map[sharing.ID]*tsha512.Output) []byte {
	tb.Helper()

	resultValues := slices.Collect(maps.Values(results))
	imageShares := sliceutils.Map(resultValues, func(in *tsha512.Output) [8]*binrep3.Share { return in.ImageShare })
	var image [8]uint64
	for i := range 8 {
		var err error
		image[i], err = scheme.Reconstruct(imageShares[0][i], imageShares[1][i], imageShares[2][i])
		require.NoError(tb, err)
	}

	imageBytes := slices.Concat(
		binary.BigEndian.AppendUint64(nil, image[0]),
		binary.BigEndian.AppendUint64(nil, image[1]),
		binary.BigEndian.AppendUint64(nil, image[2]),
		binary.BigEndian.AppendUint64(nil, image[3]),
		binary.BigEndian.AppendUint64(nil, image[4]),
		binary.BigEndian.AppendUint64(nil, image[5]),
		binary.BigEndian.AppendUint64(nil, image[6]),
		binary.BigEndian.AppendUint64(nil, image[7]),
	)
	return imageBytes
}
