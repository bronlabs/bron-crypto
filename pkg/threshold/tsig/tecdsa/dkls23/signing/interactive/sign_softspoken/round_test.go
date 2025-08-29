package sign_softspoken_test

import (
	nativeEcdsa "crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/shamir"
	dkgTestutils "github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa/dkls23/keygen/dkg/testutils"
	signTestutils "github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa/dkls23/signing/interactive/sign_softspoken/testutils"
	"github.com/stretchr/testify/require"
)

func Test_HappyPathWithDKG(t *testing.T) {
	t.Parallel()

	const THRESHOLD = 3
	const TOTAL = 5

	curve := p256.NewCurve()
	shareholders := hashset.NewComparable[sharing.ID]()
	for i := 1; i <= TOTAL; i++ {
		shareholders.Add(sharing.ID(i))
	}
	accessStructure, err := shamir.NewAccessStructure(THRESHOLD, shareholders.Freeze())
	require.NoError(t, err)

	// everything is checked inside testutils
	shards := dkgTestutils.RunDKLs23DKG(t, curve, accessStructure)

	message := []byte("Hello World")
	hashFunc := sha256.New
	for th := THRESHOLD; th <= accessStructure.Shareholders().Size(); th++ {
		for shareholdersSubset := range sliceutils.Combinations(slices.Collect(accessStructure.Shareholders().Iter()), uint(th)) {
			signature := signTestutils.RunDKLs23SignSoftspokenOT(t, shards, hashset.NewComparable(shareholdersSubset...).Freeze(), message, hashFunc)
			pk := slices.Collect(maps.Values(shards))[0].PublicKey()

			t.Run(fmt.Sprintf("signature is valid %s", stringifyShareholders(shareholdersSubset)), func(t *testing.T) {
				t.Parallel()

				nativePk := &nativeEcdsa.PublicKey{
					Curve: elliptic.P256(),
					// TODO: hope to return affine x and affine y
					X: pk.Coordinates().Value()[0].Cardinal().Big(),
					Y: pk.Coordinates().Value()[1].Cardinal().Big(),
				}

				digest, err := hashing.Hash(hashFunc, message)
				require.NoError(t, err)
				ok := nativeEcdsa.Verify(nativePk, digest, signature.R().Cardinal().Big(), signature.S().Cardinal().Big())
				require.True(t, ok)
			})
		}
	}
}

func stringifyShareholders(sharingIds []sharing.ID) string {
	s := "("
	for i, id := range sharingIds {
		s += strconv.Itoa(int(id))
		if i < len(sharingIds)-1 {
			s += ", "
		}
	}
	s += ")"
	return s
}
