package sign_test

import (
	nativeEcdsa "crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"fmt"
	"hash"
	"maps"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	dkgTestutils "github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa/dkls23/keygen/dkg/testutils"
	signTestutils "github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa/dkls23/signing/interactive/sign/testutils"
)

func Test_HappyPathWithDKG(t *testing.T) {
	t.Parallel()

	for _, testHashFunc := range testHashFuncs {
		testHashFuncName := runtime.FuncForPC(reflect.ValueOf(testHashFunc).Pointer()).Name()
		t.Run(testHashFuncName, func(t *testing.T) {
			t.Parallel()
			for _, testAccessStructure := range testAccessStructures {
				t.Run(fmt.Sprintf("(%d/%d)", testAccessStructure.Threshold(), testAccessStructure.Shareholders().Size()), func(t *testing.T) {
					t.Parallel()
					t.Run("P256", func(t *testing.T) {
						t.Parallel()
						testHappyPath(t, p256.NewCurve(), testHashFunc, testAccessStructure)
					})
					t.Run("secp256k1", func(t *testing.T) {
						t.Parallel()
						testHappyPath(t, k256.NewCurve(), testHashFunc, testAccessStructure)
					})
					t.Run("pallas", func(t *testing.T) {
						t.Parallel()
						testHappyPath(t, pasta.NewPallasCurve(), testHashFunc, testAccessStructure)
					})
					t.Run("vesta", func(t *testing.T) {
						t.Parallel()
						testHappyPath(t, pasta.NewVestaCurve(), testHashFunc, testAccessStructure)
					})
				})
			}
		})
	}
}

var testHashFuncs = []func() hash.Hash{
	sha256.New,
	hashing.HashFuncTypeErase(sha3.New256),
	sha512.New,
}

var testAccessStructures = []*sharing.ThresholdAccessStructure{
	makeAccessStructure(2, 2),
	makeAccessStructure(2, 3),
	makeAccessStructure(3, 5),
}

func testHappyPath[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](t *testing.T, curve ecdsa.Curve[P, B, S], hashFunc func() hash.Hash, accessStructure *sharing.ThresholdAccessStructure) {
	t.Helper()

	shards := dkgTestutils.RunDKLs23DKG(t, curve, accessStructure)
	message := []byte("Hello World")
	for th := accessStructure.Threshold(); th <= uint(accessStructure.Shareholders().Size()); th++ {
		for shareholdersSubset := range sliceutils.Combinations(slices.Collect(accessStructure.Shareholders().Iter()), th) {
			signature := signTestutils.RunDKLs23SignSoftspokenOT(t, shards, hashset.NewComparable(shareholdersSubset...).Freeze(), message, hashFunc)
			pk := slices.Collect(maps.Values(shards))[0].PublicKey()

			t.Run(fmt.Sprintf("signature is valid %s", stringifyShareholders(shareholdersSubset)), func(t *testing.T) {
				t.Parallel()

				nativePk := pk.ToElliptic()
				nativeR, nativeS := signature.ToElliptic()
				digest, err := hashing.Hash(hashFunc, message)
				require.NoError(t, err)
				ok := nativeEcdsa.Verify(nativePk, digest, nativeR, nativeS)
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
			s += ","
		}
	}
	s += ")"
	return s
}

func makeAccessStructure(threshold, total uint) *sharing.ThresholdAccessStructure {
	shareholders := hashset.NewComparable[sharing.ID]()
	for i := uint(1); i <= total; i++ {
		shareholders.Add(sharing.ID(i))
	}
	accessStructure, err := sharing.NewThresholdAccessStructure(threshold, shareholders.Freeze())
	if err != nil {
		panic(err)
	}
	return accessStructure
}
