package trusted_dealer_test

import (
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"maps"
	"slices"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/binrep3"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/teddsa/keygen/trusted_dealer"
	"github.com/stretchr/testify/require"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	const TOTAL = 3
	const THRESHOLD = 2
	prng := crand.Reader
	shareholders := sharing.NewOrdinalShareholderSet(TOTAL)
	shards, err := trusted_dealer.DealRandom(shareholders, prng)
	require.NotNil(t, shards)
	require.NoError(t, err)

	t.Run("should shards be consistent", func(t *testing.T) {
		t.Parallel()

		var pkBytes []byte
		shareholdersList := shareholders.List()
		slices.Sort(shareholdersList)
		for subShareholders := range sliceutils.KCoveringCombinations(shareholders.List(), THRESHOLD) {
			var seedShares [][4]*binrep3.Share
			var skValueShares []*feldman.Share[*edwards25519.Scalar]
			for _, id := range subShareholders {
				shard, ok := shards.Get(id)
				require.True(t, ok)
				seedShares = append(seedShares, shard.SeedShare())
				skValueShares = append(skValueShares, shard.Share())
			}

			seed := recoverSeed(t, shareholdersList, seedShares...)
			scheme, err := feldman.NewScheme(edwards25519.NewPrimeSubGroup().Generator(), THRESHOLD, shareholders)
			require.NoError(t, err)
			skSecret, err := scheme.Reconstruct(skValueShares...)
			require.NoError(t, err)
			pkValue := edwards25519.NewPrimeSubGroup().ScalarBaseOp(skSecret.Value())
			pkBytesActual := pkValue.ToCompressed()
			pkBytesExpected := ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
			require.Equal(t, []byte(pkBytesExpected), pkBytesActual)
			if len(pkBytes) == 0 {
				pkBytes = pkBytesActual
			} else {
				require.Equal(t, pkBytes, pkBytesActual)
			}
		}

		var verificationVector feldman.VerificationVector[*edwards25519.PrimeSubGroupPoint, *edwards25519.Scalar]
		for _, shard := range shards.Iter() {
			if verificationVector == nil {
				verificationVector = shard.VerificationVector()
			} else {
				v := shard.VerificationVector()
				require.True(t, verificationVector.Equal(v))
				verificationVector = v
			}
			require.Equal(t, pkBytes, shard.PublicKey().Value().ToCompressed())
			require.Equal(t, verificationVector.Coefficients()[0].ToCompressed(), pkBytes)

			for _, id := range shareholders.List() {
				partialPk, ok := shard.PartialPublicKeys().Get(id)
				require.True(t, ok)
				ppk := verificationVector.Eval(edwards25519.NewScalarField().FromUint64(uint64(id)))
				require.True(t, partialPk.Value().Equal(ppk))
			}
		}
	})
}

func recoverSeed(t testing.TB, shareholders []sharing.ID, shares ...[4]*binrep3.Share) [32]byte {
	t.Helper()

	subShares := make(map[sharing.ID][32]byte)
	for _, share := range shares {
		idx := slices.Index(shareholders, share[0].ID())
		prevIdx := (idx + 2) % 3
		nextIdx := (idx + 1) % 3
		prevId := shareholders[prevIdx]
		nextId := shareholders[nextIdx]

		var prevBytes [32]byte
		for k := range 4 {
			copy(prevBytes[k*8:(k+1)*8], binary.BigEndian.AppendUint64(nil, share[k].Prev()))
		}
		if _, ok := subShares[prevId]; !ok {
			subShares[prevId] = prevBytes
		} else {
			require.Equal(t, subShares[prevId], prevBytes)
		}

		var nextBytes [32]byte
		for k := range 4 {
			copy(nextBytes[k*8:(k+1)*8], binary.BigEndian.AppendUint64(nil, share[k].Next()))
		}
		if _, ok := subShares[nextId]; !ok {
			subShares[nextId] = nextBytes
		} else {
			require.Equal(t, subShares[nextId], nextBytes)
		}
	}

	var seed [32]byte
	for subSeed := range maps.Values(subShares) {
		subtle.XORBytes(seed[:], seed[:], subSeed[:])
	}

	return seed
}
