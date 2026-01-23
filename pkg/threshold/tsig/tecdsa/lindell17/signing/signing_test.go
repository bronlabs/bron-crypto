package signing_test

import (
	"bytes"
	"crypto"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa/lindell17/keygen/trusted_dealer"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa/lindell17/signing"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
)

var testAccessStructure = []int{2, 3}
var testHashFuncs = []crypto.Hash{crypto.SHA256, crypto.BLAKE2b_512}

func TestHappyPath(t *testing.T) {
	t.Parallel()

	for _, total := range testAccessStructure {
		t.Run(fmt.Sprintf("total=%d", total), func(t *testing.T) {
			t.Parallel()
			for _, ch := range testHashFuncs {
				t.Run(fmt.Sprintf("hash func=%s", ch.String()), func(t *testing.T) {
					t.Parallel()
					hashFunc := ch.New
					t.Run("secp256k1", func(t *testing.T) {
						t.Parallel()
						curve := k256.NewCurve()
						suite, err := ecdsa.NewSuite(curve, hashFunc)
						require.NoError(t, err)
						testHappyPath(t, total, suite)
					})
					t.Run("P256", func(t *testing.T) {
						t.Parallel()
						curve := p256.NewCurve()
						suite, err := ecdsa.NewSuite(curve, hashFunc)
						require.NoError(t, err)
						testHappyPath(t, total, suite)
					})
				})
			}
		})
	}
}

func testHappyPath[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](t *testing.T, total int, suite *ecdsa.Suite[P, B, S]) {
	t.Helper()

	prng := pcg.NewRandomised()
	shareholders := []sharing.ID{}
	for i := sharing.ID(1); i <= sharing.ID(total); i++ {
		shareholders = append(shareholders, i)
	}

	shards, publicKey, err := trusted_dealer.DealRandom(suite.Curve(), hashset.NewComparable(shareholders...).Freeze(), base.IFCKeyLength, prng)
	require.NoError(t, err)

	for subShareHolders := range sliceutils.KCoveringCombinations(shareholders, 2) {
		var sessionID network.SID
		_, err := io.ReadFull(prng, sessionID[:])
		require.NoError(t, err)

		primaryID := subShareHolders[0]
		secondaryID := subShareHolders[1]
		primaryShard, ok := shards.Get(primaryID)
		require.True(t, ok)
		secondaryShard, ok := shards.Get(secondaryID)
		require.True(t, ok)
		primaryTape := hagrid.NewTranscript("test")
		secondaryTape := primaryTape.Clone()

		primaryCosigner, err := signing.NewPrimaryCosigner(sessionID, suite, secondaryID, primaryShard, fiatshamir.Name, primaryTape, prng)
		require.NoError(t, err)
		secondaryCosigner, err := signing.NewSecondaryCosigner(sessionID, suite, primaryID, secondaryShard, fiatshamir.Name, secondaryTape, prng)
		require.NoError(t, err)

		message := []byte("hello world")
		r1, err := primaryCosigner.Round1()
		require.NoError(t, err)
		r2, err := secondaryCosigner.Round2(r1)
		require.NoError(t, err)
		r3, err := primaryCosigner.Round3(r2)
		require.NoError(t, err)
		r4, err := secondaryCosigner.Round4(r3, message)
		require.NoError(t, err)
		signature, err := primaryCosigner.Round5(r4, message)
		require.NoError(t, err)

		verifier, err := ecdsa.NewVerifier(suite)
		require.NoError(t, err)
		err = verifier.Verify(signature, publicKey, message)
		require.NoError(t, err)

		primaryTapeCheck, err := primaryTape.ExtractBytes("test", 32)
		require.NoError(t, err)
		secondaryTapeCheck, err := secondaryTape.ExtractBytes("test", 32)
		require.NoError(t, err)
		require.True(t, bytes.Equal(primaryTapeCheck, secondaryTapeCheck))
	}
}
