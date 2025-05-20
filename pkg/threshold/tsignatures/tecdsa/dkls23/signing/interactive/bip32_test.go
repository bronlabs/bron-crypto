package interactive_test

import (
	crand "crypto/rand"
	"crypto/sha256"
	"fmt"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/bronlabs/bron-crypto/pkg/base/combinatorics"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	ttu "github.com/bronlabs/bron-crypto/pkg/base/types/testutils"
	"github.com/bronlabs/bron-crypto/pkg/csprng/fkechacha20"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tecdsa/dkls23"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tecdsa/dkls23/keygen/trusted_dealer"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tecdsa/dkls23/testutils"
)

func Test_SignWithDerivedShardBip32(t *testing.T) {
	t.Parallel()

	const threshold = 2
	const n = 3
	const message = "Hello World!"
	curve := k256.NewCurve()
	h := sha256.New

	cipherSuite, err := ttu.MakeSigningSuite(curve, h)
	require.NoError(t, err)

	allIdentities, err := ttu.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)

	protocol, err := ttu.MakeThresholdSignatureProtocol(cipherSuite, allIdentities, threshold, allIdentities)
	require.NoError(t, err)

	parentShards, err := trusted_dealer.Keygen(protocol, crand.Reader)
	require.NoError(t, err)

	extendedShards := hashmap.NewHashableHashMap[types.IdentityKey, *dkls23.ExtendedShard]()
	for id, parentShard := range parentShards.Iter() {
		extendedShard, err := parentShard.Derive(9876)
		require.NoError(t, err)
		require.False(t, extendedShard.PublicKey().Equal(parentShard.PublicKey()))
		extendedShards.Put(id, extendedShard)
	}

	seededPrng, err := fkechacha20.NewPrng(nil, nil)
	require.NoError(t, err)

	N := make([]int, n)
	for i := range n {
		N[i] = i
	}

	combinations, err := combinatorics.Combinations(N, uint(threshold))
	require.NoError(t, err)
	if testing.Short() {
		combinations = combinations[:1]
	}
	for _, combinationIndices := range combinations {
		identities := []types.IdentityKey{}
		selectedShards := []*dkls23.Shard{}
		i := 0
		for identity, shard := range extendedShards.Iter() {
			if len(identities) == threshold {
				break
			}
			if slices.Index(combinationIndices, i) == -1 {
				i++
				continue
			}
			identities = append(identities, identity)
			selectedShards = append(selectedShards, shard.AsShard())
			i++
		}
		t.Run(fmt.Sprintf("running the happy path with identities %v", identities), func(t *testing.T) {
			t.Parallel()
			testutils.RunInteractiveSignHappyPath(t, protocol, identities, selectedShards, []byte(message), seededPrng, nil)
		})
	}
}

func Test_SignWithDerivedShardGeneric(t *testing.T) {
	t.Parallel()

	const threshold = 2
	const n = 3
	const message = "Hello World!"
	curve := p256.NewCurve()
	h := sha3.New256

	cipherSuite, err := ttu.MakeSigningSuite(curve, h)
	require.NoError(t, err)

	allIdentities, err := ttu.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)

	protocol, err := ttu.MakeThresholdSignatureProtocol(cipherSuite, allIdentities, threshold, allIdentities)
	require.NoError(t, err)

	parentShards, err := trusted_dealer.Keygen(protocol, crand.Reader)
	require.NoError(t, err)

	extendedShards := hashmap.NewHashableHashMap[types.IdentityKey, *dkls23.ExtendedShard]()
	for id, parentShard := range parentShards.Iter() {
		extendedShard, err := parentShard.Derive(3254)
		require.NoError(t, err)
		require.False(t, extendedShard.PublicKey().Equal(parentShard.PublicKey()))
		extendedShards.Put(id, extendedShard)
	}

	seededPrng, err := fkechacha20.NewPrng(nil, nil)
	require.NoError(t, err)

	N := make([]int, n)
	for i := range n {
		N[i] = i
	}

	combinations, err := combinatorics.Combinations(N, uint(threshold))
	require.NoError(t, err)
	if testing.Short() {
		combinations = combinations[:1]
	}
	for _, combinationIndices := range combinations {
		identities := []types.IdentityKey{}
		selectedShards := []*dkls23.Shard{}
		i := 0
		for identity, shard := range extendedShards.Iter() {
			if len(identities) == threshold {
				break
			}
			if slices.Index(combinationIndices, i) == -1 {
				i++
				continue
			}
			identities = append(identities, identity)
			selectedShards = append(selectedShards, shard.AsShard())
			i++
		}
		t.Run(fmt.Sprintf("running the happy path with identities %v", identities), func(t *testing.T) {
			t.Parallel()
			testutils.RunInteractiveSignHappyPath(t, protocol, identities, selectedShards, []byte(message), seededPrng, nil)
		})
	}
}
