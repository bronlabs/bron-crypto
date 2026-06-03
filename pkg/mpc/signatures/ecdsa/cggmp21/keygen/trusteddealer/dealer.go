package trusteddealer

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/commitments/intcom"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	baseDealer "github.com/bronlabs/bron-crypto/pkg/mpc/dkg/trusteddealer"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/cggmp21"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

// DealShards deals CGGMP21 shards for the given ECDSA curve and access structure.
func DealShards[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](curve ecdsa.Curve[P, B, S], prng io.Reader, as accessstructures.Monotone) (map[sharing.ID]*cggmp21.Shard[P, B, S], error) {
	return dealShards(curve, prng, as, base.IFCKeyLength)
}

// DealShardsWithKeyLen used only for testing.
func DealShardsWithKeyLen[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](tb testing.TB, curve ecdsa.Curve[P, B, S], prng io.Reader, as accessstructures.Monotone, keyLen int) map[sharing.ID]*cggmp21.Shard[P, B, S] {
	tb.Helper()
	shards, err := dealShards(curve, prng, as, keyLen)
	require.NoError(tb, err)
	return shards
}

func dealShards[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](curve ecdsa.Curve[P, B, S], prng io.Reader, as accessstructures.Monotone, keyLen int) (map[sharing.ID]*cggmp21.Shard[P, B, S], error) {
	baseShards, err := baseDealer.Deal(curve, as, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot deal base shards")
	}

	paillierSecretKeys := make(map[sharing.ID]*paillier.SecretKey)
	paillierPublicKeys := make(map[sharing.ID]*paillier.PublicKey)
	ringPedersenSecretKeys := make(map[sharing.ID]*intcom.TrapdoorKey)
	ringPedersenPublicKeys := make(map[sharing.ID]*intcom.CommitmentKey)
	for id := range as.Shareholders().Iter() {
		sk, err := paillier.SampleBlumSecretKey(uint(keyLen), prng)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot sample paillier secret key")
		}
		paillierSecretKeys[id] = sk
		paillierPublicKeys[id] = sk.Public()

		tk, err := intcom.SampleTrapdoorKey(uint(keyLen), prng)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot sample ring pedersen trapdoor key")
		}
		ringPedersenSecretKeys[id] = tk
		ringPedersenPublicKeys[id] = tk.Export()
	}

	shards := make(map[sharing.ID]*cggmp21.Shard[P, B, S])
	for id := range as.Shareholders().Iter() {
		auxInfo, err := cggmp21.NewAuxInfo(paillierSecretKeys[id], paillierPublicKeys, ringPedersenSecretKeys[id], ringPedersenPublicKeys)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create auxiliary information")
		}
		baseShard, _ := baseShards.Get(id)
		shard, err := cggmp21.NewShard(baseShard, auxInfo)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create shard")
		}
		shards[id] = shard
	}

	return shards, nil
}
