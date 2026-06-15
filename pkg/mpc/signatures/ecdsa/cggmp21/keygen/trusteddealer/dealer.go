package trusteddealer

import (
	"io"
	"maps"
	"sync"
	"testing"

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
	"github.com/bronlabs/errs-go/errs"
	"golang.org/x/sync/errgroup"
)

// Deal deals CGGMP21 shards for the given ECDSA curve and access structure.
// Note: this function requires a thread-safe PRNG.
func Deal[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](curve ecdsa.Curve[P, B, S], as accessstructures.Monotone, keyLen int, prng io.Reader) (map[sharing.ID]*cggmp21.Shard[P, B, S], error) {
	if curve == nil || as == nil || prng == nil {
		return nil, cggmp21.ErrIsNil.WithMessage("argument")
	}
	if keyLen < 8 || (keyLen%8) != 0 {
		return nil, cggmp21.ErrFailed.WithMessage("key length too short or unaligned")
	}
	if !testing.Testing() {
		if keyLen < base.IFCKeyLength {
			return nil, cggmp21.ErrFailed.WithMessage("key length too short")
		}
	}

	params, err := cggmp21.NewParameters(curve, keyLen)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create parameters")
	}
	baseShards, err := baseDealer.Deal(curve, as, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot deal base shards")
	}
	refreshID := make([]byte, params.Kappa()/8)
	if _, err = io.ReadFull(prng, refreshID); err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot read refresh ID")
	}

	lock := new(sync.Mutex)
	paillierSecretKeys := make(map[sharing.ID]*paillier.SecretKey)
	paillierPublicKeys := make(map[sharing.ID]*paillier.PublicKey)
	ringPedersenSecretKeys := make(map[sharing.ID]*intcom.TrapdoorKey)
	ringPedersenPublicKeys := make(map[sharing.ID]*intcom.CommitmentKey)
	var errGroup errgroup.Group
	for id := range as.Shareholders().Iter() {
		errGroup.Go(func() error {
			sk, err := paillier.SampleBlumSecretKey(uint(keyLen), prng)
			if err != nil {
				return errs.Wrap(err).WithMessage("cannot sample paillier secret key")
			}

			lock.Lock()
			defer lock.Unlock()
			paillierSecretKeys[id] = sk
			paillierPublicKeys[id] = sk.Public()
			return nil
		})

		errGroup.Go(func() error {
			tk, err := intcom.SampleTrapdoorKey(uint(keyLen), prng)
			if err != nil {
				return errs.Wrap(err).WithMessage("cannot sample ring pedersen trapdoor key")
			}

			lock.Lock()
			defer lock.Unlock()
			ringPedersenSecretKeys[id] = tk
			ringPedersenPublicKeys[id] = tk.Export()
			return nil
		})
	}
	err = errGroup.Wait()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot sample auxiliary information")
	}

	shards := make(map[sharing.ID]*cggmp21.Shard[P, B, S])
	for id := range as.Shareholders().Iter() {
		paillierKeys := maps.Clone(paillierPublicKeys)
		delete(paillierKeys, id)
		ringPedersenKeys := maps.Clone(ringPedersenPublicKeys)
		delete(ringPedersenKeys, id)

		auxInfo, err := cggmp21.NewAuxInfo(paillierSecretKeys[id], paillierKeys, ringPedersenSecretKeys[id], ringPedersenKeys)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create auxiliary information")
		}
		baseShard, _ := baseShards.Get(id)
		shard, err := cggmp21.NewShard(baseShard, auxInfo, refreshID)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create shard")
		}
		shards[id] = shard
	}

	return shards, nil
}
