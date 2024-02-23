package krand

import (
	"fmt"
	"io"
	"sync"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/csprng"
	"github.com/copperexchange/krypton-primitives/pkg/csprng/nist"
	"github.com/copperexchange/krypton-primitives/pkg/csprng/randwrap"
)

type cacheType struct {
	wrappedReaders ds.Map[types.IdentityKey, csprng.CSPRNG]
	mu             sync.RWMutex
}

var cache *cacheType

//nolint:gochecknoinits // this is expected behaviour. we want to use the same instance.
func init() {
	cache = &cacheType{
		wrappedReaders: hashmap.NewHashableHashMap[types.IdentityKey, csprng.CSPRNG](),
		mu:             sync.RWMutex{},
	}
}

func New(prng io.Reader, deterministicWrappingKey types.AuthKey) (csprng.CSPRNG, error) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if result, exists := cache.wrappedReaders.Get(deterministicWrappingKey); exists {
		return result, nil
	}

	wrappedPrng, err := randwrap.NewWrappedReader(prng, deterministicWrappingKey)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't wrap provided prng")
	}

	nistPersonilizationString := fmt.Sprintf("krand_%x-", deterministicWrappingKey.PublicKey().ToAffineCompressed())

	wrappedNistPrng, err := nist.NewNistPRNG(randwrap.NBytes, wrappedPrng, nil, nil, []byte(nistPersonilizationString))
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't initialise nist prng with wrapped prng as its entropy source")
	}

	threadSafeWrappedNistPrng := csprng.NewThreadSafePrng(wrappedNistPrng)

	cache.wrappedReaders.Put(deterministicWrappingKey, threadSafeWrappedNistPrng)
	return threadSafeWrappedNistPrng, nil
}
