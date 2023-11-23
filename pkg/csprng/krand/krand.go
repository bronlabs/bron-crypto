package krand

import (
	"fmt"
	"io"
	"sync"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/csprng"
	"github.com/copperexchange/krypton-primitives/pkg/csprng/nist"
	"github.com/copperexchange/krypton-primitives/pkg/csprng/randwrap"
)

type cacheType struct {
	wrappedReaders map[types.IdentityHash]csprng.CSPRNG
	mu             sync.RWMutex
}

var cache *cacheType

//nolint:gochecknoinits // this is expected behaviour. we want to use the same instance.
func init() {
	cache = &cacheType{
		wrappedReaders: map[types.IdentityHash]csprng.CSPRNG{},
		mu:             sync.RWMutex{},
	}
}

func New(prng io.Reader, deterministicWrappingKey integration.AuthKey) (csprng.CSPRNG, error) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if result, exists := cache.wrappedReaders[deterministicWrappingKey.Hash()]; exists {
		return result, nil
	}

	wrappedPrng, err := randwrap.NewWrappedReader(prng, deterministicWrappingKey)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't wrap provided prng")
	}

	nistPersonilizationString := fmt.Sprintf("krand_%x-", deterministicWrappingKey.Hash())

	wrappedNistPrng, err := nist.NewNistPRNG(randwrap.NBytes, wrappedPrng, nil, nil, []byte(nistPersonilizationString))
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't initialise nist prng with wrapped prng as its entropy source")
	}

	threadSafeWrappedNistPrng := csprng.NewThreadSafePrng(wrappedNistPrng)

	cache.wrappedReaders[deterministicWrappingKey.Hash()] = threadSafeWrappedNistPrng
	return threadSafeWrappedNistPrng, nil
}
