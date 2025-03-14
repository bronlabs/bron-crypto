package krand

import (
	"fmt"
	"io"
	"runtime/debug"
	"strings"
	"sync"

	"golang.org/x/sys/cpu"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/csprng"
	"github.com/bronlabs/bron-crypto/pkg/csprng/fkechacha20"
	"github.com/bronlabs/bron-crypto/pkg/csprng/nist"
	"github.com/bronlabs/bron-crypto/pkg/csprng/randwrap"
	"github.com/bronlabs/bron-crypto/thirdparty/golang/crypto/chacha20"
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

func newWrappedNistPrng(deterministicWrappingKey types.AuthKey, wrappedPrng *randwrap.WrappedReader, personalizationString string) (csprng.CSPRNG, error) {
	wrappedNistPrng, err := nist.NewNistPRNG(randwrap.NBytes, wrappedPrng, nil, nil, []byte(personalizationString))
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't initialise nist prng with wrapped prng as its entropy source")
	}
	threadSafeWrappedNistPrng := csprng.NewThreadSafePrng(wrappedNistPrng)
	cache.wrappedReaders.Put(deterministicWrappingKey, threadSafeWrappedNistPrng)
	return threadSafeWrappedNistPrng, nil
}

func newWrappedChaChaPrng(deterministicWrappingKey types.AuthKey, wrappedPrng *randwrap.WrappedReader, personalizationString string) (csprng.CSPRNG, error) {
	seed := make([]byte, chacha20.KeySize)
	if _, err := io.ReadFull(wrappedPrng, seed); err != nil {
		return nil, errs.WrapRandomSample(err, "cannot sample seed")
	}
	wrappedChaChaPrng, err := fkechacha20.NewPrng(seed, []byte(personalizationString))
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't initialise chacha prng")
	}
	threadSafeWrappedChaChaPrng := csprng.NewThreadSafePrng(wrappedChaChaPrng)
	cache.wrappedReaders.Put(deterministicWrappingKey, threadSafeWrappedChaChaPrng)
	return threadSafeWrappedChaChaPrng, nil
}

func builtWithPurego() bool {
	info, available := debug.ReadBuildInfo()
	// if build info is not available, assume purego was passed as build tag
	if !available {
		return true
	}
	for _, s := range info.Settings {
		if s.Key == "-tags" {
			if strings.Contains(s.Value, "purego") {
				return true
			}
			break
		}
	}
	return false
}

func hardwareAESSupport() bool {
	if builtWithPurego() {
		return false
	}
	if cpu.X86.HasAES || cpu.ARM64.HasAES {
		return true
	}
	return false
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
	personalizationString := fmt.Sprintf("krand_%x-", deterministicWrappingKey.PublicKey().ToAffineCompressed())

	// if hardware AES is supported then use AES-CTR-DRBG
	if hardwareAESSupport() {
		return newWrappedNistPrng(deterministicWrappingKey, wrappedPrng, personalizationString)
	}
	// otherwise use ChaCha
	return newWrappedChaChaPrng(deterministicWrappingKey, wrappedPrng, personalizationString)
}
