package testutils

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/csprng"
	"github.com/copperexchange/krypton-primitives/pkg/csprng/fkechacha20"
)

// MakeTestPrng creates a new deterministic PRNG for testing purposes. The seed
// is used to initialize the PRNG, and if it is not provided, a default seed is
// used. The PRNG is thread-safe.
func MakeTestPrng(seed []byte) csprng.CSPRNG {

	// Clean up the seed, ensuring it is 32 bytes long
	switch seedLen := len(seed); {
	case seedLen == 0:
		seed = []byte("You shall not pass! Gandalf said")
	case seedLen < 32:
		seed = bitstring.PadToRight(seed, 32-len(seed))
	case seedLen > 32:
		seed = seed[:32]
	}

	prng, err := fkechacha20.NewPrng(seed, nil)
	if err != nil {
		panic(err)
	}
	threadSafePrng := csprng.NewThreadSafePrng(prng)
	return threadSafePrng
}
