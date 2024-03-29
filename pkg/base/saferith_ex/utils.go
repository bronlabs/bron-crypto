package saferith_ex

import (
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/saferith_ex/internal/boring"
)

func GenSafePrimePair(bits int) (p, q *saferith.Nat) {
	primes := make([]*saferith.Nat, 2)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		primes[0] = new(saferith.Nat).SetBytes(boring.NewDiffieHellmanGroup().GenerateParameters(bits).GetP().Bytes())
		wg.Done()
	}()
	go func() {
		primes[1] = new(saferith.Nat).SetBytes(boring.NewDiffieHellmanGroup().GenerateParameters(bits).GetP().Bytes())
		wg.Done()
	}()
	wg.Wait()

	return primes[0], primes[1]
}
