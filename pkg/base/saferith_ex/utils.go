package saferith_ex

import (
	"github.com/cronokirby/saferith"
	"golang.org/x/sync/errgroup"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/saferith_ex/internal/boring"
)

func GenSafePrimePair(bits int) (p, q *saferith.Nat, err error) {
	primes := make([]*saferith.Nat, 2)

	var eg errgroup.Group
	eg.Go(func() error {
		pBytes, err := boring.NewDiffieHellmanGroup().GenerateParameters(bits).GetP().Bytes()
		if err != nil {
			return err //nolint:wrapcheck // deliberate forward
		}
		primes[0] = new(saferith.Nat).SetBytes(pBytes)
		return nil
	})
	eg.Go(func() error {
		qBytes, err := boring.NewDiffieHellmanGroup().GenerateParameters(bits).GetP().Bytes()
		if err != nil {
			return err //nolint:wrapcheck // deliberate forward
		}
		primes[1] = new(saferith.Nat).SetBytes(qBytes)
		return nil
	})

	err = eg.Wait()
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot generate primes")
	}

	return primes[0], primes[1], nil
}
