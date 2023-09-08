//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package primes

import (
	crand "crypto/rand"
	"math"
	"math/big"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton/pkg/base/errs"
)

// GenerateSafePrime creates a prime number `p`
// where (`p`-1)/2 is also prime with at least `bits`.
var GenerateSafePrime = func(bits uint) (*saferith.Nat, error) {
	if bits < 3 {
		return nil, errs.NewFailed("safe prime size must be at least 3-bits")
	}

	var p *big.Int
	var err error
	checks := int(math.Max(float64(bits)/16, 8))
	for {
		// rand.Prime throws an error if bits < 2
		// -1 so the Sophie-Germain prime is 1023 bits
		// and the Safe prime is 1024
		p, err = crand.Prime(crand.Reader, int(bits)-1)
		if err != nil {
			return nil, errs.WrapFailed(err, "reading from crand")
		}
		p.Add(p.Lsh(p, 1), big.NewInt(1))

		if p.ProbablyPrime(checks) {
			break
		}
	}

	return new(saferith.Nat).SetBig(p, int(bits)), nil
}
