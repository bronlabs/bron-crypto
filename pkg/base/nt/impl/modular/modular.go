package modular

import (
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/internal"
)

type exponentiator[E any, M internal.ModulusMutable[N], N internal.NatMutable[N]] interface {
	Modulus() M
	Exp(out, base, exp N) (ok ct.Bool)
}

type Exponentiator[E exponentiator[E, M, N], M internal.ModulusMutable[N], N internal.NatMutable[N]] exponentiator[E, M, N]
