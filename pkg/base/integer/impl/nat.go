package impl

import "github.com/copperexchange/krypton-primitives/pkg/base/integer"

var _ integer.Nat[*N, *Nat] = (*Nat)(nil)

type Nat struct {
	PositiveNatMixin[*N, *Nat]
}
