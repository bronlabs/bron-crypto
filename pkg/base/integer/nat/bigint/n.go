package bigint

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
	bg "github.com/copperexchange/krypton-primitives/pkg/base/integer/impl/bigint"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer/nat/impl"
)

var _ integer.N[*N, *Nat] = (*N)(nil)
var _ integer.NaturalRig[*N, *Nat] = (*N)(nil)

var _ impl.HolesN[*N, *Nat] = (*N)(nil)

type N struct {
	impl.N[*N, *Nat]
}

func (np *N) Name() string {
	return natName
}

func (np *N) Arithmetic() integer.Arithmetic[*Nat] {
	return bg.NewUnsignedArithmetic[*Nat](-1, false)
}

func (np *N) Unwrap() *N {
	return np
}

func (np *N) domain() algebra.Set[*Nat] {
	return np.Element().Structure()
}

func (np *N) Successor() algebra.Successor[*Nat] {
	return integer.NewSuccessorOperator(np.Arithmetic(), np.domain)
}

func (np *N) Element() *Nat {
	return np.One()
}

func (np *N) New(v uint64) *Nat {
	return nil
}
