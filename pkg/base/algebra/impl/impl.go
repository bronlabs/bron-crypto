package impl

import "github.com/copperexchange/krypton-primitives/pkg/base/algebra"

type ImplAdapter[E algebra.Element, Impl any] interface {
	Impl() Impl
	New(x Impl) E
}
