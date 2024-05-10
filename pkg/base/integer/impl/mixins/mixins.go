package mixins

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
)

type NPlus[S algebra.Structure, E algebra.Element] struct {
}

type NatPlus[S algebra.Structure, E algebra.Element] struct {
	integer.NatPlus[S, E]
}
