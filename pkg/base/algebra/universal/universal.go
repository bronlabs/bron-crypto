package universal

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
)

func NewDistribution[E algebra.Element[E]](s algebra.FiniteStructure[E]) *Distribution[E] {
	return &Distribution[E]{s: s}
}

type Distribution[E algebra.Element[E]] struct {
	s   algebra.FiniteStructure[E]
	rng io.Reader
}

func (d *Distribution[E]) Draw() E {
	return errs2.Must1(d.s.Random(d.rng))
}
