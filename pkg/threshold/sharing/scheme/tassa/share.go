package tassa

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

type Share[F algebra.PrimeFieldElement[F]] struct {
	id    sharing.ID
	value F
}

func (s *Share[F]) ID() sharing.ID {
	return s.id
}

func (s *Share[F]) Equal(rhs *Share[F]) bool {
	if s == nil || rhs == nil {
		return s == rhs
	}

	return s.id == rhs.id && s.value.Equal(rhs.value)
}

func (s *Share[F]) HashCode() ds.HashCode {
	return s.value.HashCode().Combine(ds.HashCode(s.id))
}

func (s *Share[F]) Value() F {
	return s.value
}

func (s *Share[F]) Op(e *Share[F]) *Share[F] {
	if e == nil || e.id != s.id {
		panic("cannot add shares with different IDs")
	}

	return &Share[F]{
		id:    s.id,
		value: s.value.Op(e.value),
	}
}

func (s *Share[F]) ScalarOp(actor F) *Share[F] {
	return &Share[F]{
		id:    s.id,
		value: s.value.Mul(actor),
	}
}
