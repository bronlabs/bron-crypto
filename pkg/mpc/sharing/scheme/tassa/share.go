package tassa

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
)

// Share is a Tassa share bound to one shareholder ID.
type Share[F algebra.PrimeFieldElement[F]] struct {
	id    sharing.ID
	value F
}

// ID returns the shareholder identifier associated with this share.
func (s *Share[F]) ID() sharing.ID {
	return s.id
}

// Equal reports whether two shares have the same ID and value.
func (s *Share[F]) Equal(rhs *Share[F]) bool {
	if s == nil || rhs == nil {
		return s == rhs
	}

	return s.id == rhs.id && s.value.Equal(rhs.value)
}

// HashCode returns a hash code for this share.
func (s *Share[F]) HashCode() ds.HashCode {
	return s.value.HashCode().Combine(ds.HashCode(s.id))
}

// Value returns the field element carried by this share.
func (s *Share[F]) Value() F {
	return s.value
}

// Op adds two shares with the same shareholder ID.
//
// Op panics if the IDs differ.
func (s *Share[F]) Op(e *Share[F]) *Share[F] {
	if e == nil || e.id != s.id {
		panic("cannot add shares with different IDs")
	}

	return &Share[F]{
		id:    s.id,
		value: s.value.Op(e.value),
	}
}

// ScalarOp multiplies the share value by a field scalar.
func (s *Share[F]) ScalarOp(actor F) *Share[F] {
	return &Share[F]{
		id:    s.id,
		value: s.value.Mul(actor),
	}
}
