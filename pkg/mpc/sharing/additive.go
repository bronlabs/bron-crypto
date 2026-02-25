package sharing

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
)

// NewAdditiveShare creates a new additive share with the given ID and value.
func NewAdditiveShare[E algebra.GroupElement[E]](id ID, v E) (*AdditiveShare[E], error) {
	if id == 0 || utils.IsNil(v) {
		return nil, ErrIsNil.WithMessage("id or value is nil")
	}
	return &AdditiveShare[E]{
		id: id,
		v:  v,
	}, nil
}

// AdditiveShare represents an additive secret share consisting of a shareholder ID
// and a group element value.
type AdditiveShare[E algebra.GroupElement[E]] struct {
	id ID
	v  E
}

// ID returns the shareholder identifier for this share.
func (s *AdditiveShare[E]) ID() ID {
	return s.id
}

// Value returns the group element value of this share.
func (s *AdditiveShare[E]) Value() E {
	return s.v
}

// Equal returns true if two shares have the same ID and value.
func (s *AdditiveShare[E]) Equal(other *AdditiveShare[E]) bool {
	if s == nil || other == nil {
		return s == other
	}
	return s.id == other.id && s.v.Equal(other.v)
}

// Op is an alias for Add, implementing the group element interface.
func (s *AdditiveShare[E]) Op(other *AdditiveShare[E]) *AdditiveShare[E] {
	return s.Add(other)
}

// Add returns a new share that is the component-wise sum of two shares.
// Both shares must have the same ID.
func (s *AdditiveShare[E]) Add(other *AdditiveShare[E]) *AdditiveShare[E] {
	return &AdditiveShare[E]{
		id: s.id,
		v:  s.v.Op(other.v),
	}
}

// ScalarOp returns a new share that is the result of multiplying this share's value by a scalar actor. The ID remains unchanged.
func (s *AdditiveShare[E]) ScalarOp(actor algebra.Numeric) *AdditiveShare[E] {
	return &AdditiveShare[E]{
		id: s.id,
		v:  algebrautils.ScalarMul(s.v, actor),
	}
}

// Clone returns a deep copy of this share.
func (s *AdditiveShare[E]) Clone() *AdditiveShare[E] {
	return &AdditiveShare[E]{
		id: s.id,
		v:  s.v.Clone(),
	}
}

// HashCode returns a hash code for this share, for use in hash-based collections.
func (s *AdditiveShare[E]) HashCode() base.HashCode {
	return base.HashCode(s.id).Combine(s.v.HashCode())
}
