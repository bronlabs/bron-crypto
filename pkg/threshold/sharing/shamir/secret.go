package shamir

import "github.com/bronlabs/bron-crypto/pkg/base/algebra"

type Secret[FE algebra.PrimeFieldElement[FE]] struct {
	v FE
}

func NewSecret[FE algebra.PrimeFieldElement[FE]](value FE) *Secret[FE] {
	return &Secret[FE]{v: value}
}

func (s *Secret[FE]) Value() FE {
	return s.v
}

func (s *Secret[FE]) Equal(other *Secret[FE]) bool {
	if s == nil || other == nil {
		return s == other
	}
	return s.v.Equal(other.v)
}

func (s *Secret[FE]) Clone() *Secret[FE] {
	return &Secret[FE]{
		v: s.v.Clone(),
	}
}
