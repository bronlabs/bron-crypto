package binrep3

import (
	"math/bits"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

// Share is a replicated share of (F_2)^64 i.e., 64 shares of F_2, [not to be confused with F_(2^64)]
type Share struct {
	id sharing.ID
	p  uint64
	n  uint64
}

func NewShare(id sharing.ID, prev, next uint64) *Share {
	return &Share{
		id: id,
		p:  prev,
		n:  next,
	}
}

func (s *Share) Clone() *Share {
	clone := &Share{
		id: s.id,
		p:  s.p,
		n:  s.n,
	}
	return clone
}

func (s *Share) ID() sharing.ID {
	return s.id
}

func (s *Share) Next() uint64 {
	return s.n
}

func (s *Share) Prev() uint64 {
	return s.p
}

func (s *Share) HashCode() base.HashCode {
	return base.HashCode(uint64(s.id) ^ s.p ^ s.n)
}

func (s *Share) Equal(other *Share) bool {
	return s.id == other.id && s.p == other.p && s.n == other.n
}

// Xor is a homomorphic addition in F_2
func (s *Share) Xor(rhs *Share) *Share {
	if s.id != rhs.id {
		panic("shares must have the same sharing id")
	}

	return NewShare(s.id, s.p^rhs.p, s.n^rhs.n)
}

func (s *Share) XorPublic(rhs uint64) *Share {
	// we are cheating here: this works only for 2 out of 3 (which it is)
	return NewShare(s.id, s.p^rhs, s.n^rhs)
}

// AndPublic is a scalar multiplication in F_2
func (s *Share) AndPublic(rhs uint64) *Share {
	return NewShare(s.id, s.p&rhs, s.n&rhs)
}

// ShiftLeft, ShiftRight and RotateRight below are just rearranging of F_2 shares

func (s *Share) ShiftLeft(k int) *Share {
	return NewShare(s.id, s.p<<k, s.n<<k)
}

func (s *Share) ShiftRight(k int) *Share {
	return NewShare(s.id, s.p>>k, s.n>>k)
}

func (s *Share) RotateRight(k int) *Share {
	return NewShare(s.id, bits.RotateLeft64(s.p, -k), bits.RotateLeft64(s.n, -k))
}
