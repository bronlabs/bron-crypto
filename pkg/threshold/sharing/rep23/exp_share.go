package rep23

import (
	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

var (
	_ sharing.Share                          = (*IntExpShare)(nil)
	_ datastructures.Equatable[*IntExpShare] = (*IntExpShare)(nil)
)

type IntExpShare struct {
	Id   types.SharingID
	Prev *saferith.Nat
	Next *saferith.Nat
}

func (s *IntExpShare) SharingId() types.SharingID {
	return s.Id
}

func (s *IntExpShare) Equal(rhs *IntExpShare) bool {
	if s == nil || rhs == nil {
		return s == rhs
	}

	return s.Id == rhs.Id &&
		s.Prev.Eq(rhs.Prev) != 0 &&
		s.Next.Eq(rhs.Next) != 0
}
