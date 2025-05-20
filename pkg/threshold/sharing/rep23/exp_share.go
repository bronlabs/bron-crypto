package rep23

import (
	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

var (
	_ sharing.Share = (*IntExpShare)(nil)
)

type IntExpShare struct {
	Id   types.SharingID
	Prev *saferith.Nat
	Next *saferith.Nat
}

func (s *IntExpShare) SharingId() types.SharingID {
	return s.Id
}
