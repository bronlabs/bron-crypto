package rep23

import (
	"encoding/json"
	"math/big"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

var (
	_ sharing.Share                          = (*IntExpShare)(nil)
	_ datastructures.Equatable[*IntExpShare] = (*IntExpShare)(nil)
	_ json.Marshaler                         = (*IntExpShare)(nil)
	_ json.Unmarshaler                       = (*IntExpShare)(nil)
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

type intExpShareJson struct {
	Id   uint64   `json:"id"`
	Next *big.Int `json:"next"`
	Prev *big.Int `json:"prev"`
}

func (s *IntExpShare) MarshalJSON() ([]byte, error) {
	raw := &intExpShareJson{
		Id:   uint64(s.Id),
		Next: s.Next.Big(),
		Prev: s.Prev.Big(),
	}

	data, err := json.Marshal(raw)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "cannot marshal share")
	}
	return data, nil
}

func (s *IntExpShare) UnmarshalJSON(b []byte) error {
	var raw intExpShareJson
	if err := json.Unmarshal(b, &raw); err != nil {
		return errs.WrapSerialisation(err, "cannot unmarshal share")
	}

	s.Id = types.SharingID(raw.Id)
	s.Next = new(saferith.Nat).SetBig(raw.Next, raw.Next.BitLen())
	s.Prev = new(saferith.Nat).SetBig(raw.Prev, raw.Prev.BitLen())
	return nil
}
