package trsa

import (
	"crypto/rsa"
	"encoding/json"
	"math/big"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/rep23"
)

var (
	_ datastructures.Equatable[*PublicShard] = (*PublicShard)(nil)
	_ json.Marshaler                         = (*PublicShard)(nil)
	_ json.Unmarshaler                       = (*PublicShard)(nil)

	_ datastructures.Equatable[*Shard] = (*Shard)(nil)
	_ json.Marshaler                   = (*Shard)(nil)
	_ json.Unmarshaler                 = (*Shard)(nil)
)

type PublicShard struct {
	N1 *saferith.Modulus
	N2 *saferith.Modulus
	E  uint64
}

func (s *PublicShard) Equal(rhs *PublicShard) bool {
	if s == nil || rhs == nil {
		return s == rhs
	}

	if _, eq, _ := s.N1.Cmp(rhs.N1); eq == 0 {
		return false
	}
	if _, eq, _ := s.N2.Cmp(rhs.N2); eq == 0 {
		return false
	}
	if s.E != rhs.E {
		return false
	}

	return true
}

func (s *PublicShard) PublicKey() *rsa.PublicKey {
	return &rsa.PublicKey{
		N: new(big.Int).Mul(s.N1.Big(), s.N2.Big()),
		E: int(s.E),
	}
}

type publicShardJson struct {
	N1 *big.Int `json:"n1"`
	N2 *big.Int `json:"n2"`
	E  uint64   `json:"e"`
}

func (s *PublicShard) MarshalJSON() ([]byte, error) {
	raw := &publicShardJson{
		N1: s.N1.Big(),
		N2: s.N2.Big(),
		E:  s.E,
	}

	data, err := json.Marshal(raw)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "cannot marshal shard")
	}
	return data, nil
}

func (s *PublicShard) UnmarshalJSON(b []byte) error {
	var raw publicShardJson
	if err := json.Unmarshal(b, &raw); err != nil {
		return errs.WrapSerialisation(err, "cannot unmarshal shard")
	}

	s.N1 = saferith.ModulusFromBytes(raw.N1.Bytes())
	s.N2 = saferith.ModulusFromBytes(raw.N2.Bytes())
	s.E = raw.E
	return nil
}

type Shard struct {
	PublicShard
	D1Share *rep23.IntShare
	D2Share *rep23.IntShare
}

func (s *Shard) Equal(rhs *Shard) bool {
	if s == nil || rhs == nil {
		return s == rhs
	}

	if !s.PublicShard.Equal(&rhs.PublicShard) {
		return false
	}
	if !s.D1Share.Equal(rhs.D1Share) {
		return false
	}
	if !s.D2Share.Equal(rhs.D2Share) {
		return false
	}

	return true
}

type shardJson struct {
	publicShardJson
	D1Share *rep23.IntShare `json:"d1_share"` //nolint:tagliatelle // snake_case
	D2Share *rep23.IntShare `json:"d2_share"` //nolint:tagliatelle // snake_case
}

func (s *Shard) MarshalJSON() ([]byte, error) {
	raw := &shardJson{
		publicShardJson: publicShardJson{
			N1: s.N1.Big(),
			N2: s.N2.Big(),
			E:  s.E,
		},
		D1Share: s.D1Share,
		D2Share: s.D2Share,
	}

	data, err := json.Marshal(raw)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "cannot marshal shard")
	}
	return data, nil
}

func (s *Shard) UnmarshalJSON(b []byte) error {
	var raw shardJson
	if err := json.Unmarshal(b, &raw); err != nil {
		return errs.WrapSerialisation(err, "cannot unmarshal shard")
	}

	s.N1 = saferith.ModulusFromBytes(raw.N1.Bytes())
	s.N2 = saferith.ModulusFromBytes(raw.N2.Bytes())
	s.E = raw.E
	s.D1Share = raw.D1Share
	s.D2Share = raw.D2Share
	return nil
}
