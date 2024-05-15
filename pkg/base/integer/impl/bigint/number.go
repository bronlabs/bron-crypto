package bigint

import (
	"encoding/json"
	"math/big"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/cronokirby/saferith"
)

var (
	Zero = B(big.NewInt(0))
	One  = B(big.NewInt(1))
	Two  = B(big.NewInt(2))
)

const Name = "BIG_INT"

var _ algebra.BigIntLike[*BigInt] = (*BigInt)(nil)
var _ algebra.NatLike[*BigInt] = (*BigInt)(nil)

type BigInt struct {
	V *big.Int
}

func B(v *big.Int) *BigInt {
	if v == nil {
		return nil
	}
	return &BigInt{
		V: v,
	}
}

func (n *BigInt) New(x *big.Int) *BigInt {
	n = B(x)
	return n
}

func (n *BigInt) SetUint64(x uint64) *BigInt {
	n.V = new(big.Int).SetUint64(x)
	return n
}

func (n *BigInt) SetInt64(x int64) *BigInt {
	n.V = new(big.Int).SetInt64(x)
	return n
}

func (n *BigInt) Clone() *BigInt {
	return &BigInt{
		V: new(big.Int).Set(n.Big()),
	}
}

func (n *BigInt) Equal(x *BigInt) bool {
	return n.V.Cmp(x.V) == 0
}

func (n *BigInt) Big() *big.Int {
	return n.V
}

func (n *BigInt) FromBig(v *big.Int) *BigInt {
	return &BigInt{
		V: v,
	}
}

func (n *BigInt) Uint64() uint64 {
	return n.V.Uint64()
}
func (n *BigInt) Int64() int64 {
	return n.V.Int64()
}

func (n *BigInt) Nat() *saferith.Nat {
	return new(saferith.Nat).SetBig(n.V, n.V.BitLen())
}

func (n *BigInt) SetNat(v *saferith.Nat) *BigInt {
	return &BigInt{
		V: v.Big(),
	}
}

func (n *BigInt) AnnouncedLen() int {
	return n.V.BitLen()
}

func (n *BigInt) TrueLen() uint {
	return uint(n.V.BitLen())
}

func (n *BigInt) MarshalJSON() ([]byte, error) {
	return n.MarshalJSON()
}
func (n *BigInt) UnmarshalJSON(data []byte) error {
	var b *big.Int
	if err := json.Unmarshal(data, b); err != nil {
		return errs.WrapSerialisation(err, "could not marshal big int")
	}
	n.V = b
	return nil
}
