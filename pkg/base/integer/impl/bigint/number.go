package bigint

import (
	"encoding/json"
	"math/big"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl"
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
var _ impl.ImplAdapter[*BigInt, *big.Int] = (*BigInt)(nil)

type BigInt struct {
	*big.Int
}

func B(v *big.Int) *BigInt {
	if v == nil {
		return nil
	}
	return &BigInt{
		Int: v,
	}
}

func (n *BigInt) Impl() *big.Int {
	return n.Int
}

func (n *BigInt) Wrap(x *big.Int) *BigInt {
	return B(x)
}

func (n *BigInt) Clone() *BigInt {
	return &BigInt{
		Int: new(big.Int).Set(n.Big()),
	}
}

func (n *BigInt) Equal(x *BigInt) bool {
	return n.Int.Cmp(x.Int) == 0
}

func (n *BigInt) Big() *big.Int {
	return n.Int
}

func (n *BigInt) FromBig(v *big.Int) *BigInt {
	return &BigInt{
		Int: v,
	}
}

func (n *BigInt) Uint64() uint64 {
	return n.Int.Uint64()
}

func (n *BigInt) Nat() *saferith.Nat {
	return new(saferith.Nat).SetBig(n.Int, -1)
}

func (n *BigInt) SetNat(v *saferith.Nat) *BigInt {
	return &BigInt{
		Int: v.Big(),
	}
}

func (n *BigInt) AnnouncedLen() int {
	return n.Int.BitLen()
}

func (n *BigInt) TrueLen() uint {
	return uint(n.Int.BitLen())
}

func (n *BigInt) MarshalJSON() ([]byte, error) {
	return n.MarshalJSON()
}
func (n *BigInt) UnmarshalJSON(data []byte) error {
	var b *big.Int
	if err := json.Unmarshal(data, b); err != nil {
		return errs.WrapSerialisation(err, "could not marshal big int")
	}
	n.Int = b
	return nil
}
