package bigint

import (
	"math/big"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
	"github.com/cronokirby/saferith"
)

var (
	Zero = B(big.NewInt(0))
	One  = B(big.NewInt(1))
	Two  = B(big.NewInt(2))
)

const Name = "BIG_INT"

var _ integer.Number[*BigInt] = (*BigInt)(nil)
var _ algebra.BigIntLike[*BigInt] = (*BigInt)(nil)

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

func (n *BigInt) Arithmetic() integer.Arithmetic[*BigInt] {
	return NewSignedArithmetic()
}

func (n *BigInt) Unwrap() *BigInt {
	return n
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
