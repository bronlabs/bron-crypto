package bigint

import (
	"encoding/json"
	"math/big"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/cronokirby/saferith"
)

var (
	Zero = New(big.NewInt(0))
	One  = New(big.NewInt(1))
	Two  = New(big.NewInt(2))
)

const Name = "BIG_INT"

var _ algebra.BigIntLike[*BigInt] = (*BigInt)(nil)
var _ algebra.NatLike[*BigInt] = (*BigInt)(nil)

type BigInt struct {
	V *big.Int
}

func New(v *big.Int) *BigInt {
	if v == nil {
		return nil
	}
	return &BigInt{
		V: v,
	}
}

func (n *BigInt) New(x *big.Int) *BigInt {
	return New(x)
}

func (n *BigInt) Abs() *BigInt {
	return New(new(big.Int).Abs(n.V))
}

func (n *BigInt) Neg() *BigInt {
	return New(new(big.Int).Neg(n.V))
}

func (n *BigInt) Cmp(x *BigInt) algebra.Ordering {
	if x == nil {
		panic(errs.NewIsNil("argument"))
	}
	return algebra.Ordering(n.V.Cmp(x.V))
}

func (n *BigInt) IsEven() bool {
	return n.V.Bit(0) == 0
}

func (n *BigInt) ModInverse(modulus *BigInt) (*BigInt, error) {
	if modulus == nil {
		panic(errs.NewIsNil("modulus"))
	}
	if modulus.Cmp(One) == algebra.LessThan {
		return nil, errs.NewValue("modulus < 1")
	}
	return New(new(big.Int).ModInverse(n.V, modulus.V)), nil
}

func (n *BigInt) Mod(modulus *BigInt) (*BigInt, error) {
	if modulus == nil {
		return nil, errs.NewIsNil("modulus")
	}
	if modulus.Cmp(One) == algebra.LessThan {
		return nil, errs.NewValue("modulus < 1")
	}
	return New(new(big.Int).Mod(n.V, modulus.V)), nil
}

func (n *BigInt) Add(x *BigInt) *BigInt {
	if x == nil {
		panic(errs.NewIsNil("argument"))
	}
	return New(new(big.Int).Add(n.V, x.V))
}

func (n *BigInt) Sub(x *BigInt) *BigInt {
	if x == nil {
		panic(errs.NewIsNil("argument"))
	}
	return New(new(big.Int).Sub(n.V, x.V))
}

func (n *BigInt) Mul(x *BigInt) *BigInt {
	if x == nil {
		panic(errs.NewIsNil("argument"))
	}
	return New(new(big.Int).Mul(n.V, x.V))
}

func (n *BigInt) Div(x *BigInt) (quotient *BigInt, remainder *BigInt, err error) {
	if x == nil {
		panic(errs.NewIsNil("argument"))
	}
	if x.Equal(Zero) {
		return nil, nil, errs.NewValue("can't divide by zero")
	}
	q, r := new(big.Int).DivMod(n.V, x.V, new(big.Int))
	return New(q), New(r), nil
}

func (n *BigInt) Exp(x, m *BigInt) *BigInt {
	if x == nil || m == nil {
		panic(errs.NewIsNil("argument"))
	}
	return New(new(big.Int).Exp(n.V, x.V, m.V))
}

func (n *BigInt) Sqrt() *BigInt {
	return New(new(big.Int).Sqrt(n.V))
}

func (n *BigInt) ModSqrt(modulus *BigInt) (*BigInt, error) {
	if modulus == nil {
		return nil, (errs.NewIsNil("modulus"))
	}
	if modulus.Cmp(One) == algebra.LessThan {
		return nil, errs.NewValue("modulus < 1")
	}
	return New(new(big.Int).ModSqrt(n.V, modulus.V)), nil
}

func (n *BigInt) IsProbablyPrime() bool {
	return n.V.ProbablyPrime(8)
}

func (n *BigInt) GCD(x *BigInt) *BigInt {
	if x == nil {
		panic(errs.NewIsNil("argument"))
	}
	return New(new(big.Int).GCD(nil, nil, n.V, x.V))
}

func (n *BigInt) LCM(x *BigInt) *BigInt {
	if x == nil {
		panic(errs.NewIsNil("argument"))
	}
	q, r, err := n.Mul(x).Div(n.GCD(x))
	if err != nil {
		panic(err)
	}
	if r.Cmp(Zero) == algebra.Equal {
		panic("r == 0")
	}
	return q
}

func (n *BigInt) SetUint64(x uint64) *BigInt {
	n.V = new(big.Int).SetUint64(x)
	return n
}

func (n *BigInt) SetInt64(x int64) *BigInt {
	n.V = new(big.Int).SetInt64(x)
	return n
}

func (n *BigInt) SetBytes(buf []byte) *BigInt {
	n.V = new(big.Int).SetBytes(buf)
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
