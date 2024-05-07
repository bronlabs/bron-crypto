//go:build !purego && !nobignum

package nats

import (
	natImpl "github.com/copperexchange/krypton-primitives/pkg/base/bignat/internal/bignum/nat"
	"github.com/copperexchange/krypton-primitives/pkg/base/bignat/nat"
	"github.com/copperexchange/krypton-primitives/pkg/cgo/boring"
	"io"
	"math/big"
	"sync"
)

type BnNatsImpl struct{}

var (
	bnNatsOnce sync.Once
	bnNats     *BnNatsImpl
)

func NewNats() *BnNatsImpl {
	bnNatsOnce.Do(func() {
		bnNats = &BnNatsImpl{}
	})
	return bnNats
}

func (b *BnNatsImpl) NewBig(bi *big.Int) nat.Nat {
	buffer := bi.Bytes()
	return b.NewFromBytes(buffer)
}

func (b *BnNatsImpl) NewModulus(m nat.Nat) nat.Modulus {
	bn := (*boring.BigNum)(m.(*natImpl.BnNatImpl))
	bnClone, err := bn.Copy()
	if err != nil {
		panic(err)
	}

	ctx := boring.NewBigNumCtx()
	montCtx, err := boring.NewBigNumMontCtx(bnClone, ctx)
	if err != nil {
		panic(err)
	}

	return &natImpl.BnModImpl{
		MontCtx: montCtx,
		BigNum:  bnClone,
	}
}

func (b *BnNatsImpl) New() nat.Nat {
	return (*natImpl.BnNatImpl)(boring.NewBigNum())
}

func (b *BnNatsImpl) Zero() nat.Nat {
	return (*natImpl.BnNatImpl)(boring.Zero)
}

func (b *BnNatsImpl) One() nat.Nat {
	return (*natImpl.BnNatImpl)(boring.One)
}

func (b *BnNatsImpl) NewUint64(val uint64) nat.Nat {
	u64, err := boring.NewBigNum().SetU64(val)
	if err != nil {
		panic(err)
	}

	return (*natImpl.BnNatImpl)(u64)
}

func (b *BnNatsImpl) NewRandomN(n nat.Nat, _ io.Reader) nat.Nat {
	//TODO implement me
	panic("implement me")
}

func (b *BnNatsImpl) NewRandomBits(n uint, prng io.Reader) nat.Nat {
	bytesLen := int((n + 7) / 8)
	buf := make([]byte, bytesLen)
	_, err := io.ReadFull(prng, buf)
	if err != nil {
		panic(err)
	}

	bn, err := boring.NewBigNum().SetBytes(buf)
	if err != nil {
		panic(err)
	}
	bn, err = bn.MaskBits(n)
	if err != nil {
		panic(err)
	}

	return (*natImpl.BnNatImpl)(bn)
}

func (b *BnNatsImpl) NewPrime(bits uint, _ io.Reader) nat.Nat {
	bn, err := boring.NewBigNum().GenPrime(int(bits), false)
	if err != nil {
		panic(err)
	}

	return (*natImpl.BnNatImpl)(bn)
}

func (b *BnNatsImpl) NewSafePrime(bits uint, _ io.Reader) nat.Nat {
	group, err := boring.NewDiffieHellmanGroup()
	if err != nil {
		panic(err)
	}
	group, err = group.GenerateParameters(int(bits))
	if err != nil {
		panic(err)
	}
	p, err := group.GetP()
	if err != nil {
		panic(err)
	}

	return (*natImpl.BnNatImpl)(p)
}

func (b *BnNatsImpl) NewFromBytes(bytes []byte) nat.Nat {
	bn, err := boring.NewBigNum().SetBytes(bytes)
	if err != nil {
		panic(err)
	}

	return (*natImpl.BnNatImpl)(bn)
}
