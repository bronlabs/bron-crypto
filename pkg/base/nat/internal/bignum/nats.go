//go:build !purego && !nobignum

package bignum

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/nat"
	"github.com/copperexchange/krypton-primitives/pkg/cgo/boring"
	"io"
)

type BnNats struct{}

var _ nat.Nats = (*BnNats)(nil)

func (b *BnNats) NewModulus(m nat.Nat) nat.Modulus {
	bn := (*boring.BigNum)(m.(*BnNat))
	bnClone, err := bn.Copy()
	if err != nil {
		panic(err)
	}

	ctx := boring.NewBigNumCtx()
	montCtx, err := boring.NewBigNumMontCtx(bnClone, ctx)
	if err != nil {
		panic(err)
	}

	return &BnMod{
		montCtx: montCtx,
		bigNum:  bnClone,
	}
}

func (b *BnNats) New() nat.Nat {
	return (*BnNat)(boring.NewBigNum())
}

func (b *BnNats) Zero() nat.Nat {
	return (*BnNat)(boring.Zero)
}

func (b *BnNats) One() nat.Nat {
	return (*BnNat)(boring.One)
}

func (b *BnNats) NewUint64(val uint64) nat.Nat {
	u64, err := boring.NewBigNum().SetU64(val)
	if err != nil {
		panic(err)
	}

	return (*BnNat)(u64)
}

func (b *BnNats) NewRandomN(n nat.Nat, _ io.Reader) nat.Nat {
	//TODO implement me
	panic("implement me")
}

func (b *BnNats) NewRandomBits(n uint, prng io.Reader) nat.Nat {
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

	return (*BnNat)(bn)
}

func (b *BnNats) NewPrime(bits uint, _ io.Reader) nat.Nat {
	bn, err := boring.NewBigNum().GenPrime(int(bits), false)
	if err != nil {
		panic(err)
	}

	return (*BnNat)(bn)
}

func (b *BnNats) NewSafePrime(bits uint, _ io.Reader) nat.Nat {
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

	return (*BnNat)(p)
}

func (b *BnNats) NewFromBytes(bytes []byte) nat.Nat {
	bn, err := boring.NewBigNum().SetBytes(bytes)
	if err != nil {
		panic(err)
	}

	return (*BnNat)(bn)
}
