package nats

import (
	natImpl "github.com/copperexchange/krypton-primitives/pkg/base/bignat/internal/saferith/nat"
	"github.com/copperexchange/krypton-primitives/pkg/base/bignat/nat"
	"github.com/cronokirby/saferith"
	"io"
	"math/big"
	"sync"
)

type SnatsImpl struct{}

var (
	snats     *SnatsImpl
	snatsOnce sync.Once
	zero      nat.Nat = (*natImpl.SnatImpl)(new(saferith.Nat).SetUint64(0).Resize(0))
	one       nat.Nat = (*natImpl.SnatImpl)(new(saferith.Nat).SetUint64(1).Resize(1))
)

func NewNats() *SnatsImpl {
	snatsOnce.Do(func() {
		snats = &SnatsImpl{}
	})
	return snats
}

func (s *SnatsImpl) New() nat.Nat {
	return (*natImpl.SnatImpl)(new(saferith.Nat))
}

func (s *SnatsImpl) Zero() nat.Nat {
	return zero
}

func (s *SnatsImpl) One() nat.Nat {
	return one
}

func (s *SnatsImpl) NewBig(b *big.Int) nat.Nat {
	return (*natImpl.SnatImpl)(new(saferith.Nat).SetBig(b, b.BitLen()))
}

func (s *SnatsImpl) NewModulus(modulus nat.Nat) nat.Modulus {
	m := (*saferith.Nat)(modulus.(*natImpl.SnatImpl))
	mod := saferith.ModulusFromNat(m)
	return (*natImpl.SmodImpl)(mod)
}

func (s *SnatsImpl) NewUint64(val uint64) nat.Nat {
	return (*natImpl.SnatImpl)(new(saferith.Nat).SetUint64(val))
}

func (s *SnatsImpl) NewRandomN(n nat.Nat, prng io.Reader) nat.Nat {
	//TODO implement me
	panic("implement me")
}

func (s *SnatsImpl) NewRandomBits(n uint, prng io.Reader) nat.Nat {
	bytesLen := int((n + 7) / 8)
	buf := make([]byte, bytesLen)
	_, err := io.ReadFull(prng, buf)
	if err != nil {
		panic(err)
	}

	return s.NewFromBytes(buf)
}

func (s *SnatsImpl) NewFromBytes(bytes []byte) nat.Nat {
	r := new(saferith.Nat).SetBytes(bytes)
	return (*natImpl.SnatImpl)(r)
}

func (s *SnatsImpl) NewPrime(bits uint, prng io.Reader) nat.Nat {
	//TODO implement me
	panic("implement me")
}

func (s *SnatsImpl) NewSafePrime(bits uint, prng io.Reader) nat.Nat {
	//TODO implement me
	panic("implement me")
}
