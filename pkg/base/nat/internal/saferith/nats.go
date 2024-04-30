package saferith

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/nat"
	"github.com/cronokirby/saferith"
	"io"
)

type SNats struct{}

var _ nat.Nats = (*SNats)(nil)

var (
	zero nat.Nat = (*SNat)(new(saferith.Nat).SetUint64(0).Resize(0))
	one  nat.Nat = (*SNat)(new(saferith.Nat).SetUint64(1).Resize(1))
)

func (s *SNats) New() nat.Nat {
	return (*SNat)(new(saferith.Nat))
}

func (s *SNats) Zero() nat.Nat {
	return zero
}

func (s *SNats) One() nat.Nat {
	return one
}

func (s *SNats) NewModulus(modulus nat.Nat) nat.Modulus {
	m := (*saferith.Nat)(modulus.(*SNat))
	mod := saferith.ModulusFromNat(m)
	return (*SMod)(mod)
}

func (s *SNats) NewUint64(val uint64) nat.Nat {
	return (*SNat)(new(saferith.Nat).SetUint64(val))
}

func (s *SNats) NewRandomN(n nat.Nat, prng io.Reader) nat.Nat {
	//TODO implement me
	panic("implement me")
}

func (s *SNats) NewRandomBits(n uint, prng io.Reader) nat.Nat {
	bytesLen := int((n + 7) / 8)
	buf := make([]byte, bytesLen)
	_, err := io.ReadFull(prng, buf)
	if err != nil {
		panic(err)
	}

	return s.New()
}

func (s *SNats) NewFromBytes(bytes []byte) nat.Nat {
	r := new(saferith.Nat).SetBytes(bytes)
	return (*SNat)(r)
}

func (s *SNats) NewPrime(bits uint, prng io.Reader) nat.Nat {
	//TODO implement me
	panic("implement me")
}

func (s *SNats) NewSafePrime(bits uint, prng io.Reader) nat.Nat {
	//TODO implement me
	panic("implement me")
}
