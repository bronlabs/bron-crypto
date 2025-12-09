package znstar

import (
	"github.com/bronlabs/bron-crypto/pkg/base/nt/modular"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/fxamacker/cbor/v2"
)

var (
	_ cbor.Marshaler   = (*RSAGroupKnownOrder)(nil)
	_ cbor.Unmarshaler = (*RSAGroupKnownOrder)(nil)

	_ cbor.Marshaler   = (*RSAGroupElementKnownOrder)(nil)
	_ cbor.Unmarshaler = (*RSAGroupElementKnownOrder)(nil)

	_ cbor.Marshaler   = (*RSAGroupUnknownOrder)(nil)
	_ cbor.Unmarshaler = (*RSAGroupUnknownOrder)(nil)

	_ cbor.Marshaler   = (*RSAGroupElementUnknownOrder)(nil)
	_ cbor.Unmarshaler = (*RSAGroupElementUnknownOrder)(nil)

	_ cbor.Marshaler   = (*PaillierGroupKnownOrder)(nil)
	_ cbor.Unmarshaler = (*PaillierGroupKnownOrder)(nil)

	_ cbor.Marshaler   = (*PaillierGroupElementKnownOrder)(nil)
	_ cbor.Unmarshaler = (*PaillierGroupElementKnownOrder)(nil)

	_ cbor.Marshaler   = (*PaillierGroupUnknownOrder)(nil)
	_ cbor.Unmarshaler = (*PaillierGroupUnknownOrder)(nil)

	_ cbor.Marshaler   = (*PaillierGroupElementUnknownOrder)(nil)
	_ cbor.Unmarshaler = (*PaillierGroupElementUnknownOrder)(nil)
)

const (
	RSAGroupKnownOrderTag = 5010 + iota
	RSAGroupKnownOrderElementTag
	RSAGroupUnknownOrderTag
	RSAGroupUnknownOrderElementTag
	PaillierGroupKnownOrderTag
	PaillierGroupKnownOrderElementTag
	PaillierGroupUnknownOrderTag
	PaillierGroupUnknownOrderElementTag
)

func init() {
	serde.Register[*RSAGroupKnownOrder](RSAGroupKnownOrderTag)
	serde.Register[*RSAGroupElementKnownOrder](RSAGroupKnownOrderElementTag)
	serde.Register[*RSAGroupUnknownOrder](RSAGroupUnknownOrderTag)
	serde.Register[*RSAGroupElementUnknownOrder](RSAGroupUnknownOrderElementTag)
	serde.Register[*PaillierGroupKnownOrder](PaillierGroupKnownOrderTag)
	serde.Register[*PaillierGroupElementKnownOrder](PaillierGroupKnownOrderElementTag)
	serde.Register[*PaillierGroupUnknownOrder](PaillierGroupUnknownOrderTag)
	serde.Register[*PaillierGroupElementUnknownOrder](PaillierGroupUnknownOrderElementTag)
}

type rsaGroupKnownOrderDTO struct {
	P *num.NatPlus `cbor:"p"`
	Q *num.NatPlus `cbor:"q"`
}

type rsaGroupUnknownOrderDTO struct {
	Modulus *num.NatPlus `cbor:"modulus"`
}

type rsaGroupUnknownOrderElementDTO struct {
	V          *num.Uint              `cbor:"v"`
	Arithmetic *modular.SimpleModulus `cbor:"arithmetic"`
}

type rsaGroupKnownOrderElementDTO struct {
	V          *num.Uint                `cbor:"v"`
	Arithmetic *modular.OddPrimeFactors `cbor:"arithmetic"`
}

type paillierGroupKnownOrderDTO struct {
	P *num.NatPlus `cbor:"p"`
	Q *num.NatPlus `cbor:"q"`
}

type paillierGroupUnknownOrderDTO struct {
	N *num.NatPlus `cbor:"n"`
}

type paillierGroupKnownOrderElementDTO struct {
	V          *num.Uint                      `cbor:"v"`
	Arithmetic *modular.OddPrimeSquareFactors `cbor:"arithmetic"`
}

type paillierGroupUnknownOrderElementDTO struct {
	V          *num.Uint              `cbor:"v"`
	Arithmetic *modular.SimpleModulus `cbor:"arithmetic"`
	N          *num.NatPlus           `cbor:"n"`
}

// ========== CBOR Serialization ==========

func (pg *PaillierGroup[X]) MarshalCBOR() ([]byte, error) {
	var tag uint64
	switch any(pg.arith).(type) {
	case *modular.OddPrimeSquareFactors:
		tag = PaillierGroupKnownOrderTag
		dto := &paillierGroupKnownOrderDTO{
			P: num.NPlus().FromModulusCT(any(pg.arith).(*modular.OddPrimeSquareFactors).P.Factor),
			Q: num.NPlus().FromModulusCT(any(pg.arith).(*modular.OddPrimeSquareFactors).Q.Factor),
		}
		return serde.MarshalCBORTagged(dto, tag)
	case *modular.SimpleModulus:
		tag = PaillierGroupUnknownOrderTag
		dto := &paillierGroupUnknownOrderDTO{
			N: pg.n,
		}
		return serde.MarshalCBORTagged(dto, tag)
	default:
		panic("unknown arithmetic type for PaillierGroup")
	}
}

func (pg *PaillierGroup[X]) UnmarshalCBOR(data []byte) error {
	switch any(pg.arith).(type) {
	case *modular.OddPrimeSquareFactors:
		dto, err := serde.UnmarshalCBOR[paillierGroupKnownOrderDTO](data)
		if err != nil {
			return err
		}
		reconstructed, err := NewPaillierGroup(dto.P, dto.Q)
		if err != nil {
			return err
		}
		*pg = *any(reconstructed).(*PaillierGroup[X])
		return nil
	case *modular.SimpleModulus:
		dto, err := serde.UnmarshalCBOR[paillierGroupUnknownOrderDTO](data)
		if err != nil {
			return err
		}
		n2 := dto.N.Square()
		reconstructed, err := NewPaillierGroupOfUnknownOrder(n2, dto.N)
		if err != nil {
			return err
		}
		*pg = *any(reconstructed).(*PaillierGroup[X])
		return nil
	default:
		panic("unknown arithmetic type in UnmarshalCBOR")
	}
}

func (u *PaillierGroupElement[X]) MarshalCBOR() ([]byte, error) {
	var tag uint64
	switch any(u.arith).(type) {
	case *modular.OddPrimeSquareFactors:
		tag = PaillierGroupKnownOrderElementTag
		dto := &paillierGroupKnownOrderElementDTO{
			V:          u.v,
			Arithmetic: any(u.arith).(*modular.OddPrimeSquareFactors),
		}
		return serde.MarshalCBORTagged(dto, tag)
	case *modular.SimpleModulus:
		tag = PaillierGroupUnknownOrderElementTag
		dto := &paillierGroupUnknownOrderElementDTO{
			V:          u.v,
			Arithmetic: any(u.arith).(*modular.SimpleModulus),
			N:          u.n,
		}
		return serde.MarshalCBORTagged(dto, tag)
	default:
		panic("unknown arithmetic type for PaillierGroupElement")
	}
}

func (u *PaillierGroupElement[X]) UnmarshalCBOR(data []byte) error {
	switch any(u.arith).(type) {
	case *modular.OddPrimeSquareFactors:
		dto, err := serde.UnmarshalCBOR[paillierGroupKnownOrderElementDTO](data)
		if err != nil {
			return err
		}
		p := num.NPlus().FromModulusCT(dto.Arithmetic.P.Factor)
		q := num.NPlus().FromModulusCT(dto.Arithmetic.Q.Factor)
		g, err := NewPaillierGroup(p, q)
		if err != nil {
			return err
		}
		elem, err := g.FromUint(dto.V)
		if err != nil {
			return err
		}
		*u = *any(elem).(*PaillierGroupElement[X])
		return nil
	case *modular.SimpleModulus:
		dto, err := serde.UnmarshalCBOR[paillierGroupUnknownOrderElementDTO](data)
		if err != nil {
			return err
		}
		n2 := dto.N.Square()
		g, err := NewPaillierGroupOfUnknownOrder(n2, dto.N)
		if err != nil {
			return err
		}
		elem, err := g.FromUint(dto.V)
		if err != nil {
			return err
		}
		*u = *any(elem).(*PaillierGroupElement[X])
		return nil
	default:
		// For initial unmarshal when arith is zero value, try both
		if dtoKnown, err := serde.UnmarshalCBOR[paillierGroupKnownOrderElementDTO](data); err == nil {
			p := num.NPlus().FromModulusCT(dtoKnown.Arithmetic.P.Factor)
			q := num.NPlus().FromModulusCT(dtoKnown.Arithmetic.Q.Factor)
			g, err := NewPaillierGroup(p, q)
			if err != nil {
				return err
			}
			elem, err := g.FromUint(dtoKnown.V)
			if err != nil {
				return err
			}
			*u = *any(elem).(*PaillierGroupElement[X])
			return nil
		}
		dto, err := serde.UnmarshalCBOR[paillierGroupUnknownOrderElementDTO](data)
		if err != nil {
			return err
		}
		n2 := dto.N.Square()
		g, err := NewPaillierGroupOfUnknownOrder(n2, dto.N)
		if err != nil {
			return err
		}
		elem, err := g.FromUint(dto.V)
		if err != nil {
			return err
		}
		*u = *any(elem).(*PaillierGroupElement[X])
		return nil
	}
}

func (rg *RSAGroup[X]) MarshalCBOR() ([]byte, error) {
	// Determine tag based on arithmetic type
	var tag uint64
	switch any(rg.arith).(type) {
	case *modular.OddPrimeFactors:
		tag = RSAGroupKnownOrderTag
		dto := &rsaGroupKnownOrderDTO{
			P: num.NPlus().FromModulusCT(any(rg.arith).(*modular.OddPrimeFactors).Params.P),
			Q: num.NPlus().FromModulusCT(any(rg.arith).(*modular.OddPrimeFactors).Params.Q),
		}
		return serde.MarshalCBORTagged(dto, tag)
	case *modular.SimpleModulus:
		tag = RSAGroupUnknownOrderTag
		dto := &rsaGroupUnknownOrderDTO{
			Modulus: rg.Modulus(),
		}
		return serde.MarshalCBORTagged(dto, tag)
	default:
		panic("unknown arithmetic type for RSAGroup")
	}
}

func (rg *RSAGroup[X]) UnmarshalCBOR(data []byte) error {
	// Determine which type based on X
	switch any(rg.arith).(type) {
	case *modular.OddPrimeFactors:
		dto, err := serde.UnmarshalCBOR[rsaGroupKnownOrderDTO](data)
		if err != nil {
			return err
		}
		reconstructed, err := NewRSAGroup(dto.P, dto.Q)
		if err != nil {
			return err
		}
		*rg = *any(reconstructed).(*RSAGroup[X])
		return nil
	case *modular.SimpleModulus:
		dto, err := serde.UnmarshalCBOR[rsaGroupUnknownOrderDTO](data)
		if err != nil {
			return err
		}
		reconstructed, err := NewRSAGroupOfUnknownOrder(dto.Modulus)
		if err != nil {
			return err
		}
		*rg = *any(reconstructed).(*RSAGroup[X])
		return nil
	default:
		panic("unknown arithmetic type in UnmarshalCBOR")
	}
}

func (u *RSAGroupElement[X]) MarshalCBOR() ([]byte, error) {
	var tag uint64
	switch any(u.arith).(type) {
	case *modular.OddPrimeFactors:
		tag = RSAGroupKnownOrderElementTag
		dto := &rsaGroupKnownOrderElementDTO{
			V:          u.v,
			Arithmetic: any(u.arith).(*modular.OddPrimeFactors),
		}
		return serde.MarshalCBORTagged(dto, tag)
	case *modular.SimpleModulus:
		tag = RSAGroupUnknownOrderElementTag
		dto := &rsaGroupUnknownOrderElementDTO{
			V:          u.v,
			Arithmetic: any(u.arith).(*modular.SimpleModulus),
		}
		return serde.MarshalCBORTagged(dto, tag)
	default:
		panic("unknown arithmetic type for RSAGroupElement")
	}
}

func (u *RSAGroupElement[X]) UnmarshalCBOR(data []byte) error {
	switch any(u.arith).(type) {
	case *modular.OddPrimeFactors:
		dto, err := serde.UnmarshalCBOR[rsaGroupKnownOrderElementDTO](data)
		if err != nil {
			return err
		}
		p := num.NPlus().FromModulusCT(dto.Arithmetic.Params.P)
		q := num.NPlus().FromModulusCT(dto.Arithmetic.Params.Q)
		g, err := NewRSAGroup(p, q)
		if err != nil {
			return err
		}
		elem, err := g.FromUint(dto.V)
		if err != nil {
			return err
		}
		*u = *any(elem).(*RSAGroupElement[X])
		return nil
	case *modular.SimpleModulus:
		dto, err := serde.UnmarshalCBOR[rsaGroupUnknownOrderElementDTO](data)
		if err != nil {
			return err
		}
		g, err := NewRSAGroupOfUnknownOrder(dto.V.Modulus())
		if err != nil {
			return err
		}
		elem, err := g.FromUint(dto.V)
		if err != nil {
			return err
		}
		*u = *any(elem).(*RSAGroupElement[X])
		return nil
	default:
		// For initial unmarshal when arith is zero value, try both
		if dtoKnown, err := serde.UnmarshalCBOR[rsaGroupKnownOrderElementDTO](data); err == nil {
			p := num.NPlus().FromModulusCT(dtoKnown.Arithmetic.Params.P)
			q := num.NPlus().FromModulusCT(dtoKnown.Arithmetic.Params.Q)
			g, err := NewRSAGroup(p, q)
			if err != nil {
				return err
			}
			elem, err := g.FromUint(dtoKnown.V)
			if err != nil {
				return err
			}
			*u = *any(elem).(*RSAGroupElement[X])
			return nil
		}
		dto, err := serde.UnmarshalCBOR[rsaGroupUnknownOrderElementDTO](data)
		if err != nil {
			return err
		}
		g, err := NewRSAGroupOfUnknownOrder(dto.V.Modulus())
		if err != nil {
			return err
		}
		elem, err := g.FromUint(dto.V)
		if err != nil {
			return err
		}
		*u = *any(elem).(*RSAGroupElement[X])
		return nil
	}
}
