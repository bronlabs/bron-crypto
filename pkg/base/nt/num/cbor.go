package num

import (
	"github.com/fxamacker/cbor/v2"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
)

var (
	_ cbor.Marshaler   = (*NatPlus)(nil)
	_ cbor.Unmarshaler = (*NatPlus)(nil)
	_ cbor.Marshaler   = (*Nat)(nil)
	_ cbor.Unmarshaler = (*Nat)(nil)
	_ cbor.Marshaler   = (*Int)(nil)
	_ cbor.Unmarshaler = (*Int)(nil)
	_ cbor.Marshaler   = (*Uint)(nil)
	_ cbor.Unmarshaler = (*Uint)(nil)
	_ cbor.Marshaler   = (*Rat)(nil)
	_ cbor.Unmarshaler = (*Rat)(nil)

	_ cbor.Marshaler   = (*ZMod)(nil)
	_ cbor.Unmarshaler = (*ZMod)(nil)
)

type natPlusDTO struct {
	NatPlus *numct.Nat `cbor:"natPlus"`
}

func (np *NatPlus) MarshalCBOR() ([]byte, error) {
	dto := &natPlusDTO{NatPlus: np.v}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs2.Wrap(err)
	}
	return data, nil
}

func (np *NatPlus) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*natPlusDTO](data)
	if err != nil {
		return err
	}
	if dto.NatPlus.IsZero() == ct.True {
		return ErrOutOfRange.WithStackFrame().WithMessage("NatPlus must be greater than 0")
	}
	np.v = dto.NatPlus
	return nil
}

type natDTO struct {
	Nat *numct.Nat `cbor:"nat"`
}

func (n *Nat) MarshalCBOR() ([]byte, error) {
	dto := &natDTO{Nat: n.v}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs2.Wrap(err)
	}
	return data, nil
}

func (n *Nat) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*natDTO](data)
	if err != nil {
		return err
	}
	n.v = dto.Nat
	return nil
}

type intDTO struct {
	Int *numct.Int `cbor:"int"`
}

func (i *Int) MarshalCBOR() ([]byte, error) {
	dto := &intDTO{Int: i.v}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs2.Wrap(err)
	}
	return data, nil
}

func (i *Int) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*intDTO](data)
	if err != nil {
		return err
	}
	i.v = dto.Int
	return nil
}

type uintDTO struct {
	Value   *numct.Nat     `cbor:"value"`
	Modulus *numct.Modulus `cbor:"modulus"`
}

func (u *Uint) MarshalCBOR() ([]byte, error) {
	dto := &uintDTO{
		Value:   u.v,
		Modulus: u.m,
	}
	out, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs2.Wrap(err)
	}
	return out, nil
}

func (u *Uint) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*uintDTO](data)
	if err != nil {
		return err
	}
	if dto.Modulus == nil {
		return ErrIsNil.WithStackFrame().WithMessage("modulus bytes")
	}
	if dto.Value == nil {
		return ErrIsNil.WithStackFrame().WithMessage("value")
	}

	// Deserialize the modulus interface directly - tags handle type preservation
	if lt, _, _ := dto.Value.Compare(dto.Modulus.Nat()); lt == ct.False {
		return ErrOutOfRange.WithStackFrame().WithMessage("value must be in [0, modulus)")
	}
	u.v = dto.Value
	u.m = dto.Modulus
	return nil
}

type ratDTO struct {
	A *Int     `cbor:"a"`
	B *NatPlus `cbor:"b"`
}

func (r *Rat) MarshalCBOR() ([]byte, error) {
	dto := &ratDTO{
		A: r.a,
		B: r.b,
	}
	out, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs2.Wrap(err)
	}
	return out, nil
}

func (r *Rat) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*ratDTO](data)
	if err != nil {
		return errs2.Wrap(err)
	}
	if dto.A == nil {
		return ErrIsNil.WithStackFrame().WithMessage("numerator")
	}
	if dto.B == nil {
		return ErrIsNil.WithStackFrame().WithMessage("denominator")
	}
	r.a = dto.A
	r.b = dto.B
	return nil
}

type zmodDTO struct {
	Modulus *NatPlus `cbor:"modulus"`
}

func (z *ZMod) MarshalCBOR() ([]byte, error) {
	dto := &zmodDTO{Modulus: z.n}
	out, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs2.Wrap(err)
	}
	return out, nil
}

func (z *ZMod) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*zmodDTO](data)
	if err != nil {
		return err
	}
	if dto.Modulus == nil {
		return ErrIsNil.WithStackFrame().WithMessage("modulus")
	}
	z.n = dto.Modulus
	return nil
}
