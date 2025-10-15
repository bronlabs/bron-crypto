package znstar

import (
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/modular"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/fxamacker/cbor/v2"
)

var (
	_ cbor.Marshaler   = (*UnitTrait)(nil)
	_ cbor.Unmarshaler = (*UnitTrait)(nil)
	_ cbor.Marshaler   = (*UnitKnownOrderTrait[*modular.OddPrimeFactors])(nil)
	_ cbor.Unmarshaler = (*UnitKnownOrderTrait[*modular.OddPrimeFactors])(nil)
	_ cbor.Marshaler   = (*UnitKnownOrderTrait[*modular.OddPrimeSquareFactors])(nil)
	_ cbor.Unmarshaler = (*UnitKnownOrderTrait[*modular.OddPrimeSquareFactors])(nil)
	_ cbor.Marshaler   = (*UnitGroupKnownOrderTrait[*modular.SimpleModulus])(nil)
	_ cbor.Unmarshaler = (*UnitGroupKnownOrderTrait[*modular.SimpleModulus])(nil)
	_ cbor.Marshaler   = (*UnitGroupKnownOrderTrait[*modular.OddPrimeFactors])(nil)
	_ cbor.Unmarshaler = (*UnitGroupKnownOrderTrait[*modular.OddPrimeFactors])(nil)
	_ cbor.Marshaler   = (*UnitGroupKnownOrderTrait[*modular.OddPrimeSquareFactors])(nil)
	_ cbor.Unmarshaler = (*UnitGroupKnownOrderTrait[*modular.OddPrimeSquareFactors])(nil)
	_ cbor.Marshaler   = (*UnitGroupTrait)(nil)
	_ cbor.Unmarshaler = (*UnitGroupTrait)(nil)
	_ cbor.Marshaler   = (*rsaGroup)(nil)
	_ cbor.Unmarshaler = (*rsaGroup)(nil)
	_ cbor.Marshaler   = (*rsaGroupKnownOrder)(nil)
	_ cbor.Unmarshaler = (*rsaGroupKnownOrder)(nil)
	_ cbor.Marshaler   = (*paillierGroup)(nil)
	_ cbor.Unmarshaler = (*paillierGroup)(nil)
	_ cbor.Marshaler   = (*paillierGroupKnownOrder)(nil)
	_ cbor.Unmarshaler = (*paillierGroupKnownOrder)(nil)
)

const (
	UnitTag                    = 5010
	UnitKnownOrderRSATag       = 5011
	UnitKnownOrderPaillierTag  = 5019
	UZModSimpleTag             = 5012
	UZModOddPrimeTag           = 5013
	UZModOddPrimeSquareTag     = 5014
	PaillierGroupTag           = 5015
	PaillierGroupKnownOrderTag = 5016
	RSAGroupTag                = 5017
	RSAGroupKnownOrderTag      = 5018
)

func init() {
	// Register unit types for both known and unknown order
	serde.Register[*UnitTrait](UnitTag)
	serde.Register[*UnitKnownOrderTrait[*modular.OddPrimeFactors]](UnitKnownOrderRSATag)
	serde.Register[*UnitKnownOrderTrait[*modular.OddPrimeSquareFactors]](UnitKnownOrderPaillierTag)
	// Register group types
	serde.Register[*UnitGroupTrait](RSAGroupTag)
	serde.Register[*UnitGroupKnownOrderTrait[*modular.SimpleModulus]](UZModSimpleTag)
	serde.Register[*UnitGroupKnownOrderTrait[*modular.OddPrimeFactors]](UZModOddPrimeTag)
	serde.Register[*UnitGroupKnownOrderTrait[*modular.OddPrimeSquareFactors]](UZModOddPrimeSquareTag)
	serde.Register[*paillierGroup](PaillierGroupTag)
	serde.Register[*paillierGroupKnownOrder](PaillierGroupKnownOrderTag)
	serde.Register[*rsaGroupKnownOrder](RSAGroupKnownOrderTag)
}

// MarshalCBOR/UnmarshalCBOR for unitKnownOrder - handles generic known-order units
func (u *UnitKnownOrderTrait[X]) MarshalCBOR() ([]byte, error) {
	// Choose tag based on the arithmetic type
	var tag uint64
	switch any(u.g.Arithmetic()).(type) {
	case *modular.OddPrimeFactors:
		tag = UnitKnownOrderRSATag
	case *modular.OddPrimeSquareFactors:
		tag = UnitKnownOrderPaillierTag
	default:
		return nil, errs.NewValue("unsupported arithmetic type for unitKnownOrder")
	}
	dto := &unitDTOKnownOrder{V: u.v, X: u.g.Arithmetic()}
	return serde.MarshalCBORTagged(dto, tag)
}

func (u *UnitKnownOrderTrait[X]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[unitDTOKnownOrder](data)
	if err != nil {
		return err
	}
	u.v = dto.V

	// Type assertion to get the arithmetic with correct type
	arith, ok := dto.X.(X)
	if !ok {
		return errs.NewType("decoded arithmetic doesn't match unit type parameter")
	}

	// Create group from arithmetic
	group, err := NewUnitGroup(arith)
	if err != nil {
		return err
	}

	// Type assert to get the group with Arithmetic() method
	if g, ok := group.(interface {
		UnitGroup
		Arithmetic() X
	}); ok {
		u.g = g
	} else {
		return errs.NewType("group doesn't match expected type")
	}

	return nil
}

type unitDTO struct {
	V   *numct.Nat    `cbor:"value"`
	Mod numct.Modulus `cbor:"modulus"`
}

type unitDTOKnownOrder struct {
	V *numct.Nat         `cbor:"value"`
	X modular.Arithmetic `cbor:"group"`
}

// MarshalCBOR/UnmarshalCBOR for unit - handles unknown-order units only
func (u *UnitTrait) MarshalCBOR() ([]byte, error) {
	dto := &unitDTO{V: u.v, Mod: u.g.ModulusCT()}
	return serde.MarshalCBORTagged(dto, UnitTag)
}

func (u *UnitTrait) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[unitDTO](data)
	if err != nil {
		return err
	}
	u.v = dto.V
	uzmod, err := NewUnitGroupOfUnknownOrder(num.NPlus().FromModulus(dto.Mod))
	if err != nil {
		return err
	}
	u.g = uzmod.(*uZMod)
	return nil
}

type uZModDTO struct {
	Arith modular.Arithmetic `cbor:"arithmetic"`
}

type uZModDTOUnknown struct {
	Mod numct.Modulus `cbor:"modulus"`
}

func (us *UnitGroupKnownOrderTrait[X]) MarshalCBOR() ([]byte, error) {
	// Choose tag based on the concrete instantiation of uZModKnownOrder[X].
	var tag uint64
	switch any(us).(type) {
	case *UnitGroupKnownOrderTrait[*modular.SimpleModulus]:
		tag = UZModSimpleTag
	case *UnitGroupKnownOrderTrait[*modular.OddPrimeFactors]:
		tag = UZModOddPrimeTag
	case *UnitGroupKnownOrderTrait[*modular.OddPrimeSquareFactors]:
		tag = UZModOddPrimeSquareTag
	default:
		return nil, errs.NewValue("unsupported uZModKnownOrder specialization in MarshalCBOR")
	}

	// Serialize the arithmetic object (carries modulus and factors/order)
	dto := &uZModDTO{Arith: us.arith}
	return serde.MarshalCBORTagged(dto, tag)
}

func (us *UnitGroupKnownOrderTrait[X]) UnmarshalCBOR(data []byte) error {
	// When called by serde, the tag has already been stripped
	// Try to unmarshal as known-order first (has arithmetic field)
	kdto, err := serde.UnmarshalCBOR[uZModDTO](data)
	if err == nil && kdto.Arith != nil {
		// Known-order path
		z, err := num.NewZModFromModulus(kdto.Arith.Modulus())
		if err != nil {
			return errs.WrapFailed(err, "failed to construct ZMod from arithmetic modulus")
		}
		us.zMod = z
		// Type assertion is safe because we're inside the correct generic monomorphization.
		if arith, ok := any(kdto.Arith).(X); ok {
			us.arith = arith
		} else {
			return errs.NewType("decoded arithmetic doesn't match UZMod type parameter")
		}
		return nil
	}

	// Try to unmarshal as unknown-order (has modulus field)
	udto, err := serde.UnmarshalCBOR[uZModDTOUnknown](data)
	if err != nil {
		return errs.WrapSerialisation(err, "couldn't unmarshal UZMod as known or unknown order")
	}
	// Unknown-order path
	z, err := num.NewZModFromModulus(udto.Mod)
	if err != nil {
		return errs.WrapFailed(err, "failed to construct ZMod from modulus")
	}
	us.zMod = z
	// arith remains nil/zero for unknown order
	return nil
}

// Group serialization DTOs and methods

type paillierGroupDTO struct {
	Arith modular.Arithmetic `cbor:"arithmetic,omitempty"` // nil for unknown order
	Mod   numct.Modulus      `cbor:"modulus,omitempty"`    // for unknown order
	N     *num.NatPlus       `cbor:"n"`
}

func (pg *paillierGroup) MarshalCBOR() ([]byte, error) {
	dto := &paillierGroupDTO{N: pg.n}
	if !utils.IsNil(pg.arith) {
		dto.Arith = pg.arith
	} else {
		dto.Mod = pg.ModulusCT()
	}
	return serde.MarshalCBORTagged(dto, PaillierGroupTag)
}

func (pg *paillierGroup) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[paillierGroupDTO](data)
	if err != nil {
		return err
	}
	pg.n = dto.N

	if dto.Arith != nil {
		// Known order path
		arith, ok := dto.Arith.(*modular.OddPrimeSquareFactors)
		if !ok {
			return errs.NewType("arithmetic is not OddPrimeSquareFactors")
		}
		z, err := num.NewZModFromModulus(arith.Modulus())
		if err != nil {
			return err
		}
		pg.zMod = z
		pg.arith = arith
	} else {
		// Unknown order path
		z, err := num.NewZModFromModulus(dto.Mod)
		if err != nil {
			return err
		}
		pg.zMod = z
		// arith remains nil
	}
	return nil
}

func (pg *paillierGroupKnownOrder) MarshalCBOR() ([]byte, error) {
	dto := &paillierGroupDTO{
		Arith: pg.arith,
		N:     pg.n,
	}
	return serde.MarshalCBORTagged(dto, PaillierGroupKnownOrderTag)
}

func (pg *paillierGroupKnownOrder) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[paillierGroupDTO](data)
	if err != nil {
		return err
	}
	pg.n = dto.N

	arith, ok := dto.Arith.(*modular.OddPrimeSquareFactors)
	if !ok {
		return errs.NewType("arithmetic is not OddPrimeSquareFactors")
	}
	z, err := num.NewZModFromModulus(arith.Modulus())
	if err != nil {
		return err
	}
	pg.zMod = z
	pg.arith = arith
	return nil
}

// MarshalCBOR/UnmarshalCBOR for uZMod - handles unknown-order groups
func (us *UnitGroupTrait) MarshalCBOR() ([]byte, error) {
	dto := &uZModDTOUnknown{Mod: us.zMod.Modulus().ModulusCT()}
	return serde.MarshalCBORTagged(dto, RSAGroupTag)
}

func (us *UnitGroupTrait) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[uZModDTOUnknown](data)
	if err != nil {
		return err
	}
	z, err := num.NewZModFromModulus(dto.Mod)
	if err != nil {
		return errs.WrapFailed(err, "failed to construct ZMod from modulus")
	}
	us.zMod = z
	return nil
}

// rsaGroup serialization - delegates to embedded uZMod but preserves rsaGroup type
func (rg *rsaGroup) MarshalCBOR() ([]byte, error) {
	// rsaGroup is just a wrapper around uZMod, serialize the embedded uZMod
	return rg.UnitGroupTrait.MarshalCBOR()
}

func (rg *rsaGroup) UnmarshalCBOR(data []byte) error {
	// Deserialize into the embedded uZMod
	return rg.UnitGroupTrait.UnmarshalCBOR(data)
}

type rsaGroupDTO struct {
	UZMod *UnitGroupKnownOrderTrait[*modular.OddPrimeFactors] `cbor:"uzmod"`
}

func (rg *rsaGroupKnownOrder) MarshalCBOR() ([]byte, error) {
	dto := &rsaGroupDTO{
		UZMod: &rg.UnitGroupKnownOrderTrait,
	}
	return serde.MarshalCBORTagged(dto, RSAGroupKnownOrderTag)
}

func (rg *rsaGroupKnownOrder) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[rsaGroupDTO](data)
	if err != nil {
		return err
	}
	rg.UnitGroupKnownOrderTrait = *dto.UZMod
	return nil
}
