package znstar

import (
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/modular"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/fxamacker/cbor/v2"
)

// Wrapper types for unit to support dual-tag registration
// These wrappers allow us to register different CBOR tags for the same underlying type
// Both will unmarshal to the Unit interface
type unitUnknownOrder struct {
	*unit
}

type unitKnownOrder struct {
	*unit
}

var (
	_ cbor.Marshaler   = (*unit)(nil)
	_ cbor.Unmarshaler = (*unit)(nil)
	_ cbor.Marshaler   = (*unitUnknownOrder)(nil)
	_ cbor.Unmarshaler = (*unitUnknownOrder)(nil)
	_ cbor.Marshaler   = (*unitKnownOrder)(nil)
	_ cbor.Unmarshaler = (*unitKnownOrder)(nil)
	_ cbor.Marshaler   = (*UZMod[*modular.SimpleModulus])(nil)
	_ cbor.Unmarshaler = (*UZMod[*modular.SimpleModulus])(nil)
	_ cbor.Marshaler   = (*UZMod[*modular.OddPrimeFactors])(nil)
	_ cbor.Unmarshaler = (*UZMod[*modular.OddPrimeFactors])(nil)
	_ cbor.Marshaler   = (*UZMod[*modular.OddPrimeSquareFactors])(nil)
	_ cbor.Unmarshaler = (*UZMod[*modular.OddPrimeSquareFactors])(nil)
)

const (
	UnitTag                    = 5010
	UnitKnownOrderTag          = 5011
	UZModSimpleTag             = 5012
	UZModOddPrimeTag           = 5013
	UZModOddPrimeSquareTag     = 5014
	PaillierGroupTag           = 5015
	PaillierGroupKnownOrderTag = 5016
	RSAGroupTag                = 5017
	RSAGroupKnownOrderTag      = 5018
)

func init() {
	// Register both wrapper types to handle dual tags for units
	serde.Register[*unitUnknownOrder](UnitTag)
	serde.Register[*unitKnownOrder](UnitKnownOrderTag)
	serde.Register[*UZMod[*modular.SimpleModulus]](UZModSimpleTag)
	serde.Register[*UZMod[*modular.OddPrimeFactors]](UZModOddPrimeTag)
	serde.Register[*UZMod[*modular.OddPrimeSquareFactors]](UZModOddPrimeSquareTag)
	serde.Register[*paillierGroup](PaillierGroupTag)
	serde.Register[*paillierGroupKnownOrder](PaillierGroupKnownOrderTag)
	// RSA Group for now is just alias of UZMod
	// serde.Register[*rsaGroup](RSAGroupTag)
	serde.Register[*rsaGroupKnownOrder](RSAGroupKnownOrderTag)
}

// MarshalCBOR for unitUnknownOrder - delegates to embedded unit
func (u *unitUnknownOrder) MarshalCBOR() ([]byte, error) {
	return u.unit.MarshalCBOR()
}

// UnmarshalCBOR for unitUnknownOrder - deserializes unknown order unit
func (u *unitUnknownOrder) UnmarshalCBOR(data []byte) error {
	// When called by serde, the tag has already been stripped
	// We know this is an unknown order unit because of the tag that was registered
	dto, err := serde.UnmarshalCBOR[unitDTO](data)
	if err != nil {
		return err
	}
	if u.unit == nil {
		u.unit = &unit{}
	}
	u.unit.v = dto.V
	uzmod, err := NewUnitGroupOfUnknownOrder[*modular.SimpleModulus](num.NPlus().FromModulus(dto.Mod))
	if err != nil {
		return err
	}
	u.unit.g = uzmod
	return nil
}

// MarshalCBOR for unitKnownOrder - delegates to embedded unit
func (u *unitKnownOrder) MarshalCBOR() ([]byte, error) {
	return u.unit.MarshalCBOR()
}

// UnmarshalCBOR for unitKnownOrder - deserializes known order unit
func (u *unitKnownOrder) UnmarshalCBOR(data []byte) error {
	// When called by serde, the tag has already been stripped
	// We know this is a known order unit because of the tag that was registered
	dto, err := serde.UnmarshalCBOR[unitDTOKnownOrder](data)
	if err != nil {
		return err
	}
	if u.unit == nil {
		u.unit = &unit{}
	}
	u.unit.v = dto.V

	// Create the appropriate group type based on the arithmetic type
	switch arith := dto.X.(type) {
	case *modular.OddPrimeFactors:
		// This is an RSA group
		uzmod, err := NewUnitGroup(arith)
		if err != nil {
			return err
		}
		// Wrap in rsaGroupKnownOrder
		u.unit.g = &rsaGroupKnownOrder{rsaGroup: *uzmod}
	case *modular.OddPrimeSquareFactors:
		// This is a Paillier group
		uzmod, err := NewUnitGroup(arith)
		if err != nil {
			return err
		}
		// Need to extract N from the arith which has it embedded
		// OddPrimeSquareFactors has CrtModN which contains the modulus n (not n²)
		n := num.NPlus().FromModulus(arith.CrtModN.Modulus())
		u.unit.g = &paillierGroupKnownOrder{
			paillierGroup: paillierGroup{
				UZMod: *uzmod,
				n:     n,
			},
		}
	default:
		uzmod, err := NewUnitGroup(dto.X)
		if err != nil {
			return err
		}
		u.unit.g = uzmod
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

func (u *unit) MarshalCBOR() ([]byte, error) {
	if u.IsUnknownOrder() {
		dto := &unitDTO{V: u.v, Mod: u.g.ModulusCT()}
		return serde.MarshalCBORTagged(dto, UnitTag)
	}
	dto := &unitDTOKnownOrder{V: u.v, X: arithmeticOf(u)}
	return serde.MarshalCBORTagged(dto, UnitKnownOrderTag)
}

func (u *unit) UnmarshalCBOR(data []byte) error {
	var base struct {
		Tag uint64 `cbor:"_serde_tag"`
	}
	if err := cbor.Unmarshal(data, &base); err != nil {
		return err
	}
	switch base.Tag {
	case UnitTag:
		dto, err := serde.UnmarshalCBOR[unitDTO](data)
		if err != nil {
			return err
		}
		u.v = dto.V
		uzmod, err := NewUnitGroupOfUnknownOrder[*modular.SimpleModulus](num.NPlus().FromModulus(dto.Mod))
		if err != nil {
			return err
		}
		u.g = uzmod
		return nil
	case UnitKnownOrderTag:
		dto, err := serde.UnmarshalCBOR[unitDTOKnownOrder](data)
		if err != nil {
			return err
		}
		u.v = dto.V
		uzmod, err := NewUnitGroup(dto.X)
		if err != nil {
			return err
		}
		u.g = uzmod
		return nil
	default:
		return errs.NewValue("unknown tag for unit")
	}
}

type uZModDTO struct {
	Arith modular.Arithmetic `cbor:"arithmetic"`
}

type uZModDTOUnknown struct {
	Mod numct.Modulus `cbor:"modulus"`
}

func (us *UZMod[X]) MarshalCBOR() ([]byte, error) {
	// Choose tag based on the concrete instantiation of UZMod[X].
	var tag uint64
	switch any(us).(type) {
	case *UZMod[*modular.SimpleModulus]:
		tag = UZModSimpleTag
	case *UZMod[*modular.OddPrimeFactors]:
		tag = UZModOddPrimeTag
	case *UZMod[*modular.OddPrimeSquareFactors]:
		tag = UZModOddPrimeSquareTag
	default:
		return nil, errs.NewValue("unsupported UZMod specialization in MarshalCBOR")
	}

	// Check if this is unknown order (nil arithmetic)
	if utils.IsNil(us.arith) || us.order.IsUnknown() {
		// Unknown order: just serialize the modulus
		dto := &uZModDTOUnknown{Mod: us.zMod.Modulus().ModulusCT()}
		return serde.MarshalCBORTagged(dto, tag)
	}

	// Known-order: serialize the arithmetic object (carries modulus and factors/order).
	dto := &uZModDTO{Arith: us.arith}
	return serde.MarshalCBORTagged(dto, tag)
}

func (us *UZMod[X]) UnmarshalCBOR(data []byte) error {
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
		us.order = kdto.Arith.MultiplicativeOrder()
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
	us.order = cardinal.Unknown()
	// arith remains nil/zero for unknown order
	return nil
}

// Group serialization DTOs and methods

type paillierGroupDTO struct {
	UZMod *UZMod[*modular.OddPrimeSquareFactors] `cbor:"uzmod"`
	N     *num.NatPlus                           `cbor:"n"`
}

func (pg *paillierGroup) MarshalCBOR() ([]byte, error) {
	dto := &paillierGroupDTO{
		UZMod: &pg.UZMod,
		N:     pg.n,
	}
	return serde.MarshalCBORTagged(dto, PaillierGroupTag)
}

func (pg *paillierGroup) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[paillierGroupDTO](data)
	if err != nil {
		return err
	}
	pg.UZMod = *dto.UZMod
	pg.n = dto.N
	return nil
}

func (pg *paillierGroupKnownOrder) MarshalCBOR() ([]byte, error) {
	dto := &paillierGroupDTO{
		UZMod: &pg.UZMod,
		N:     pg.n,
	}
	return serde.MarshalCBORTagged(dto, PaillierGroupKnownOrderTag)
}

func (pg *paillierGroupKnownOrder) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[paillierGroupDTO](data)
	if err != nil {
		return err
	}
	pg.UZMod = *dto.UZMod
	pg.n = dto.N
	return nil
}

type rsaGroupDTO struct {
	UZMod *UZMod[*modular.OddPrimeFactors] `cbor:"uzmod"`
}

func (rg *rsaGroupKnownOrder) MarshalCBOR() ([]byte, error) {
	dto := &rsaGroupDTO{
		UZMod: &rg.rsaGroup,
	}
	return serde.MarshalCBORTagged(dto, RSAGroupKnownOrderTag)
}

func (rg *rsaGroupKnownOrder) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[rsaGroupDTO](data)
	if err != nil {
		return err
	}
	rg.rsaGroup = *dto.UZMod
	return nil
}
