package znstar

import (
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/modular"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
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

	// Create simple modulus arithmetic for unknown order
	arith, ok := modular.NewSimple(dto.Mod)
	if ok == ct.False {
		return errs.NewFailed("failed to create SimpleModulus")
	}
	zMod, err := num.NewZModFromModulus(dto.Mod)
	if err != nil {
		return err
	}

	// For RSA unknown order, create rsaGroup
	// For now, just create a generic UZMod with SimpleModulus
	u.unit.g = &UZMod[*modular.SimpleModulus]{
		zMod:  zMod,
		arith: arith,
	}
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
		// This is an RSA group with known order
		zMod, err := num.NewZModFromModulus(arith.Modulus())
		if err != nil {
			return err
		}
		u.unit.g = &rsaGroupKnownOrder{
			UZMod: UZMod[*modular.OddPrimeFactors]{
				zMod:  zMod,
				arith: arith,
			},
		}
	case *modular.OddPrimeSquareFactors:
		// This is a Paillier group with known order
		zMod, err := num.NewZModFromModulus(arith.Modulus())
		if err != nil {
			return err
		}
		// Extract N from CrtModN which contains the modulus n (not n²)
		n := num.NPlus().FromModulus(arith.CrtModN.Modulus())
		u.unit.g = &paillierGroupKnownOrder{
			UZMod: UZMod[*modular.OddPrimeSquareFactors]{
				zMod:  zMod,
				arith: arith,
			},
			n: n,
		}
	default:
		return errs.NewType("unknown arithmetic type in unit deserialization")
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
	// This method is only used for direct unmarshaling, not through serde
	// For serde interface unmarshaling, the wrapper types are used
	dto, err := serde.UnmarshalCBOR[unitDTO](data)
	if err != nil {
		return err
	}
	u.v = dto.V

	// Create simple modulus arithmetic for unknown order
	arith, ok := modular.NewSimple(dto.Mod)
	if ok == ct.False {
		return errs.NewFailed("failed to create SimpleModulus")
	}
	zMod, err := num.NewZModFromModulus(dto.Mod)
	if err != nil {
		return err
	}

	u.g = &UZMod[*modular.SimpleModulus]{
		zMod:  zMod,
		arith: arith,
	}
	return nil
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

	// Serialize the arithmetic object (carries modulus and order)
	dto := &uZModDTO{Arith: us.arith}
	return serde.MarshalCBORTagged(dto, tag)
}

func (us *UZMod[X]) UnmarshalCBOR(data []byte) error {
	// When called by serde, the tag has already been stripped
	dto, err := serde.UnmarshalCBOR[uZModDTO](data)
	if err != nil {
		return err
	}

	// Create ZMod from arithmetic modulus
	z, err := num.NewZModFromModulus(dto.Arith.Modulus())
	if err != nil {
		return errs.WrapFailed(err, "failed to construct ZMod from arithmetic modulus")
	}
	us.zMod = z

	// Type assertion is safe because we're inside the correct generic monomorphization
	if arith, ok := dto.Arith.(X); ok {
		us.arith = arith
	} else {
		return errs.NewType("decoded arithmetic doesn't match UZMod type parameter")
	}
	return nil
}

// Group serialization DTOs and methods

type paillierGroupUnknownDTO struct {
	UZMod *UZMod[*modular.SimpleModulus] `cbor:"uzmod"`
	N     *num.NatPlus                   `cbor:"n"`
}

type paillierGroupKnownDTO struct {
	UZMod *UZMod[*modular.OddPrimeSquareFactors] `cbor:"uzmod"`
	N     *num.NatPlus                           `cbor:"n"`
}

func (pg *paillierGroup) MarshalCBOR() ([]byte, error) {
	dto := &paillierGroupUnknownDTO{
		UZMod: &pg.UZMod,
		N:     pg.n,
	}
	return serde.MarshalCBORTagged(dto, PaillierGroupTag)
}

func (pg *paillierGroup) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[paillierGroupUnknownDTO](data)
	if err != nil {
		return err
	}
	pg.UZMod = *dto.UZMod
	pg.n = dto.N
	return nil
}

func (pg *paillierGroupKnownOrder) MarshalCBOR() ([]byte, error) {
	dto := &paillierGroupKnownDTO{
		UZMod: &pg.UZMod,
		N:     pg.n,
	}
	return serde.MarshalCBORTagged(dto, PaillierGroupKnownOrderTag)
}

func (pg *paillierGroupKnownOrder) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[paillierGroupKnownDTO](data)
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
		UZMod: &rg.UZMod,
	}
	return serde.MarshalCBORTagged(dto, RSAGroupKnownOrderTag)
}

func (rg *rsaGroupKnownOrder) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[rsaGroupDTO](data)
	if err != nil {
		return err
	}
	rg.UZMod = *dto.UZMod
	return nil
}
