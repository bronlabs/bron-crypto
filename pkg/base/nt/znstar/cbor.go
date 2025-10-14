package znstar

import (
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/modular"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/fxamacker/cbor/v2"
)

var (
	_ cbor.Marshaler   = (*unit)(nil)
	_ cbor.Unmarshaler = (*unit)(nil)
	_ cbor.Marshaler   = (*UZMod[*modular.SimpleModulus])(nil)
	_ cbor.Unmarshaler = (*UZMod[*modular.SimpleModulus])(nil)
	_ cbor.Marshaler   = (*UZMod[*modular.OddPrimeFactors])(nil)
	_ cbor.Unmarshaler = (*UZMod[*modular.OddPrimeFactors])(nil)
	_ cbor.Marshaler   = (*UZMod[*modular.OddPrimeSquareFactors])(nil)
	_ cbor.Unmarshaler = (*UZMod[*modular.OddPrimeSquareFactors])(nil)
)

const (
	UnitTag                = 5010
	UnitKnownOrderTag      = 5011
	UZModSimpleTag         = 5012
	UZModOddPrimeTag       = 5013
	UZModOddPrimeSquareTag = 5014
)

func init() {
	serde.Register[*unit](UnitTag)
	serde.Register[*UZMod[*modular.SimpleModulus]](UZModSimpleTag)
	serde.Register[*UZMod[*modular.OddPrimeFactors]](UZModOddPrimeTag)
	serde.Register[*UZMod[*modular.OddPrimeSquareFactors]](UZModOddPrimeSquareTag)
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
	Mod numct.Modulus `cbor:"modulus"`
}

type uZModKnownOrderDTO struct {
	Arith modular.Arithmetic `cbor:"arithmetic"`
}

// func (us *UZMod[X]) MarshalCBOR() ([]byte, error) {
// 	if us.order.IsUnknown() {
// 		dto := &uZModDTO{Mod: us.zMod.Modulus()}
