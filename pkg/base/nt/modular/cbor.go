package modular

import (
	"github.com/fxamacker/cbor/v2"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
)

var (
	_ cbor.Marshaler   = (*SimpleModulus)(nil)
	_ cbor.Unmarshaler = (*SimpleModulus)(nil)
	_ cbor.Marshaler   = (*OddPrimeFactors)(nil)
	_ cbor.Unmarshaler = (*OddPrimeFactors)(nil)
	_ cbor.Marshaler   = (*OddPrimeSquareFactors)(nil)
	_ cbor.Unmarshaler = (*OddPrimeSquareFactors)(nil)
)

const (
	SimpleModulusTag         = 5006
	OddPrimeFactorsTag       = 5007
	OddPrimeSquareFactorsTag = 5008
)

func init() {
	serde.Register[*SimpleModulus](SimpleModulusTag)
	serde.Register[*OddPrimeFactors](OddPrimeFactorsTag)
	serde.Register[*OddPrimeSquareFactors](OddPrimeSquareFactorsTag)
}

type simpleDTO struct {
	Modulus numct.Modulus `cbor:"modulus"`
}

func (s *SimpleModulus) MarshalCBOR() ([]byte, error) {
	dto := &simpleDTO{Modulus: s.m}
	data, err := serde.MarshalCBORTagged(dto, SimpleModulusTag)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "failed to marshal SimpleModulus")
	}
	return data, nil
}

func (s *SimpleModulus) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[simpleDTO](data)
	if err != nil {
		return err
	}
	s.m = dto.Modulus
	return nil
}

type pairDTO struct {
	P *numct.Nat `cbor:"p"`
	Q *numct.Nat `cbor:"q"`
}

func (o *OddPrimeFactors) MarshalCBOR() ([]byte, error) {
	dto := &pairDTO{
		P: o.Params.P.Nat(),
		Q: o.Params.Q.Nat(),
	}
	data, err := serde.MarshalCBORTagged(dto, OddPrimeFactorsTag)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "failed to marshal OddPrimeFactors")
	}
	return data, nil
}

func (o *OddPrimeFactors) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[pairDTO](data)
	if err != nil {
		return err
	}
	out, ok := NewOddPrimeFactors(dto.P, dto.Q)
	if ok == ct.False {
		return errs.NewValue("failed to create OddPrimeFactors")
	}
	*o = *out
	return nil
}

func (s *OddPrimeSquareFactors) MarshalCBOR() ([]byte, error) {
	dto := &pairDTO{
		P: s.P.Factor.Nat(),
		Q: s.Q.Factor.Nat(),
	}
	data, err := serde.MarshalCBORTagged(dto, OddPrimeSquareFactorsTag)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "failed to marshal OddPrimeSquareFactors")
	}
	return data, nil
}

func (s *OddPrimeSquareFactors) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[pairDTO](data)
	if err != nil {
		return err
	}
	out, ok := NewOddPrimeSquareFactors(dto.P, dto.Q)
	if ok == ct.False {
		return errs.NewValue("failed to create OddPrimeSquareFactors")
	}
	*s = *out
	return nil
}
