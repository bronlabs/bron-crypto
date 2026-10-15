package modular

import (
	"github.com/fxamacker/cbor/v2"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/internal/tags"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
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
	SimpleModulusTag         = tags.SimpleModulusTag
	OddPrimeFactorsTag       = tags.OddPrimeFactorsTag
	OddPrimeSquareFactorsTag = tags.OddPrimeSquareFactorsTag
)

func init() {
	serde.Register[*SimpleModulus](SimpleModulusTag)
	serde.Register[*OddPrimeFactors](OddPrimeFactorsTag)
	serde.Register[*OddPrimeSquareFactors](OddPrimeSquareFactorsTag)
}

type simpleDTO struct {
	Modulus *numct.Modulus `cbor:"modulus"`
}

func (m *SimpleModulus) MarshalCBOR() ([]byte, error) {
	dto := &simpleDTO{Modulus: m.m}
	data, err := serde.MarshalCBORTagged(dto, SimpleModulusTag)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal SimpleModulus")
	}
	return data, nil
}

func (m *SimpleModulus) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[simpleDTO](data)
	if err != nil {
		return errs.Wrap(err)
	}
	out, ok := NewSimple(dto.Modulus)
	if ok == ct.False {
		return ErrFailed.WithMessage("failed to create SimpleModulus")
	}
	*m = *out
	return nil
}

type pairDTO struct {
	P *numct.Nat `cbor:"p"`
	Q *numct.Nat `cbor:"q"`
}

// validateDecodedFactors screens a decoded factor pair before it reaches a
// constructor. The constructors run in constant-time style: they derive every
// modulus they need (p, q, p-1, q-1, p^2, p*q, ...) and fold each failure into
// the returned flag instead of stopping, so they assume both factors are
// present and at least 2. A nil or zero factor, or the value 1, makes one of
// those derived moduli zero, numct.NewModulus yields nil for it, and the flow
// dereferences it. Honest callers never pass such inputs; a CBOR payload is
// untrusted and is checked here. Oddness and primality stay with the
// constructor.
func validateDecodedFactors(p, q *numct.Nat) error {
	if p == nil || q == nil {
		return ErrFailed.WithMessage("factor is nil")
	}
	if p.TrueLen() < 2 || q.TrueLen() < 2 {
		return ErrFailed.WithMessage("factor must be greater than one")
	}
	return nil
}

func (m *OddPrimeFactors) MarshalCBOR() ([]byte, error) {
	dto := &pairDTO{
		P: m.Params.P.Nat(),
		Q: m.Params.Q.Nat(),
	}
	data, err := serde.MarshalCBORTagged(dto, OddPrimeFactorsTag)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal OddPrimeFactors")
	}
	return data, nil
}

func (m *OddPrimeFactors) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[pairDTO](data)
	if err != nil {
		return errs.Wrap(err)
	}
	if err := validateDecodedFactors(dto.P, dto.Q); err != nil {
		return errs.Wrap(err).WithMessage("invalid OddPrimeFactors payload")
	}
	out, ok := NewOddPrimeFactors(dto.P, dto.Q)
	if ok == ct.False {
		return ErrFailed.WithMessage("failed to create OddPrimeFactors")
	}
	*m = *out
	return nil
}

func (m *OddPrimeSquareFactors) MarshalCBOR() ([]byte, error) {
	dto := &pairDTO{
		P: m.P.Factor.Nat(),
		Q: m.Q.Factor.Nat(),
	}
	data, err := serde.MarshalCBORTagged(dto, OddPrimeSquareFactorsTag)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal OddPrimeSquareFactors")
	}
	return data, nil
}

func (m *OddPrimeSquareFactors) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[pairDTO](data)
	if err != nil {
		return errs.Wrap(err)
	}
	if err := validateDecodedFactors(dto.P, dto.Q); err != nil {
		return errs.Wrap(err).WithMessage("invalid OddPrimeSquareFactors payload")
	}
	out, ok := NewOddPrimeSquareFactors(dto.P, dto.Q)
	if ok == ct.False {
		return ErrFailed.WithMessage("failed to create OddPrimeSquareFactors")
	}
	*m = *out
	return nil
}

var (
	ErrFailed = errs.New("failed")
)
