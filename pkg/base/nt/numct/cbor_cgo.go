//go:build !purego && !nobignum

package numct

import (
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/fxamacker/cbor/v2"
)

var (
	_ cbor.Marshaler   = (*ModulusOddPrime)(nil)
	_ cbor.Unmarshaler = (*ModulusOddPrime)(nil)
	_ cbor.Marshaler   = (*ModulusOdd)(nil)
	_ cbor.Unmarshaler = (*ModulusOdd)(nil)
)

func (m *ModulusOddPrime) MarshalCBOR() ([]byte, error) {
	serial := &modulusDTO{N: m.Nat()}
	return serde.MarshalCBORTagged(serial, ModulusOddPrimeTag)
}

func (m *ModulusOddPrime) UnmarshalCBOR(data []byte) error {
	serial, err := serde.UnmarshalCBOR[*modulusDTO](data)
	if err != nil {
		return err
	}
	if serial.N == nil {
		return errs.NewIsNil("modulus data")
	}
	mod, ok := NewModulusOddPrime(serial.N)
	if ok == ct.False {
		return errs.NewValue("not a valid odd prime modulus")
	}
	// Copy all fields including mSub2 and once from the newly created modulus
	*m = *mod
	// Ensure montgomery parameters are computed
	m.ensureMont()
	return nil
}

func (m *ModulusOdd) MarshalCBOR() ([]byte, error) {
	serial := &modulusDTO{N: m.Nat()}
	return serde.MarshalCBORTagged(serial, ModulusOddTag)
}

func (m *ModulusOdd) UnmarshalCBOR(data []byte) error {
	serial, err := serde.UnmarshalCBOR[*modulusDTO](data)
	if err != nil {
		return err
	}
	if serial.N == nil {
		return errs.NewIsNil("modulus data")
	}
	mod, ok := NewModulusOdd(serial.N)
	if ok == ct.False {
		return errs.NewValue("not a valid odd modulus")
	}
	// Copy all fields including mSub2, mNum, and once from the newly created modulus
	*m = *mod
	// Ensure montgomery parameters are computed
	m.ensureMont()
	return nil
}
