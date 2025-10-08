package serde

import (
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/fxamacker/cbor/v2"
)

func MarshalCBOR[T any](t T) ([]byte, error) {
	enc, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		return nil, errs.WrapSerialisation(err, "cannot marshal to CBOR")
	}
	return enc.Marshal(t)
}

func UnmarshalCBOR[T any](data []byte) (T, error) {
	var t T
	// TODO: decide on the options
	decOptions := cbor.DecOptions{
		DupMapKey: cbor.DupMapKeyEnforcedAPF,
	}

	dec, err := decOptions.DecMode()
	if err != nil {
		return t, errs.WrapSerialisation(err, "cannot unmarshal from CBOR")
	}
	err = dec.Unmarshal(data, &t)
	return t, err
}
