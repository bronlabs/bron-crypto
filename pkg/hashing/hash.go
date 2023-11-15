package hashing

import (
	"bytes"
	"hash"

	"golang.org/x/crypto/hkdf"

	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

// Hash iteratively writes all the inputs to the given hash function and returns the result.
func Hash(h func() hash.Hash, xs ...[]byte) ([]byte, error) {
	H := h()
	for _, x := range xs {
		if _, err := H.Write(x); err != nil {
			return nil, errs.WrapFailed(err, "could not write to H")
		}
	}
	digest := H.Sum(nil)
	return digest, nil
}

// HashChain computes the HKDF over many values iteratively such that each
// value is hashed separately and based on preceding values.
//
// The first value is computed as okm_0 = KDF(f || value) where
//   - f is a byte slice of 32 0xFF
//   - salt is zero-filled byte slice with length equal to the hash output length
//   - info is the protocol name
//   - okm is the 32 byte output
//
// The each subsequent iteration is computed by as okm_i = KDF(f_i || value || okm_{i-1})
// where f_i = 2^b - 1 - i such that there are 0xFF bytes prior to the value.
// f_1 changes the first byte to 0xFE, f_2 to 0xFD. The previous okm is appended to the value
// to provide cryptographic domain separation.
// See https://signal.org/docs/specifications/x3dh/#cryptographic-notation
// and https://signal.org/docs/specifications/xeddsa/#hash-functions
// for more details.
// This uses the KDF function similar to X3DH for each `value`
// But changes the key just like XEdDSA where the prefix bytes change by a single bit.
func HashChain(h func() hash.Hash, xs ...[]byte) ([]byte, error) {
	// Don't accept any nil arguments
	for _, x := range xs {
		if x == nil {
			return nil, errs.NewIsNil("an input is nil")
		}
	}

	info := []byte("KRYPTON_PRIMITIVES_FIAT_SHAMIR_WITH_HKDF")
	salt := make([]byte, 32)
	okm := make([]byte, 32)
	f := bytes.Repeat([]byte{0xFF}, 32)

	for _, x := range xs {
		ikm := append(f, x...)
		ikm = append(ikm, okm...)
		kdf := hkdf.New(h, ikm, salt, info)
		n, err := kdf.Read(okm)
		if err != nil {
			return nil, errs.WrapRandomSampleFailed(err, "write to kdf failed")
		}
		if n != len(okm) {
			return nil, errs.NewFailed("unable to read expected number of bytes want=%v got=%v", len(okm), n)
		}
		bitstring.ByteSubLE(f)
	}
	return okm, nil
}
