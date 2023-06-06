package hashing

import (
	"bytes"
	"fmt"
	"hash"
	"math"
	"math/big"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves/native"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/pkg/errors"
	"golang.org/x/crypto/hkdf"
)

func I2OSP(b, n int) []byte {
	os := new(big.Int).SetInt64(int64(b)).Bytes()
	if n > len(os) {
		var buf bytes.Buffer
		buf.Write(make([]byte, n-len(os)))
		buf.Write(os)
		return buf.Bytes()
	}
	return os[:n]
}

func OS2IP(os []byte) *big.Int {
	return new(big.Int).SetBytes(os)
}

func concat(xs ...[]byte) []byte {
	var result []byte
	for _, x := range xs {
		result = append(result, x...)
	}
	return result
}

func xor(b1, b2 []byte) []byte {
	// b1 and b2 must be same length
	result := make([]byte, len(b1))
	for i := range b1 {
		result[i] = b1[i] ^ b2[i]
	}

	return result
}

func ExpandMessageXmd(f func() hash.Hash, msg, DST []byte, lenInBytes int) ([]byte, error) {
	// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-10#section-5.4.1

	// step 1
	ell := int(math.Ceil(float64(lenInBytes) / float64(f().Size())))

	//step 2
	if ell > 255 {
		return nil, fmt.Errorf("ell > 255")
	}

	// step 3
	dstPrime := append(DST, I2OSP(len(DST), 1)...)

	// step 4
	zPad := I2OSP(0, f().BlockSize())

	// step 5 & 6
	msgPrime := concat(zPad, msg, I2OSP(lenInBytes, 2), I2OSP(0, 1), dstPrime)

	var err error

	b := make([][]byte, ell+1)

	// step 7
	b[0], err = Hash(f, msgPrime)
	if err != nil {
		return nil, err
	}

	// step 8
	b[1], err = Hash(f, concat(b[0], I2OSP(1, 1), dstPrime))
	if err != nil {
		return nil, err
	}

	// step 9
	for i := 2; i <= ell; i++ {
		// step 10
		b[i], err = Hash(f, concat(xor(b[0], b[i-1]), I2OSP(i, 1), dstPrime))
		if err != nil {
			return nil, err
		}
	}
	// step 11
	uniformBytes := concat(b[1:]...)

	// step 12
	return uniformBytes[:lenInBytes], nil
}

// TODO: make sure this outputs consistently with the curve implementation
func HashToField(h func() hash.Hash, DST, message []byte, securityParameter, characteristic, extensionDegree, count int) ([][]*big.Int, error) {
	// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-10#section-5.3

	L := int(math.Ceil(
		(math.Ceil(math.Log2(float64(characteristic))) + float64(securityParameter)) /
			float64(8),
	))

	// step 1
	lenInBytes := count * extensionDegree * L

	// step 2
	uniformBytes, err := ExpandMessageXmd(h, message, DST, lenInBytes)
	if err != nil {
		return nil, err
	}

	u := make([][]*big.Int, count)

	// step 3
	for i := 0; i < count; i++ {
		e := make([]*big.Int, extensionDegree)
		// step 4
		for j := 0; j < extensionDegree; j++ {
			// step 5
			elmOffset := L * (j + i*extensionDegree)
			// step 6
			tv := uniformBytes[elmOffset : elmOffset+L]
			// step 7
			e[j] = new(big.Int).Mod(OS2IP(tv), big.NewInt(int64(characteristic)))

		}
		// step 8
		u[i] = e
	}
	// step 9
	return u, nil
}

// TODO: make sure this outputs consistently with the curve implementation
func HashToCurve(curve curves.Curve, mapToCurve func(curves.Scalar) curves.Point, message []byte) (curves.Point, error) {
	// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-10#name-encoding-byte-strings-to-ell
	// Needs curve profile, a method to clear cofactor afterwards etc.
	return nil, errors.New("not implemented")
}

// Hash iteratively writes all the inputs to the given hash function and returns the result
func Hash(h func() hash.Hash, xs ...[]byte) ([]byte, error) {
	H := h()
	for _, x := range xs {
		if _, err := H.Write(x); err != nil {
			return nil, errors.Wrap(err, "could not write to H")
		}
	}

	digest := H.Sum(nil)
	return digest, nil
}

// FiatShamir computes the challenge scalar writing all inputs to the hash and creating a digest
func FiatShamir(cipherSuite *integration.CipherSuite, xs ...[]byte) (curves.Scalar, error) {
	digest, err := Hash(cipherSuite.Hash, xs...)
	if err != nil {
		return nil, errors.New("could not compute fiat shamir digest")
	}

	var setBytesFunc func([]byte) (curves.Scalar, error)
	switch len(digest) {
	case native.FieldBytes:
		setBytesFunc = cipherSuite.Curve.Scalar.SetBytes
	case native.WideFieldBytes:
		setBytesFunc = cipherSuite.Curve.Scalar.SetBytesWide
	default:
		return nil, errors.Errorf("digest length %d unsporrted", len(digest))
	}

	challenge, err := setBytesFunc(digest)
	if err != nil {
		return nil, errors.Wrap(err, "could not compute challenge")
	}
	return challenge, nil
}

// FiatShamirHKDF computes the HKDF over many values
// iteratively such that each value is hashed separately
// and based on preceding values
//
// The first value is computed as okm_0 = KDF(f || value) where
// f is a byte slice of 32 0xFF
// salt is zero-filled byte slice with length equal to the hash output length
// info is the protocol name
// okm is the 32 byte output
//
// The each subsequent iteration is computed by as okm_i = KDF(f_i || value || okm_{i-1})
// where f_i = 2^b - 1 - i such that there are 0xFF bytes prior to the value.
// f_1 changes the first byte to 0xFE, f_2 to 0xFD. The previous okm is appended to the value
// to provide cryptographic domain separation.
// See https://signal.org/docs/specifications/x3dh/#cryptographic-notation
// and https://signal.org/docs/specifications/xeddsa/#hash-functions
// for more details.
// This uses the KDF function similar to X3DH for each `value`
// But changes the key just like XEdDSA where the prefix bytes change by a single bit
func FiatShamirHKDF(h func() hash.Hash, xs ...[]byte) ([]byte, error) {
	// Don't accept any nil arguments
	for _, x := range xs {
		if x == nil {
			return nil, errors.New("can't be nil")
		}
	}

	info := []byte("KNOX_PRIMITIVES_FIAT_SHAMIR_WITH_HKDF")
	salt := make([]byte, 32)
	okm := make([]byte, 32)
	f := bytes.Repeat([]byte{0xFF}, 32)

	for _, x := range xs {
		ikm := append(f, x...)
		ikm = append(ikm, okm...)
		kdf := hkdf.New(h, ikm, salt, info)
		n, err := kdf.Read(okm)
		if err != nil {
			return nil, err
		}
		if n != len(okm) {
			return nil, errors.Errorf("unable to read expected number of bytes want=%v got=%v", len(okm), n)
		}
		byteSub(f)
	}
	return okm, nil
}

// ByteSub is a constant time algorithm for subtracting
// 1 from the array as if it were a big number.
// 0 is considered a wrap which resets to 0xFF
func byteSub(b []byte) {
	m := byte(1)
	for i := 0; i < len(b); i++ {
		b[i] -= m

		// If b[i] > 0, s == 0
		// If b[i] == 0, s == 1
		// Computing IsNonZero(b[i])
		s1 := int8(b[i]) >> 7
		s2 := -int8(b[i]) >> 7
		s := byte((s1 | s2) + 1)

		// If s == 0, don't subtract anymore
		// s == 1, continue subtracting
		m = s & m
		// If s == 0 this does nothing
		// If s == 1 reset this value to 0xFF
		b[i] |= -s
	}
}
