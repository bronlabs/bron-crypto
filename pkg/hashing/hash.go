package hashing

import (
	"crypto/hmac"
	"hash"
	"slices"

	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/hashing/kmac"
)

// Hash iteratively writes all the inputs to the given hash function and returns the result.
func Hash(h func() hash.Hash, xs ...[]byte) ([]byte, error) {
	H := h()
	for i, x := range xs {
		if _, err := H.Write(x); err != nil {
			return nil, errs.WrapFailed(err, "could not write to H for input %d", i)
		}
	}
	digest := H.Sum(nil)
	return digest, nil
}

func HashPrefixedLength(h func() hash.Hash, xs ...[]byte) ([]byte, error) {
	H := h()
	H.Write(encodePrefixedLength(xs...))
	digest := H.Sum(nil)
	return digest, nil
}

func HashChain(h func() hash.Hash, xs ...[]byte) ([]byte, error) {
	H := h()
	var err error
	out := make([]byte, H.Size())
	for i, x := range xs {
		out, err = Hash(h, out, x)
		if err != nil {
			return nil, errs.WrapHashing(err, "could not compute hash for input %d", i)
		}
	}
	return out, nil
}

// Hmac iteratively writes all the inputs to an hmac (defined by the hash function and the key) and returns the result.
func Hmac(key []byte, h func() hash.Hash, xs ...[]byte) ([]byte, error) {
	hmacFunc := func() hash.Hash { return hmac.New(h, key) }
	out, err := Hash(hmacFunc, xs...)
	if err != nil {
		return nil, errs.WrapHashing(err, "computing hmac")
	}
	return out, nil
}

// Same as Hmac but applies encodedPrefixLength to the inputs.
func HmacPrefixedLength(key []byte, h func() hash.Hash, xs ...[]byte) ([]byte, error) {
	hmacFunc := func() hash.Hash { return hmac.New(h, key) }
	out, err := HashPrefixedLength(hmacFunc, xs...)
	if err != nil {
		return nil, errs.WrapHashing(err, "computing hmac")
	}
	return out, nil
}

// Kmac iteratively writes all the inputs to a kmac (defined by the cSHAKE function) and returns the result.
// Tag sizes are 32 and 64 bytes when instantiated with cSHAKE128 and cSHAKE256, respectively.
func Kmac(key, customizationString []byte, h func(n, s []byte) sha3.ShakeHash, xs ...[]byte) ([]byte, error) {
	cShake := h([]byte("KMAC"), customizationString)
	if len(key) < cShake.Size()/2 {
		return nil, errs.NewArgument("key length does not meet %d-bit security level", cShake.Size()*4)
	}
	k := kmac.AbsorbPaddedKey(key, cShake.Size(), cShake)
	for _, x := range xs {
		_, err := k.Write(x)
		if err != nil {
			return nil, errs.WrapHashing(err, "could not write into internal state successfully")
		}
	}
	return k.Sum(nil), nil
}

// Same as Kmac but applies encodedPrefixLength to the inputs.
func KmacPrefixedLength(key, customizationString []byte, h func(n, s []byte) sha3.ShakeHash, xs ...[]byte) ([]byte, error) {
	cShake := h([]byte("KMAC"), customizationString)
	if len(key) < cShake.Size()/2 {
		return nil, errs.NewArgument("key length does not meet %d-bit security level", cShake.Size()*4)
	}
	k := kmac.AbsorbPaddedKey(key, cShake.Size(), cShake)
	_, err := k.Write(encodePrefixedLength(xs...))
	if err != nil {
		return nil, errs.WrapHashing(err, "could not write into internal state successfully")
	}
	return k.Sum(nil), nil
}

func encodePrefixedLength(messages ...[]byte) []byte {
	output := []byte{}
	for i, message := range messages {
		encodedMessage := slices.Concat(bitstring.ToBytes32LE(int32(i)), bitstring.ToBytes32LE(int32(len(message))), message)
		output = slices.Concat(output, encodedMessage)
	}
	return output
}
