package hashing

import (
	"crypto/hmac"
	"encoding/binary"
	"hash"
	"slices"

	"golang.org/x/crypto/sha3"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/hashing/kmac"
)

type (
	KMACCustomizationString = []byte
)

// Hash iteratively writes all the inputs to the given hash function and returns the result.
func Hash[H hash.Hash](hashFunc func() H, xs ...[]byte) ([]byte, error) {
	h := hashFunc()
	for i, x := range xs {
		if _, err := h.Write(x); err != nil {
			return nil, errs.WrapFailed(err, "could not write to H for input %d", i)
		}
	}
	digest := h.Sum(nil)
	return digest, nil
}

func HashPrefixedLength[H hash.Hash](hashFunc func() H, xs ...[]byte) ([]byte, error) {
	h := hashFunc()
	_, err := h.Write(encodePrefixedLength(xs...))
	if err != nil {
		return nil, errs.WrapHashing(err, "could not hash input")
	}

	digest := h.Sum(nil)
	return digest, nil
}

func HashChain[H hash.Hash](hashFunc func() H, xs ...[]byte) ([]byte, error) {
	h := hashFunc()
	var err error
	out := make([]byte, h.Size())
	for i, x := range xs {
		out, err = Hash(hashFunc, out, x)
		if err != nil {
			return nil, errs.WrapHashing(err, "could not compute hash for input %d", i)
		}
	}
	return out, nil
}

// Hmac iteratively writes all the inputs to an hmac (defined by the hash function and the key) and returns the result.
func Hmac[H hash.Hash](key []byte, hashFunc func() H, xs ...[]byte) ([]byte, error) {
	hmacFunc := func() hash.Hash { return hmac.New(HashFuncTypeErase(hashFunc), key) }
	out, err := Hash(hmacFunc, xs...)
	if err != nil {
		return nil, errs.WrapHashing(err, "computing hmac")
	}
	return out, nil
}

// HmacPrefixedLength is the same as Hmac but applies encodedPrefixLength to the inputs.
func HmacPrefixedLength[H hash.Hash](key []byte, hashFunc func() H, xs ...[]byte) ([]byte, error) {
	hmacFunc := func() hash.Hash { return hmac.New(HashFuncTypeErase(hashFunc), key) }
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

func HashFuncTypeErase[H hash.Hash](hashFunc func() H) func() hash.Hash {
	return func() hash.Hash {
		return hashFunc()
	}
}

func encodePrefixedLength(messages ...[]byte) []byte {
	output := []byte{}
	for i, message := range messages {
		encodedMessage := slices.Concat(toBytes32LE(int32(i)), toBytes32LE(int32(len(message))), message)
		output = slices.Concat(output, encodedMessage)
	}
	return output
}

func toBytes32LE(i int32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(i))
	return b
}
