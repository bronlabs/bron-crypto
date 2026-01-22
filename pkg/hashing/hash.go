package hashing

import (
	"crypto/hmac"
	"encoding/binary"
	"hash"
	"slices"

	"golang.org/x/crypto/sha3"

	"github.com/bronlabs/bron-crypto/pkg/hashing/kmac"
	"github.com/bronlabs/errs-go/errs"
)

type (
	// KMACCustomizationString is a byte slice used as a domain separation string for KMAC operations.
	KMACCustomizationString = []byte
)

// Hash iteratively writes all the inputs to the given hash function and returns the result.
func Hash[H hash.Hash](hashFunc func() H, xs ...[]byte) ([]byte, error) {
	h := hashFunc()
	for i, x := range xs {
		if _, err := h.Write(x); err != nil {
			return nil, errs.Wrap(err).WithMessage("could not write to hash for input %d", i)
		}
	}
	digest := h.Sum(nil)
	return digest, nil
}

// HashPrefixedLength hashes the inputs after encoding each with its index and length prefix.
// This encoding ensures that different input sequences produce distinct hash inputs.
func HashPrefixedLength[H hash.Hash](hashFunc func() H, xs ...[]byte) ([]byte, error) {
	h := hashFunc()
	_, err := h.Write(encodePrefixedLength(xs...))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not hash input")
	}

	digest := h.Sum(nil)
	return digest, nil
}

// HashChain computes an iterated hash where each input is hashed together with the previous output.
// It starts with a zero-initialised buffer and iteratively computes H(previous || input) for each input.
func HashChain[H hash.Hash](hashFunc func() H, xs ...[]byte) ([]byte, error) {
	h := hashFunc()
	var err error
	out := make([]byte, h.Size())
	for i, x := range xs {
		out, err = Hash(hashFunc, out, x)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not compute hash for input %d", i)
		}
	}
	return out, nil
}

// Hmac iteratively writes all the inputs to an hmac (defined by the hash function and the key) and returns the result.
func Hmac[H hash.Hash](key []byte, hashFunc func() H, xs ...[]byte) ([]byte, error) {
	hmacFunc := func() hash.Hash { return hmac.New(HashFuncTypeErase(hashFunc), key) }
	out, err := Hash(hmacFunc, xs...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("computing hmac")
	}
	return out, nil
}

// HmacPrefixedLength computes an HMAC over the inputs after encoding each with its index and length prefix.
func HmacPrefixedLength[H hash.Hash](key []byte, hashFunc func() H, xs ...[]byte) ([]byte, error) {
	hmacFunc := func() hash.Hash { return hmac.New(HashFuncTypeErase(hashFunc), key) }
	out, err := HashPrefixedLength(hmacFunc, xs...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("computing hmac")
	}
	return out, nil
}

// Kmac computes a KMAC (Keccak Message Authentication Code) over the inputs using a cSHAKE function.
// Tag sizes are 32 and 64 bytes when instantiated with cSHAKE128 and cSHAKE256, respectively.
// The key must be at least half the output size to meet the security level requirements.
func Kmac(key, customizationString []byte, h func(n, s []byte) sha3.ShakeHash, xs ...[]byte) ([]byte, error) {
	cShake := h([]byte("KMAC"), customizationString)
	if len(key) < cShake.Size()/2 {
		return nil, kmac.ErrInvalidKeyLength.WithMessage("key length does not meet %d-bit security level", cShake.Size()*4)
	}
	k := kmac.AbsorbPaddedKey(key, cShake.Size(), cShake)
	for _, x := range xs {
		_, err := k.Write(x)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not write into internal state")
		}
	}
	return k.Sum(nil), nil
}

// KmacPrefixedLength computes a KMAC over the inputs after encoding each with its index and length prefix.
func KmacPrefixedLength(key, customizationString []byte, h func(n, s []byte) sha3.ShakeHash, xs ...[]byte) ([]byte, error) {
	cShake := h([]byte("KMAC"), customizationString)
	if len(key) < cShake.Size()/2 {
		return nil, kmac.ErrInvalidKeyLength.WithMessage("key length does not meet %d-bit security level", cShake.Size()*4)
	}
	k := kmac.AbsorbPaddedKey(key, cShake.Size(), cShake)
	_, err := k.Write(encodePrefixedLength(xs...))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not write into internal state")
	}
	return k.Sum(nil), nil
}

// HashFuncTypeErase converts a generic hash constructor to a non-generic one returning hash.Hash.
// This is useful when interfacing with APIs that require func() hash.Hash, such as crypto/hmac.
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
