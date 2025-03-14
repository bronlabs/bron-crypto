package deterministic

import (
	"github.com/bronlabs/bron-crypto/pkg/base/bitstring"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/base/uint2k/uint256"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

type Signer struct {
	suite      types.SigningSuite
	privateKey curves.Scalar
}

func NewSigner(suite types.SigningSuite, privateKey curves.Scalar) (*Signer, error) {
	if err := types.ValidateSigningSuite(suite); err != nil {
		return nil, errs.WrapArgument(err, "invalid cipher suite")
	}
	if privateKey == nil {
		return nil, errs.NewIsNil("private key is nil")
	}
	if suite.Curve().BaseField().ElementSize() > uint256.RingBytes {
		return nil, errs.NewArgument("curve base field is too large (%dB > %dB)",
			suite.Curve().BaseField().ElementSize(), uint256.RingBytes)
	}
	return &Signer{suite, privateKey}, nil
}

// Sign signs a message using the provided private key, generating a deterministic
// nonce `k` as per RFC 6979 (https://tools.ietf.org/html/rfc6979).
func (s *Signer) Sign(message []byte) (*ecdsa.Signature, error) {
	qUint, err := uint256.Uint256{}.SetBytes(s.suite.Curve().Order().Bytes())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot set q")
	}

	// step 1: hashing the message
	hBytes, err := hashing.Hash(s.suite.Hash(), message)
	if err != nil {
		return nil, errs.WrapHashing(err, "could not produce HMAC of message")
	}
	hlen := len(hBytes)
	h := ecdsa.BitsToInt(hBytes, s.suite.Curve())
	if h.Cmp(qUint) >= 0 {
		h = h.Sub(qUint)
	}
	hBytes = s.int2octets(h.Bytes())

	// step 2: generate k (deterministic)
	// steps 2.b & 2.c
	V := make([]byte, hlen)
	for i := 0; i < hlen; i++ {
		V[i] = 0x01
	}
	K := make([]byte, hlen)
	// step 2.d
	x := s.int2octets(s.privateKey.Bytes())
	if K, err = hashing.Hmac(K, s.suite.Hash(), V, []byte{0x00}, x, hBytes); err != nil {
		return nil, errs.WrapHashing(err, "could not produce HMAC for K")
	}
	// steps 2.e & 2.f & 2.g
	if V, err = hashing.Hmac(K, s.suite.Hash(), V); err != nil {
		return nil, errs.WrapHashing(err, "could not produce HMAC for V")
	}
	if K, err = hashing.Hmac(K, s.suite.Hash(), V, []byte{0x01}, x, hBytes); err != nil {
		return nil, errs.WrapHashing(err, "could not produce HMAC for K")
	}
	if V, err = hashing.Hmac(K, s.suite.Hash(), V); err != nil {
		return nil, errs.WrapHashing(err, "could not produce HMAC for V")
	}
	// step 2.h
	var k uint256.Uint256
iterate_k:
	var T []byte
	for {
		// step 2.h.2
		if V, err = hashing.Hmac(K, s.suite.Hash(), V); err != nil {
			return nil, errs.WrapHashing(err, "could not produce HMAC for V")
		}
		T = append(T, V...)
		// step 2.h.3
		k = ecdsa.BitsToInt(T, s.suite.Curve())
		if k.Cmp(qUint) < 0 {
			break
		}
		K, err = hashing.Hmac(K, s.suite.Hash(), V, []byte{0x00})
		if err != nil {
			return nil, errs.WrapHashing(err, "could not produce HMAC for K")
		}
		V, err = hashing.Hmac(K, s.suite.Hash(), V)
		if err != nil {
			return nil, errs.WrapHashing(err, "could not produce HMAC for V")
		}
	}
	// step 3: calculate R
	kScalar, err := s.suite.Curve().ScalarField().Element().SetBytes(k.Bytes())
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not convert k to scalar")
	}
	R := s.suite.Curve().ScalarBaseMult(kScalar)
	r, err := s.suite.Curve().ScalarField().Element().SetBytesWide(R.AffineX().Bytes())
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not convert R.X to scalar")
	}
	if r.IsZero() {
		goto iterate_k
	}
	// step 4: calculate  s = (h+x*r)/k mod q
	hScalar, err := s.suite.Curve().ScalarField().Element().SetBytes(hBytes)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not convert h to scalar")
	}
	S, err := hScalar.Add(s.privateKey.Mul(r)).Div(kScalar)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not calculate S")
	}
	v, err := ecdsa.CalculateRecoveryId(R)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not calculate recovery id")
	}
	return &ecdsa.Signature{V: &v, R: r, S: S}, nil
}

// int2octets converts an integer to an octet string following the conversion
// from RFC 6979, section 2.3.3.
func (s *Signer) int2octets(a []byte) []byte {
	// Limit to ceil(|q| / 8) bytes
	rlen := (s.suite.Curve().Order().BitLen() + 7) / 8
	if len(a) > rlen {
		a = a[len(a)-rlen:]
	} else if len(a) < rlen {
		a = bitstring.PadToLeft(a, rlen-len(a))
	}
	return a
}
