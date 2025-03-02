package paillier

import (
	"encoding/hex"
	"encoding/json"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/base/primes"
	"github.com/cronokirby/saferith"
	"io"
)

var (
	_ json.Marshaler   = (*CipherText)(nil)
	_ json.Unmarshaler = (*CipherText)(nil)
)

type PlainText = saferith.Int
type Nonce = saferith.Nat
type Scalar = saferith.Int

type CipherText struct {
	C saferith.Nat
}

func (ct *CipherText) MarshalJSON() ([]byte, error) {
	ctBytes, err := ct.C.MarshalBinary()
	if err != nil {
		return nil, err
	}
	ctStr := hex.EncodeToString(ctBytes)
	return json.Marshal(ctStr)
}

func (ct *CipherText) UnmarshalJSON(bytes []byte) error {
	var ctStr string
	if err := json.Unmarshal(bytes, &ctStr); err != nil {
		return err
	}
	ctBytes, err := hex.DecodeString(ctStr)
	if err != nil {
		return errs.WrapSerialisation(err, "invalid ciphertext format")
	}

	if err := ct.C.UnmarshalBinary(ctBytes); err != nil {
		return err
	}

	return nil
}

func (ct *CipherText) Equal(rhs *CipherText) bool {
	if ct == nil || rhs == nil {
		return ct == rhs
	}

	return ct.C.Eq(&rhs.C) != 0
}

func (ct *CipherText) Validate(pk *PublicKey) error {
	if ct == nil {
		return errs.NewValidation("ciphertext is nil")
	}

	if _, _, l := ct.C.Cmp(pk.nn.Nat()); l == 0 {
		return errs.NewValidation("invalid ciphertext")
	}
	if ct.C.IsUnit(pk.nn) == 0 {
		return errs.NewValidation("invalid ciphertext")
	}

	return nil
}

func KeyGenWithPrimeGenerator(bits int, prng io.Reader, primeGen func(bits int, prng io.Reader) (p, q *saferith.Nat, err error)) (*PublicKey, *SecretKey, error) {
	p, q, err := primeGen(bits/2, prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "keygen failed")
	}

	sk, err := NewSecretKey(p, q)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "keygen failed")
	}

	return &sk.PublicKey, sk, nil
}

func KeyGen(bits int, prng io.Reader) (*PublicKey, *SecretKey, error) {
	return KeyGenWithPrimeGenerator(bits, prng, primes.GeneratePrimePair)
}
