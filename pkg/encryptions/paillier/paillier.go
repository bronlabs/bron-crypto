package paillier

import (
	"encoding/hex"
	"encoding/json"
	"io"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/base/primes"
	saferithUtils "github.com/bronlabs/krypton-primitives/pkg/base/utils/saferith"
)

type PlainText = saferith.Nat

var _ json.Marshaler = (*CipherText)(nil)

type CipherText struct {
	C *saferith.Nat
}

type cipherTextJson struct {
	C string `json:"c"`
}

func (c *CipherText) Equal(other *CipherText) bool {
	return other != nil && c.C != nil && c.C.Eq(other.C) == 1
}

func (c *CipherText) Validate(pk *PublicKey) error {
	if c == nil || c.C == nil || c.C.EqZero() == 1 || c.C.Coprime(pk.N) != 1 {
		return errs.NewValidation("invalid cipher text: %v", c.C)
	}

	nnMod, err := pk.GetNNResidueParams()
	if err != nil {
		return errs.WrapValidation(err, "invalid pk")
	}

	if !saferithUtils.NatIsLess(c.C, nnMod.GetModulus().Nat()) {
		return errs.NewValidation("invalid cipher text")
	}

	return nil
}

func (c *CipherText) MarshalJSON() ([]byte, error) {
	out, err := json.Marshal(&cipherTextJson{
		C: hex.EncodeToString(c.C.Bytes()),
	})
	if err != nil {
		return nil, errs.WrapSerialisation(err, "marshal failed")
	}
	return out, nil
}

func (c *CipherText) UnmarshalJSON(data []byte) error {
	var jsonCipherText cipherTextJson
	if err := json.Unmarshal(data, &jsonCipherText); err != nil {
		return errs.WrapSerialisation(err, "unmarshal failed")
	}
	cBytes, err := hex.DecodeString(jsonCipherText.C)
	if err != nil {
		return errs.WrapSerialisation(err, "could not set bytes")
	}
	c.C = new(saferith.Nat).SetBytes(cBytes)
	return nil
}

func KeyGenWithPrimeGenerator(bits int, prng io.Reader, primeGen func(bits int, prng io.Reader) (p, q *saferith.Nat, err error)) (*PublicKey, *SecretKey, error) {
	p, q, err := primeGen(bits, prng)
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
