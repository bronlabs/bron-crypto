package paillier

import (
	"encoding"
	"encoding/hex"
	"encoding/json"
	"io"

	"github.com/cronokirby/saferith"
	"golang.org/x/sync/errgroup"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/modular"
	"github.com/bronlabs/bron-crypto/pkg/indcpa"
)

var (
	_ indcpa.EncryptionKey[*PlainText, *Nonce, *CipherText] = (*PublicKey)(nil)
	_ json.Marshaler                                        = (*PublicKey)(nil)
	_ json.Unmarshaler                                      = (*PublicKey)(nil)
	_ encoding.BinaryMarshaler                              = (*PublicKey)(nil)
	_ encoding.BinaryUnmarshaler                            = (*PublicKey)(nil)
)

type PublicKey struct {
	N  *saferith.Modulus
	nn *saferith.Modulus
}

func NewPublicKey(n *saferith.Nat) (*PublicKey, error) {
	if n == nil {
		return nil, errs.NewIsNil("n")
	}

	pk := &PublicKey{N: saferith.ModulusFromNat(n)}
	pk.precompute()

	return pk, nil
}

func (pk *PublicKey) Equal(rhs *PublicKey) bool {
	if pk == nil || rhs == nil {
		return pk == rhs
	}

	return pk.N.Nat().Eq(rhs.N.Nat()) == 1
}

func (pk *PublicKey) Validate() error {
	if pk == nil {
		return errs.NewIsNil("sk is nil")
	}
	if pk.N.Nat().Byte(0)%2 != 1 {
		return errs.NewValidation("N is even")
	}

	return nil
}

func (pk *PublicKey) RandomPlaintext(prng io.Reader) (plaintext *PlainText, err error) {
	plaintextBytes := make([]byte, (pk.N.BitLen()+128)/8)
	_, err = io.ReadFull(prng, plaintextBytes)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "failed to generate plaintext")
	}
	plaintextNat := new(saferith.Nat).SetBytes(plaintextBytes)
	plaintext = new(PlainText).SetModSymmetric(plaintextNat, pk.N)
	return plaintext, nil
}

func (pk *PublicKey) RandomNonce(prng io.Reader) (nonce *Nonce, err error) {
	nonceBytes := make([]byte, (pk.N.BitLen()+128)/8)
	nonce = new(Nonce)

	for {
		_, err = io.ReadFull(prng, nonceBytes)
		if err != nil {
			return nil, errs.WrapRandomSample(err, "failed to generate nonce")
		}
		nonce.SetBytes(nonceBytes)
		nonce.Mod(nonce, pk.N)
		if (nonce.Eq(one) | (nonce.IsUnit(pk.N) ^ 1)) != 0 {
			continue
		}

		return nonce, nil
	}
}

func (pk *PublicKey) RandomCiphertext(prng io.Reader) (ciphertext *CipherText, err error) {
	ciphertextBytes := make([]byte, (pk.nn.BitLen()+128)/8)
	ciphertext = new(CipherText)

	for {
		_, err = io.ReadFull(prng, ciphertextBytes)
		if err != nil {
			return nil, errs.WrapRandomSample(err, "failed to generate nonce")
		}
		ciphertext.C.SetBytes(ciphertextBytes)
		ciphertext.C.Mod(&ciphertext.C, pk.nn)
		if ciphertext.C.IsUnit(pk.N) == 0 {
			continue
		}

		return ciphertext, nil
	}
}

func (pk *PublicKey) EncryptWithNonce(plainText *PlainText, nonce *Nonce) (cipherText *CipherText, err error) {
	if !pk.validPlaintext(plainText) {
		return nil, errs.NewValidation("invalid plaintext")
	}
	if !pk.validNonce(nonce) {
		return nil, errs.NewValidation("invalid nonce")
	}

	gToM := pk.gToM(plainText)
	rToN, err := pk.rToN(nonce)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to encrypt plaintext")
	}

	c := new(CipherText)
	c.C.ModMul(gToM, rToN, pk.nn)
	return c, nil
}

func (pk *PublicKey) Encrypt(plainText *PlainText, prng io.Reader) (cipherText *CipherText, nonce *Nonce, err error) {
	if prng == nil {
		return nil, nil, errs.NewIsNil("prng")
	}
	if !pk.validPlaintext(plainText) {
		return nil, nil, errs.NewValidation("invalid plaintext")
	}

	r, err := pk.RandomNonce(prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "failed to generate random nonce")
	}

	c, err := pk.EncryptWithNonce(plainText, r)
	if err != nil {
		return nil, nil, err
	}

	return c, r, nil
}

func (pk *PublicKey) EncryptManyWithNonce(plainTexts []*PlainText, nonces []*saferith.Nat) ([]*CipherText, error) {
	if len(plainTexts) != len(nonces) {
		return nil, errs.NewValidation("length mismatch")
	}

	ciphertexts := make([]*CipherText, len(plainTexts))
	var eg errgroup.Group
	for i, p := range plainTexts {
		eg.Go(func() error {
			var err error
			ciphertexts[i], err = pk.EncryptWithNonce(p, nonces[i])
			return err
		})
	}
	err := eg.Wait()
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to encrypt plaintexts")
	}

	return ciphertexts, nil
}

func (pk *PublicKey) EncryptMany(plainTexts []*PlainText, prng io.Reader) ([]*CipherText, []*saferith.Nat, error) {
	nonces := make([]*Nonce, len(plainTexts))
	for i := range plainTexts {
		var err error
		nonces[i], err = pk.RandomNonce(prng)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "failed to generate random nonce")
		}
	}

	ciphertexts, err := pk.EncryptManyWithNonce(plainTexts, nonces)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "failed to encrypt plaintexts")
	}

	return ciphertexts, nonces, nil
}

func (pk *PublicKey) CipherTextEqual(lhs, rhs *CipherText) bool {
	if lhs == nil || rhs == nil {
		return lhs == rhs
	}

	return pk.validCiphertext(lhs) && pk.validCiphertext(rhs) && lhs.C.Eq(&rhs.C) != 0
}

func (pk *PublicKey) MarshalJSON() ([]byte, error) {
	nBytes, err := pk.N.MarshalBinary()
	if err != nil {
		return nil, errs.WrapSerialisation(err, "failed to serialise public key")
	}
	pkJson := &publicKeyJson{N: hex.EncodeToString(nBytes)}
	data, err := json.Marshal(pkJson)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "failed to serialise public key")
	}

	return data, nil
}

func (pk *PublicKey) UnmarshalJSON(bytes []byte) error {
	var pkJson publicKeyJson
	err := json.Unmarshal(bytes, &pkJson)
	if err != nil {
		return errs.WrapFailed(err, "failed to deserialise public key")
	}
	nBytes, err := hex.DecodeString(pkJson.N)
	if err != nil {
		return errs.WrapSerialisation(err, "failed to decode n")
	}

	pk.N = new(saferith.Modulus)
	err = pk.N.UnmarshalBinary(nBytes)
	if err != nil {
		return errs.WrapSerialisation(err, "failed to decode n")
	}
	pk.precompute()
	return nil
}

func (pk *PublicKey) MarshalBinary() (data []byte, err error) {
	data, err = pk.N.MarshalBinary()
	if err != nil {
		return nil, errs.WrapSerialisation(err, "failed to encode n")
	}

	return data, nil
}

func (pk *PublicKey) UnmarshalBinary(data []byte) error {
	pk.N = new(saferith.Modulus)
	err := pk.N.UnmarshalBinary(data)
	if err != nil {
		return errs.WrapSerialisation(err, "failed to decode public key")
	}
	pk.precompute()
	return nil
}

func (pk *PublicKey) gToM(m *saferith.Int) *saferith.Nat {
	mNat := m.Mod(pk.N)
	gm := new(saferith.Nat).Mul(pk.N.Nat(), mNat, pk.nn.BitLen())
	gmp1 := gm.Add(gm, new(saferith.Nat).SetUint64(1).Resize(1), pk.nn.BitLen())
	gToM := gmp1.Mod(gmp1, pk.nn)
	return gToM
}

func (pk *PublicKey) rToN(r *saferith.Nat) (*saferith.Nat, error) {
	r, err := modular.FastExp(r, pk.N.Nat(), pk.nn)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to compute r^N")
	}

	return r, nil
}

func (pk *PublicKey) validPlaintext(plainText *PlainText) bool {
	if plainText == nil || plainText.CheckInRange(pk.N) == 0 {
		return false
	}

	return true
}

func (pk *PublicKey) validNonce(nonce *Nonce) bool {
	if nonce == nil {
		return false
	}
	_, _, l := nonce.CmpMod(pk.N)
	if l == 0 || nonce.IsUnit(pk.N) == 0 {
		return false
	}

	return true
}

func (pk *PublicKey) validCiphertext(cipherText *CipherText) bool {
	if cipherText == nil {
		return false
	}
	_, _, l := cipherText.C.CmpMod(pk.nn)
	if l == 0 || cipherText.C.IsUnit(pk.N) == 0 {
		return false
	}

	return true
}

func (pk *PublicKey) precompute() {
	nn := new(saferith.Nat).Mul(pk.N.Nat(), pk.N.Nat(), -1)
	pk.nn = saferith.ModulusFromNat(nn)
}

type publicKeyJson struct {
	N string `json:"n"`
}
