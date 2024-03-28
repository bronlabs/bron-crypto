package paillier

import (
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"github.com/copperexchange/krypton-primitives/pkg/base/saferith_ex"
	"io"
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils"
)

type PublicKeyPrecomputed struct {
	nMod  saferith_ex.Modulus
	nnMod saferith_ex.Modulus
}

type PublicKey struct {
	N               *saferith.Nat
	precomputed     *PublicKeyPrecomputed
	precomputedOnce sync.Once
}

type publicKeyJson struct {
	N string `json:"n"`
}

var _ json.Marshaler = (*PublicKey)(nil)
var _ json.Unmarshaler = (*PublicKey)(nil)

func NewPublicKey(n *saferith.Nat) (*PublicKey, error) {
	if n == nil {
		return nil, errs.NewIsNil("n")
	}

	pk := &PublicKey{N: n}
	pk.precompute()
	return pk, nil
}

func (pk *PublicKey) GetNModulus() saferith_ex.Modulus {
	pk.precomputedOnce.Do(func() { pk.precompute() })
	return pk.precomputed.nMod
}

func (pk *PublicKey) GetNNModulus() saferith_ex.Modulus {
	pk.precomputedOnce.Do(func() { pk.precompute() })
	return pk.precomputed.nnMod
}

func (pk *PublicKey) Add(lhs, rhs *CipherText) (*CipherText, error) {
	if err := lhs.Validate(pk); err != nil {
		return nil, errs.WrapValidation(err, "invalid lhs")
	}
	if err := rhs.Validate(pk); err != nil {
		return nil, errs.WrapValidation(err, "invalid rhs")
	}

	nnMod := pk.GetNNModulus()

	return &CipherText{
		C: new(saferith.Nat).ModMul(lhs.C, rhs.C, nnMod.Modulus()),
	}, nil
}

func (pk *PublicKey) AddPlaintext(lhs *CipherText, rhs *PlainText) (*CipherText, error) {
	if err := lhs.Validate(pk); err != nil {
		return nil, errs.WrapValidation(err, "invalid lhs")
	}
	if rhs == nil || !utils.IsLess(rhs, pk.N) {
		return nil, errs.NewValidation("invalid rhs")
	}

	nnModulus := pk.GetNNModulus()
	rhsC := new(saferith.Nat).ModAdd(new(saferith.Nat).ModMul(pk.N, rhs, nnModulus.Modulus()), natOne, nnModulus.Modulus())
	result := new(saferith.Nat).ModMul(lhs.C, rhsC, nnModulus.Modulus())

	return &CipherText{
		C: result,
	}, nil
}

func (pk *PublicKey) Sub(lhs, rhs *CipherText) (*CipherText, error) {
	if err := lhs.Validate(pk); err != nil {
		return nil, errs.WrapValidation(err, "invalid lhs")
	}
	if err := rhs.Validate(pk); err != nil {
		return nil, errs.WrapValidation(err, "invalid rhs")
	}

	nnMod := pk.GetNNModulus()
	rhsInv := new(saferith.Nat).ModInverse(rhs.C, nnMod.Modulus())
	result := new(saferith.Nat).ModMul(lhs.C, rhsInv, nnMod.Modulus())

	return &CipherText{
		C: result,
	}, nil
}

func (pk *PublicKey) SubPlaintext(lhs *CipherText, rhs *PlainText) (*CipherText, error) {
	if err := lhs.Validate(pk); err != nil {
		return nil, errs.WrapValidation(err, "invalid lhs")
	}
	if rhs == nil || !utils.IsLess(rhs, pk.N) {
		return nil, errs.NewValidation("invalid rhs")
	}

	nnMod := pk.GetNNModulus()
	nMod := pk.GetNModulus()
	rhsNeg := new(saferith.Nat).ModNeg(rhs, nMod.Modulus())
	rhsCInv := new(saferith.Nat).ModAdd(new(saferith.Nat).ModMul(pk.N, rhsNeg, nnMod.Modulus()), natOne, nnMod.Modulus())
	result := new(saferith.Nat).ModMul(lhs.C, rhsCInv, nnMod.Modulus())

	return &CipherText{
		C: result,
	}, nil
}

func (pk *PublicKey) MulPlaintext(lhs *CipherText, rhs *PlainText) (*CipherText, error) {
	if err := lhs.Validate(pk); err != nil {
		return nil, errs.WrapFailed(err, "invalid lhs")
	}
	if rhs == nil || !utils.IsLess(rhs, pk.N) {
		return nil, errs.NewFailed("invalid rhs")
	}

	nnMod := pk.GetNNModulus()
	result := nnMod.Exp(lhs.C, rhs)
	return &CipherText{
		C: result,
	}, nil
}

func (pk *PublicKey) EncryptWithNonce(plainText *PlainText, nonce *saferith.Nat) (*CipherText, error) {
	if plainText == nil || !utils.IsLess(plainText, pk.N) {
		return nil, errs.NewValidation("invalid plainText")
	}
	nMod := pk.GetNModulus()
	if nonce == nil || nonce.EqZero() == 1 || !utils.IsLess(nonce, pk.N) || nonce.IsUnit(nMod.Modulus()) != 1 {
		return nil, errs.NewValidation("invalid nonce")
	}

	nnMod := pk.GetNNModulus()
	gToM := new(saferith.Nat).ModAdd(new(saferith.Nat).ModMul(plainText, pk.N, nnMod.Modulus()), natOne, nnMod.Modulus())
	rToN := nnMod.Exp(nonce, pk.N)
	cipherText := new(saferith.Nat).ModMul(gToM, rToN, nnMod.Modulus())

	return &CipherText{
		C: cipherText,
	}, nil
}

func (pk *PublicKey) EncryptManyWithNonce(plainTexts []*PlainText, nonces []*saferith.Nat) ([]*CipherText, error) {
	if plainTexts == nil {
		return nil, errs.NewValidation("invalid plainText")
	}
	for _, p := range plainTexts {
		if !utils.IsLess(p, pk.N) {
			return nil, errs.NewValidation("invalid plainText")
		}
	}

	nMod := pk.GetNModulus()
	if nonces == nil || len(nonces) != len(plainTexts) {
		return nil, errs.NewValidation("invalid nonce")
	}
	for _, r := range nonces {
		if r.EqZero() == 1 || !utils.IsLess(r, pk.N) || r.IsUnit(nMod.Modulus()) != 1 {
			return nil, errs.NewValidation("invalid nonce")
		}
	}

	nnMod := pk.GetNNModulus()
	rToN := nnMod.MultiBaseExp(nonces, pk.N)

	cipherTexts := make([]*CipherText, len(plainTexts))
	for i, p := range plainTexts {
		gToM := new(saferith.Nat).ModAdd(new(saferith.Nat).ModMul(p, pk.N, nnMod.Modulus()), natOne, nnMod.Modulus())
		cipherTexts[i] = &CipherText{C: new(saferith.Nat).ModMul(gToM, rToN[i], nnMod.Modulus())}
	}

	return cipherTexts, nil
}

func (pk *PublicKey) Encrypt(plainText *PlainText, prng io.Reader) (*CipherText, *saferith.Nat, error) {
	if prng == nil {
		return nil, nil, errs.NewIsNil("prng")
	}
	if plainText == nil || !utils.IsLess(plainText, pk.N) {
		return nil, nil, errs.NewValidation("invalid plainText")
	}

	nMod := pk.GetNModulus()
	var nonce *saferith.Nat
	for {
		nonceBig, err := crand.Int(prng, pk.N.Big())
		if err != nil {
			return nil, nil, errs.NewRandomSample("cannot sample nonce")
		}
		nonce = new(saferith.Nat).SetBig(nonceBig, pk.N.AnnouncedLen())
		if nonce.EqZero() != 1 && nonce.IsUnit(nMod.Modulus()) == 1 {
			break
		}
	}

	cipherText, err := pk.EncryptWithNonce(plainText, nonce)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot encrypt")
	}

	return cipherText, nonce, nil
}

func (pk *PublicKey) EncryptMany(plainTexts []*PlainText, prng io.Reader) ([]*CipherText, []*saferith.Nat, error) {
	if prng == nil {
		return nil, nil, errs.NewIsNil("prng")
	}
	if plainTexts == nil {
		return nil, nil, errs.NewValidation("invalid plainText")
	}
	for _, p := range plainTexts {
		if !utils.IsLess(p, pk.N) {
			return nil, nil, errs.NewValidation("invalid plainText")
		}
	}

	nMod := pk.GetNModulus()
	nonces := make([]*saferith.Nat, len(plainTexts))
	for i := 0; i < len(plainTexts); i++ {
		for {
			nonceBig, err := crand.Int(prng, pk.N.Big())
			if err != nil {
				return nil, nil, errs.NewRandomSample("cannot sample nonce")
			}
			nonces[i] = new(saferith.Nat).SetBig(nonceBig, pk.N.AnnouncedLen())
			if nonces[i].EqZero() != 1 && nonces[i].IsUnit(nMod.Modulus()) == 1 {
				break
			}
		}
	}

	cipherTexts, err := pk.EncryptManyWithNonce(plainTexts, nonces)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot encrypt")
	}

	return cipherTexts, nonces, nil
}

func (pk *PublicKey) MarshalJSON() ([]byte, error) {
	val := &publicKeyJson{N: hex.EncodeToString(pk.N.Bytes())}
	ret, err := json.Marshal(val)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "marshal failed")
	}

	return ret, nil
}

func (pk *PublicKey) UnmarshalJSON(bytes []byte) error {
	var val publicKeyJson
	err := json.Unmarshal(bytes, &val)
	if err != nil {
		return errs.WrapSerialisation(err, "unmarshal failed")
	}
	nBytes, err := hex.DecodeString(val.N)
	if err != nil {
		return errs.WrapSerialisation(err, "unmarshal failed")
	}

	pk.N = new(saferith.Nat).SetBytes(nBytes)
	pk.precompute()
	return nil
}

func (pk *PublicKey) Validate() error {
	if pk == nil {
		return errs.NewIsNil("sk")
	}
	if pk.N == nil {
		return errs.NewIsNil("n")
	}

	return nil
}

func (pk *PublicKey) precompute() {
	nn := new(saferith.Nat).Mul(pk.N, pk.N, -1)

	nMod, err := saferith_ex.NewOddModulus(pk.N)
	if err != nil {
		panic(err)
	}
	nnMod, err := saferith_ex.NewOddModulus(nn)
	if err != nil {
		panic(err)
	}

	pk.precomputed = &PublicKeyPrecomputed{
		nMod:  nMod,
		nnMod: nnMod,
	}
}
