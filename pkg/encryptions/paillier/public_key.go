package paillier

import (
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"github.com/copperexchange/krypton-primitives/pkg/base/bignum"
	"io"
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils"
)

type PublicKeyPrecomputed struct {
	nModulus  *saferith.Modulus
	nnModulus *saferith.Modulus
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

func (pk *PublicKey) GetNModulus() *saferith.Modulus {
	pk.precomputedOnce.Do(func() { pk.precompute() })
	return pk.precomputed.nModulus
}

func (pk *PublicKey) GetNNModulus() *saferith.Modulus {
	pk.precomputedOnce.Do(func() { pk.precompute() })
	return pk.precomputed.nnModulus
}

func (pk *PublicKey) Add(lhs, rhs *CipherText) (*CipherText, error) {
	if err := lhs.Validate(pk); err != nil {
		return nil, errs.WrapFailed(err, "invalid lhs")
	}
	if err := rhs.Validate(pk); err != nil {
		return nil, errs.WrapFailed(err, "invalid rhs")
	}

	nnMod := pk.GetNNModulus()

	return &CipherText{
		C: new(saferith.Nat).ModMul(lhs.C, rhs.C, nnMod),
	}, nil
}

func (pk *PublicKey) AddPlaintext(lhs *CipherText, rhs *PlainText) (*CipherText, error) {
	if err := lhs.Validate(pk); err != nil {
		return nil, errs.WrapFailed(err, "invalid lhs")
	}
	if rhs == nil || !utils.IsLess(rhs, pk.N) {
		return nil, errs.NewFailed("invalid rhs")
	}

	nnModulus := pk.GetNNModulus()
	rhsC := new(saferith.Nat).ModAdd(new(saferith.Nat).ModMul(pk.N, rhs, nnModulus), natOne, nnModulus)
	result := new(saferith.Nat).ModMul(lhs.C, rhsC, nnModulus)

	return &CipherText{
		C: result,
	}, nil
}

func (pk *PublicKey) Sub(lhs, rhs *CipherText) (*CipherText, error) {
	if err := lhs.Validate(pk); err != nil {
		return nil, errs.WrapFailed(err, "invalid lhs")
	}
	if err := rhs.Validate(pk); err != nil {
		return nil, errs.WrapFailed(err, "invalid rhs")
	}

	nnMod := pk.GetNNModulus()
	rhsInv := new(saferith.Nat).ModInverse(rhs.C, nnMod)
	result := new(saferith.Nat).ModMul(lhs.C, rhsInv, nnMod)

	return &CipherText{
		C: result,
	}, nil
}

func (pk *PublicKey) SubPlaintext(lhs *CipherText, rhs *PlainText) (*CipherText, error) {
	if err := lhs.Validate(pk); err != nil {
		return nil, errs.WrapFailed(err, "invalid lhs")
	}
	if rhs == nil || !utils.IsLess(rhs, pk.N) {
		return nil, errs.NewFailed("invalid rhs")
	}

	nnMod := pk.GetNNModulus()
	nMod := pk.GetNModulus()
	rhsNeg := new(saferith.Nat).ModNeg(rhs, nMod)
	rhsCInv := new(saferith.Nat).ModAdd(new(saferith.Nat).ModMul(pk.N, rhsNeg, nnMod), natOne, nnMod)
	result := new(saferith.Nat).ModMul(lhs.C, rhsCInv, nnMod)

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
	result := bignum.FastExp(lhs.C, rhs, nnMod.Nat())
	return &CipherText{
		C: result,
	}, nil
}

func (pk *PublicKey) EncryptWithNonce(plainText *PlainText, nonce *saferith.Nat) (*CipherText, error) {
	if plainText == nil || !utils.IsLess(plainText, pk.N) {
		return nil, errs.NewFailed("invalid plainText")
	}
	nMod := pk.GetNModulus()
	if nonce == nil || nonce.EqZero() == 1 || !utils.IsLess(nonce, pk.N) || nonce.IsUnit(nMod) != 1 {
		return nil, errs.NewFailed("invalid nonce")
	}

	nnMod := pk.GetNNModulus()
	gToM := new(saferith.Nat).ModAdd(new(saferith.Nat).ModMul(plainText, pk.N, nnMod), natOne, nnMod)
	rToN := bignum.FastExp(nonce, pk.N, nnMod.Nat())
	cipherText := new(saferith.Nat).ModMul(gToM, rToN, nnMod)

	return &CipherText{
		C: cipherText,
	}, nil
}

func (pk *PublicKey) EncryptManyWithNonce(plainTexts []*PlainText, rs []*saferith.Nat) ([]*CipherText, error) {
	if len(plainTexts) != len(rs) {
		return nil, errs.NewIsNil("message or nonce mismatch")
	}

	for _, plainText := range plainTexts {
		if plainText == nil || !utils.IsLess(plainText, pk.N) {
			return nil, errs.NewFailed("invalid plainText")
		}
	}

	nMod := pk.GetNModulus()
	for _, r := range rs {
		if r == nil || r.EqZero() == 1 || !utils.IsLess(r, pk.N) || r.IsUnit(nMod) != 1 {
			return nil, errs.NewFailed("invalid nonce")
		}
	}

	nnMod := pk.GetNNModulus()
	gToMs := make([]*saferith.Nat, len(plainTexts))
	for i, plainText := range plainTexts {
		gToMs[i] = new(saferith.Nat).ModAdd(new(saferith.Nat).ModMul(plainText, pk.N, nnMod), natOne, nnMod)
	}
	rToNs := bignum.FastFixedExponentMultiExp(rs, pk.N, pk.GetNNModulus().Nat())

	cs := make([]*CipherText, len(plainTexts))
	for i := range plainTexts {
		cs[i] = &CipherText{C: new(saferith.Nat).ModMul(gToMs[i], rToNs[i], pk.GetNNModulus())}
	}

	return cs, nil
}

func (pk *PublicKey) Encrypt(plainText *PlainText, prng io.Reader) (*CipherText, *saferith.Nat, error) {
	if prng == nil {
		return nil, nil, errs.NewIsNil("prng")
	}
	if plainText == nil || !utils.IsLess(plainText, pk.N) {
		return nil, nil, errs.NewFailed("invalid plainText")
	}

	nMod := pk.GetNModulus()
	var nonce *saferith.Nat
	for {
		nonceBig, err := crand.Int(prng, pk.N.Big())
		if err != nil {
			return nil, nil, errs.NewRandomSample("cannot sample nonce")
		}
		nonce = new(saferith.Nat).SetBig(nonceBig, pk.N.AnnouncedLen())
		if nonce.EqZero() != 1 && nonce.IsUnit(nMod) == 1 {
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

	nonces := make([]*saferith.Nat, len(plainTexts))
	for i := range plainTexts {
		for {
			nonceCandidateBig, err := crand.Int(prng, pk.N.Big())
			if err != nil {
				return nil, nil, errs.WrapFailed(err, "cannot generate nonce")
			}
			nonceCandidate := new(saferith.Nat).SetBig(nonceCandidateBig, pk.N.AnnouncedLen())
			if nonceCandidate.IsUnit(pk.GetNModulus()) != 1 || nonceCandidate.EqZero() == 1 {
				continue
			}
			nonces[i] = nonceCandidate
			break
		}
	}

	cipherTexts, err := pk.EncryptManyWithNonce(plainTexts, nonces)
	if err != nil {
		return nil, nil, errs.NewFailed("encryption failed")
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
	nMod := saferith.ModulusFromNat(pk.N)
	nn := new(saferith.Nat).Mul(pk.N, pk.N, -1)
	nnMod := saferith.ModulusFromNat(nn)
	pk.precomputed = &PublicKeyPrecomputed{
		nModulus:  nMod,
		nnModulus: nnMod,
	}
}
