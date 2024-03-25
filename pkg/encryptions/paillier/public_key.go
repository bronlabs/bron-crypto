package paillier

import (
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

type PublicKeyPrecomputed struct {
	NModulus  *saferith.Modulus
	NNModulus *saferith.Modulus
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

func (pk *PublicKey) GetPrecomputed() *PublicKeyPrecomputed {
	pk.precomputedOnce.Do(func() { pk.precompute() })

	return pk.precomputed
}

func (pk *PublicKey) Add(lhs, rhs *CipherText) (*CipherText, error) {
	if err := lhs.Validate(pk); err != nil {
		return nil, errs.WrapFailed(err, "invalid lhs")
	}
	if err := rhs.Validate(pk); err != nil {
		return nil, errs.WrapFailed(err, "invalid rhs")
	}

	n2 := pk.GetPrecomputed().NNModulus

	return &CipherText{
		C: new(saferith.Nat).ModMul(lhs.C, rhs.C, n2),
	}, nil
}

func (pk *PublicKey) AddPlaintext(lhs *CipherText, rhs *PlainText) (*CipherText, error) {
	if err := lhs.Validate(pk); err != nil {
		return nil, errs.WrapFailed(err, "invalid lhs")
	}
	if rhs == nil || !isLess(rhs, pk.N) {
		return nil, errs.NewFailed("invalid rhs")
	}

	nnModulus := pk.GetPrecomputed().NNModulus
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

	n2 := pk.GetPrecomputed().NNModulus
	rhsInv := new(saferith.Nat).ModInverse(rhs.C, n2)
	result := new(saferith.Nat).ModMul(lhs.C, rhsInv, n2)

	return &CipherText{
		C: result,
	}, nil
}

func (pk *PublicKey) SubPlaintext(lhs *CipherText, rhs *PlainText) (*CipherText, error) {
	if err := lhs.Validate(pk); err != nil {
		return nil, errs.WrapFailed(err, "invalid lhs")
	}
	if rhs == nil || !isLess(rhs, pk.N) {
		return nil, errs.NewFailed("invalid rhs")
	}

	nnModulus := pk.GetPrecomputed().NNModulus
	n := pk.GetPrecomputed().NModulus
	rhsNeg := new(saferith.Nat).ModNeg(rhs, n)
	rhsCInv := new(saferith.Nat).ModAdd(new(saferith.Nat).ModMul(pk.N, rhsNeg, nnModulus), natOne, nnModulus)
	result := new(saferith.Nat).ModMul(lhs.C, rhsCInv, nnModulus)

	return &CipherText{
		C: result,
	}, nil
}

func (pk *PublicKey) MulPlaintext(lhs *CipherText, rhs *PlainText) (*CipherText, error) {
	if err := lhs.Validate(pk); err != nil {
		return nil, errs.WrapFailed(err, "invalid lhs")
	}
	if rhs == nil || !isLess(rhs, pk.N) {
		return nil, errs.NewFailed("invalid rhs")
	}

	n2 := pk.GetPrecomputed().NNModulus
	result := new(saferith.Nat).Exp(lhs.C, rhs, n2)
	return &CipherText{
		C: result,
	}, nil
}

func (pk *PublicKey) EncryptWithNonce(plainText *PlainText, nonce *saferith.Nat) (*CipherText, error) {
	if plainText == nil || !isLess(plainText, pk.N) {
		return nil, errs.NewFailed("invalid plainText")
	}
	n := pk.GetPrecomputed().NModulus
	if nonce == nil || nonce.EqZero() == 1 || !isLess(nonce, pk.N) || nonce.IsUnit(n) != 1 {
		return nil, errs.NewFailed("invalid nonce")
	}

	nnModulus := pk.GetPrecomputed().NNModulus
	gToM := new(saferith.Nat).ModAdd(new(saferith.Nat).ModMul(plainText, pk.N, nnModulus), natOne, nnModulus)
	rToN := new(saferith.Nat).Exp(nonce, pk.N, nnModulus)
	cipherText := new(saferith.Nat).ModMul(gToM, rToN, nnModulus)

	return &CipherText{
		C: cipherText,
	}, nil
}

func (pk *PublicKey) Encrypt(plainText *PlainText, prng io.Reader) (*CipherText, *saferith.Nat, error) {
	if prng == nil {
		return nil, nil, errs.NewIsNil("prng")
	}
	if plainText == nil || !isLess(plainText, pk.N) {
		return nil, nil, errs.NewFailed("invalid plainText")
	}

	n := pk.GetPrecomputed().NModulus
	var nonce *saferith.Nat
	for {
		nonceBig, err := crand.Int(prng, pk.N.Big())
		if err != nil {
			return nil, nil, errs.NewRandomSample("cannot sample nonce")
		}
		nonce = new(saferith.Nat).SetBig(nonceBig, pk.N.AnnouncedLen())
		if nonce.EqZero() != 1 && nonce.IsUnit(n) == 1 {
			break
		}
	}

	cipherText, err := pk.EncryptWithNonce(plainText, nonce)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot encrypt")
	}

	return cipherText, nonce, nil
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
		NModulus:  nMod,
		NNModulus: nnMod,
	}
}

func isLess(l, r *saferith.Nat) bool {
	_, _, less := l.Cmp(r)
	return less == 1
}
