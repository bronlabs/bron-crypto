package paillier

import (
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/modular"
	saferithUtils "github.com/copperexchange/krypton-primitives/pkg/base/utils/saferith"
)

type PublicKeyPrecomputed struct {
	nResidueParams  modular.ResidueParams
	nnResidueParams modular.ResidueParams
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
	err := pk.precompute()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot precompute")
	}

	return pk, nil
}

func (pk *PublicKey) Add(lhs, rhs *CipherText) (*CipherText, error) {
	if err := lhs.Validate(pk); err != nil {
		return nil, errs.WrapValidation(err, "invalid lhs")
	}
	if err := rhs.Validate(pk); err != nil {
		return nil, errs.WrapValidation(err, "invalid rhs")
	}

	nnMod, err := pk.GetNNResidueParams()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot get NN residue params")
	}

	return &CipherText{
		C: new(saferith.Nat).ModMul(lhs.C, rhs.C, nnMod.GetModulus()),
	}, nil
}

func (pk *PublicKey) AddPlaintext(lhs *CipherText, rhs *PlainText) (*CipherText, error) {
	if err := lhs.Validate(pk); err != nil {
		return nil, errs.WrapValidation(err, "invalid lhs")
	}
	if rhs == nil || !saferithUtils.NatIsLess(rhs, pk.N) {
		return nil, errs.NewValidation("invalid rhs")
	}

	nnMod, err := pk.GetNNResidueParams()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot get NN residue params")
	}

	rhsC := new(saferith.Nat).ModAdd(new(saferith.Nat).ModMul(pk.N, rhs, nnMod.GetModulus()), saferithUtils.NatOne, nnMod.GetModulus())
	result := new(saferith.Nat).ModMul(lhs.C, rhsC, nnMod.GetModulus())

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

	nnMod, err := pk.GetNNResidueParams()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot get NN residue params")
	}

	rhsInv := new(saferith.Nat).ModInverse(rhs.C, nnMod.GetModulus())
	result := new(saferith.Nat).ModMul(lhs.C, rhsInv, nnMod.GetModulus())

	return &CipherText{
		C: result,
	}, nil
}

func (pk *PublicKey) SubPlaintext(lhs *CipherText, rhs *PlainText) (*CipherText, error) {
	if err := lhs.Validate(pk); err != nil {
		return nil, errs.WrapValidation(err, "invalid lhs")
	}
	if rhs == nil || !saferithUtils.NatIsLess(rhs, pk.N) {
		return nil, errs.NewValidation("invalid rhs")
	}

	nnMod, err := pk.GetNNResidueParams()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot get NN residue params")
	}
	nMod, err := pk.GetNResidueParams()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot get N residue params")
	}

	rhsNeg := new(saferith.Nat).ModNeg(rhs, nMod.GetModulus())
	rhsCInv := new(saferith.Nat).ModAdd(new(saferith.Nat).ModMul(pk.N, rhsNeg, nnMod.GetModulus()), saferithUtils.NatOne, nnMod.GetModulus())
	result := new(saferith.Nat).ModMul(lhs.C, rhsCInv, nnMod.GetModulus())

	return &CipherText{
		C: result,
	}, nil
}

func (pk *PublicKey) MulPlaintext(lhs *CipherText, rhs *PlainText) (*CipherText, error) {
	if err := lhs.Validate(pk); err != nil {
		return nil, errs.WrapFailed(err, "invalid lhs")
	}
	if rhs == nil || !saferithUtils.NatIsLess(rhs, pk.N) {
		return nil, errs.NewFailed("invalid rhs")
	}

	nnMod, err := pk.GetNNResidueParams()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot get NN residue params")
	}

	result, err := nnMod.ModExp(lhs.C, rhs)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot compute exponent")
	}

	return &CipherText{
		C: result,
	}, nil
}

func (pk *PublicKey) EncryptWithNonce(plainText *PlainText, nonce *saferith.Nat) (*CipherText, error) {
	if plainText == nil || !saferithUtils.NatIsLess(plainText, pk.N) {
		return nil, errs.NewValidation("invalid plainText")
	}
	if nonce == nil || nonce.EqZero() == 1 || !saferithUtils.NatIsLess(nonce, pk.N) || nonce.Coprime(pk.N) != 1 {
		return nil, errs.NewValidation("invalid nonce")
	}

	nnMod, err := pk.GetNNResidueParams()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot get NN residue params")
	}

	gToM := new(saferith.Nat).ModAdd(new(saferith.Nat).ModMul(plainText, pk.N, nnMod.GetModulus()), saferithUtils.NatOne, nnMod.GetModulus())
	rToN, err := nnMod.ModExp(nonce, pk.N)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot compute exponent")
	}

	cipherText := new(saferith.Nat).ModMul(gToM, rToN, nnMod.GetModulus())

	return &CipherText{
		C: cipherText,
	}, nil
}

func (pk *PublicKey) EncryptManyWithNonce(plainTexts []*PlainText, nonces []*saferith.Nat) ([]*CipherText, error) {
	if plainTexts == nil {
		return nil, errs.NewValidation("invalid plainText")
	}
	for _, p := range plainTexts {
		if !saferithUtils.NatIsLess(p, pk.N) {
			return nil, errs.NewValidation("invalid plainText")
		}
	}

	if nonces == nil || len(nonces) != len(plainTexts) {
		return nil, errs.NewValidation("invalid nonce")
	}
	for _, r := range nonces {
		if r.EqZero() == 1 || !saferithUtils.NatIsLess(r, pk.N) || r.Coprime(pk.N) != 1 {
			return nil, errs.NewValidation("invalid nonce")
		}
	}

	nnMod, err := pk.GetNNResidueParams()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot get NN residue params")
	}

	rToN, err := nnMod.ModMultiBaseExp(nonces, pk.N)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot compute exp")
	}

	cipherTexts := make([]*CipherText, len(plainTexts))
	for i, p := range plainTexts {
		gToM := new(saferith.Nat).ModAdd(new(saferith.Nat).ModMul(p, pk.N, nnMod.GetModulus()), saferithUtils.NatOne, nnMod.GetModulus())
		cipherTexts[i] = &CipherText{C: new(saferith.Nat).ModMul(gToM, rToN[i], nnMod.GetModulus())}
	}

	return cipherTexts, nil
}

func (pk *PublicKey) Encrypt(plainText *PlainText, prng io.Reader) (*CipherText, *saferith.Nat, error) {
	if prng == nil {
		return nil, nil, errs.NewIsNil("prng")
	}
	if plainText == nil || !saferithUtils.NatIsLess(plainText, pk.N) {
		return nil, nil, errs.NewValidation("invalid plainText")
	}

	var nonce *saferith.Nat
	for {
		nonceBig, err := crand.Int(prng, pk.N.Big())
		if err != nil {
			return nil, nil, errs.NewRandomSample("cannot sample nonce")
		}
		nonce = new(saferith.Nat).SetBig(nonceBig, pk.N.AnnouncedLen())
		if nonce.EqZero() != 1 && nonce.Coprime(pk.N) == 1 {
			break
		}
	}

	cipherText, err := pk.EncryptWithNonce(plainText, nonce)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot encrypt")
	}

	return cipherText, nonce, nil
}

//nolint:dupl // required to use different variant of residue params
func (pk *PublicKey) EncryptMany(plainTexts []*PlainText, prng io.Reader) ([]*CipherText, []*saferith.Nat, error) {
	if prng == nil {
		return nil, nil, errs.NewIsNil("prng")
	}
	if plainTexts == nil {
		return nil, nil, errs.NewValidation("invalid plainText")
	}
	for _, p := range plainTexts {
		if !saferithUtils.NatIsLess(p, pk.N) {
			return nil, nil, errs.NewValidation("invalid plainText")
		}
	}

	nonces := make([]*saferith.Nat, len(plainTexts))
	for i := 0; i < len(plainTexts); i++ {
		for {
			nonceBig, err := crand.Int(prng, pk.N.Big())
			if err != nil {
				return nil, nil, errs.NewRandomSample("cannot sample nonce")
			}
			nonces[i] = new(saferith.Nat).SetBig(nonceBig, pk.N.AnnouncedLen())
			if nonces[i].EqZero() != 1 && nonces[i].Coprime(pk.N) == 1 {
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

func (pk *PublicKey) GetNResidueParams() (modular.ResidueParams, error) {
	var err error
	pk.precomputedOnce.Do(func() {
		err = pk.precompute()
	})
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot precompute residue parameters")
	}

	return pk.precomputed.nResidueParams, nil
}

func (pk *PublicKey) GetNNResidueParams() (modular.ResidueParams, error) {
	var err error
	pk.precomputedOnce.Do(func() {
		err = pk.precompute()
	})
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot precompute residue parameters")
	}

	return pk.precomputed.nnResidueParams, nil
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
	pk.precomputedOnce = sync.Once{}
	err = pk.precompute()
	if err != nil {
		return errs.WrapSerialisation(err, "cannot precompute")
	}

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

func (pk *PublicKey) precompute() error {
	nResidueParams, err := modular.NewOddResidueParams(pk.N)
	if err != nil {
		return errs.WrapFailed(err, "cannot precompute N residue params")
	}

	nn := new(saferith.Nat).Mul(pk.N, pk.N, -1)
	nnResidueParams, err := modular.NewOddResidueParams(nn)
	if err != nil {
		return errs.WrapFailed(err, "cannot precompute NN residue params")
	}

	pk.precomputed = &PublicKeyPrecomputed{
		nResidueParams,
		nnResidueParams,
	}

	return nil
}
