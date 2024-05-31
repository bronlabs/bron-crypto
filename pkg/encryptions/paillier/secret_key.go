package paillier

import (
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"github.com/copperexchange/krypton-primitives/pkg/base/modular"
	"io"
	"math/big"
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	saferithUtils "github.com/copperexchange/krypton-primitives/pkg/base/utils/saferith"
)

type SecretKeyPrecomputed struct {
	p  *saferith.Nat
	q  *saferith.Nat
	mu *saferith.Nat

	// CRT parameters
	crtNResidueParams  modular.CrtResidueParams
	crtNNResidueParams modular.CrtResidueParams
}

type SecretKey struct {
	PublicKey
	Phi             *saferith.Nat
	precomputed     *SecretKeyPrecomputed
	precomputedOnce sync.Once
}

type secretKeyJson struct {
	N   string `json:"n"`
	Phi string `json:"phi"`
}

var _ json.Marshaler = (*SecretKey)(nil)
var _ json.Unmarshaler = (*SecretKey)(nil)

func NewSecretKey(p, q *saferith.Nat) (*SecretKey, error) {
	if p == nil || q == nil {
		return nil, errs.NewIsNil("p or q")
	}
	if p.TrueLen() != q.TrueLen() {
		return nil, errs.NewLength("unsupported p/q size (must be of equivalent length)")
	}
	if p.Eq(q) == 1 {
		return nil, errs.NewValidation("p == q")
	}

	pMinusOne := saferithUtils.NatDec(p)
	qMinusOne := saferithUtils.NatDec(q)
	n := new(saferith.Nat).Mul(p, q, -1)
	phi := new(saferith.Nat).Mul(pMinusOne, qMinusOne, 2*n.AnnouncedLen())

	key := &SecretKey{
		PublicKey: PublicKey{
			N: n,
		},
		Phi: phi,
	}

	err := key.PublicKey.precompute()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot precompute pk")
	}
	err = key.precompute()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot precompute sk")
	}

	return key, nil
}

func (sk *SecretKey) EncryptWithNonce(plainText *PlainText, nonce *saferith.Nat) (*CipherText, error) {
	if plainText == nil || !saferithUtils.NatIsLess(plainText, sk.N) {
		return nil, errs.NewValidation("invalid plainText")
	}
	if nonce == nil || nonce.EqZero() == 1 || !saferithUtils.NatIsLess(nonce, sk.N) || nonce.Coprime(sk.N) != 1 {
		return nil, errs.NewValidation("invalid nonce")
	}

	nnMod, err := sk.GetNNResidueParams()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot get NN residue params")
	}

	rToN, err := nnMod.ModExp(nonce, sk.N)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot compute exp")
	}

	gToM := new(saferith.Nat).ModAdd(new(saferith.Nat).ModMul(plainText, sk.N, nnMod.GetModulus()), saferithUtils.NatOne, nnMod.GetModulus())
	cipherText := new(saferith.Nat).ModMul(gToM, rToN, nnMod.GetModulus())

	return &CipherText{
		C: cipherText,
	}, nil
}

func (sk *SecretKey) EncryptManyWithNonce(plainTexts []*PlainText, nonces []*saferith.Nat) ([]*CipherText, error) {
	if plainTexts == nil {
		return nil, errs.NewValidation("invalid plainText")
	}
	for _, p := range plainTexts {
		if !saferithUtils.NatIsLess(p, sk.N) {
			return nil, errs.NewValidation("invalid plainText")
		}
	}

	if nonces == nil || len(nonces) != len(plainTexts) {
		return nil, errs.NewValidation("invalid nonce")
	}
	for _, r := range nonces {
		if r.EqZero() == 1 || !saferithUtils.NatIsLess(r, sk.N) || r.Coprime(sk.N) != 1 {
			return nil, errs.NewValidation("invalid nonce")
		}
	}

	nnMod, err := sk.GetNNResidueParams()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot get NN residue params")
	}

	rToN, err := nnMod.ModMultiBaseExp(nonces, sk.N)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot compute exp")
	}

	cipherTexts := make([]*CipherText, len(plainTexts))
	for i, p := range plainTexts {
		gToM := new(saferith.Nat).ModAdd(new(saferith.Nat).ModMul(p, sk.N, nnMod.GetModulus()), saferithUtils.NatOne, nnMod.GetModulus())
		cipherTexts[i] = &CipherText{C: new(saferith.Nat).ModMul(gToM, rToN[i], nnMod.GetModulus())}
	}

	return cipherTexts, nil
}

func (sk *SecretKey) Encrypt(plainText *PlainText, prng io.Reader) (*CipherText, *saferith.Nat, error) {
	if prng == nil {
		return nil, nil, errs.NewIsNil("prng")
	}
	if plainText == nil || !saferithUtils.NatIsLess(plainText, sk.N) {
		return nil, nil, errs.NewValidation("invalid plainText")
	}

	var nonce *saferith.Nat
	for {
		nonceBig, err := crand.Int(prng, sk.N.Big())
		if err != nil {
			return nil, nil, errs.NewRandomSample("cannot sample nonce")
		}
		nonce = new(saferith.Nat).SetBig(nonceBig, sk.N.AnnouncedLen())
		if nonce.EqZero() != 1 && nonce.Coprime(sk.N) == 1 {
			break
		}
	}

	cipherText, err := sk.EncryptWithNonce(plainText, nonce)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot encrypt")
	}

	return cipherText, nonce, nil
}

func (sk *SecretKey) EncryptMany(plainTexts []*PlainText, prng io.Reader) ([]*CipherText, []*saferith.Nat, error) {
	if prng == nil {
		return nil, nil, errs.NewIsNil("prng")
	}
	if plainTexts == nil {
		return nil, nil, errs.NewValidation("invalid plainText")
	}
	for _, p := range plainTexts {
		if !saferithUtils.NatIsLess(p, sk.N) {
			return nil, nil, errs.NewValidation("invalid plainText")
		}
	}

	nonces := make([]*saferith.Nat, len(plainTexts))
	for i := 0; i < len(plainTexts); i++ {
		for {
			nonceBig, err := crand.Int(prng, sk.N.Big())
			if err != nil {
				return nil, nil, errs.NewRandomSample("cannot sample nonce")
			}
			nonces[i] = new(saferith.Nat).SetBig(nonceBig, sk.N.AnnouncedLen())
			if nonces[i].EqZero() != 1 && nonces[i].Coprime(sk.N) == 1 {
				break
			}
		}
	}

	cipherTexts, err := sk.EncryptManyWithNonce(plainTexts, nonces)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot encrypt")
	}

	return cipherTexts, nonces, nil
}

func (sk *SecretKey) MulPlaintext(lhs *CipherText, rhs *PlainText) (*CipherText, error) {
	if err := lhs.Validate(&sk.PublicKey); err != nil {
		return nil, errs.WrapValidation(err, "invalid lhs")
	}
	if rhs == nil || !saferithUtils.NatIsLess(rhs, sk.N) {
		return nil, errs.NewValidation("invalid rhs")
	}

	nnMod, err := sk.GetNNResidueParams()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot get NN residue params")
	}

	result, err := nnMod.ModExp(lhs.C, rhs)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot compute exp")
	}

	return &CipherText{
		C: result,
	}, nil
}

func (sk *SecretKey) GetP() (*saferith.Nat, error) {
	var err error
	sk.precomputedOnce.Do(func() { err = sk.precompute() })
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot precompute")
	}

	return sk.precomputed.p, nil
}

func (sk *SecretKey) GetQ() (*saferith.Nat, error) {
	var err error
	sk.precomputedOnce.Do(func() { err = sk.precompute() })
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot precompute")
	}

	return sk.precomputed.q, nil
}

func (sk *SecretKey) GetMu() (*saferith.Nat, error) {
	var err error
	sk.precomputedOnce.Do(func() { err = sk.precompute() })
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot precompute")
	}

	return sk.precomputed.mu, nil
}

func (sk *SecretKey) GetNNResidueParams() (modular.CrtResidueParams, error) {
	var err error
	sk.precomputedOnce.Do(func() { err = sk.precompute() })
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot precompute")
	}

	return sk.precomputed.crtNNResidueParams, nil
}

func (sk *SecretKey) GetNResidueParams() (modular.CrtResidueParams, error) {
	var err error
	sk.precomputedOnce.Do(func() { err = sk.precompute() })
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot precompute")
	}

	return sk.precomputed.crtNResidueParams, nil
}

func (sk *SecretKey) MarshalJSON() ([]byte, error) {
	val := &secretKeyJson{
		N:   hex.EncodeToString(sk.N.Bytes()),
		Phi: hex.EncodeToString(sk.Phi.Bytes()),
	}

	ret, err := json.Marshal(val)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "marshal failed")
	}

	return ret, nil
}

func (sk *SecretKey) UnmarshalJSON(bytes []byte) error {
	var val secretKeyJson
	err := json.Unmarshal(bytes, &val)
	if err != nil {
		return errs.WrapSerialisation(err, "unmarshal failed")
	}

	nBytes, err := hex.DecodeString(val.N)
	if err != nil {
		return errs.WrapSerialisation(err, "unmarshal failed")
	}
	phiBytes, err := hex.DecodeString(val.Phi)
	if err != nil {
		return errs.WrapSerialisation(err, "unmarshal failed")
	}

	sk.N = new(saferith.Nat).SetBytes(nBytes)
	sk.Phi = new(saferith.Nat).SetBytes(phiBytes)
	sk.PublicKey.precomputedOnce = sync.Once{}
	sk.precomputedOnce = sync.Once{}

	err = sk.PublicKey.precompute()
	if err != nil {
		return errs.WrapFailed(err, "cannot precompute pk")
	}

	err = sk.precompute()
	if err != nil {
		return errs.WrapFailed(err, "cannot precompute sk")
	}

	return nil
}

func (sk *SecretKey) Validate() error {
	if sk == nil {
		return errs.NewIsNil("sk")
	}
	if err := sk.PublicKey.Validate(); err != nil {
		return errs.WrapValidation(err, "invalid public key")
	}
	if sk.Phi == nil {
		return errs.NewIsNil("phi")
	}
	if sk.N.TrueLen() < 4 {
		return errs.NewValue("N is too small")
	}
	if !saferithUtils.NatIsLess(sk.Phi, sk.N) {
		return errs.NewValue("Phi >= N")
	}

	return nil
}

func (sk *SecretKey) L(x *saferith.Nat) (*saferith.Nat, error) {
	nMod, err := sk.GetNResidueParams()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot get N residue params")
	}

	xMinusOne := saferithUtils.NatDec(x)
	l := new(saferith.Nat).Div(xMinusOne, nMod.GetModulus(), nMod.GetModulus().BitLen())
	return l, nil
}

func (sk *SecretKey) precompute() error {
	nParams, err := sk.PublicKey.GetNResidueParams()
	if err != nil {
		return errs.WrapFailed(err, "cannot precompute")
	}
	nMod := nParams.GetModulus()

	minusB := new(saferith.Nat).Sub(saferithUtils.NatInc(sk.N), sk.Phi, -1)
	bb := new(saferith.Nat).Mul(minusB, minusB, -1)
	fourN := new(saferith.Nat).Lsh(sk.N, 2, -1)
	delta := new(saferith.Nat).Sub(bb, fourN, -1)
	sqrtDeltaBig := new(big.Int).Sqrt(delta.Big())
	sqrtDelta := new(saferith.Nat).SetBig(sqrtDeltaBig, sqrtDeltaBig.BitLen())
	p := new(saferith.Nat).Rsh(new(saferith.Nat).Sub(minusB, sqrtDelta, -1), 1, -1)
	q := new(saferith.Nat).Rsh(new(saferith.Nat).Add(minusB, sqrtDelta, -1), 1, -1)

	crtNResidueParams, err := modular.NewCrtResidueParams(p, 1, q, 1)
	if err != nil {
		return errs.WrapFailed(err, "cannot precompute")
	}
	crtNNResidueParams, err := modular.NewCrtResidueParams(p, 2, q, 2)
	if err != nil {
		return errs.WrapFailed(err, "cannot precompute")
	}

	nPhi := new(saferith.Nat).Mul(crtNResidueParams.GetPhiM1().Nat(), crtNResidueParams.GetPhiM2().Nat(), -1)
	nPhiInv := new(saferith.Nat).ModInverse(nPhi, nMod)

	sk.precomputed = &SecretKeyPrecomputed{
		p:                  p,
		q:                  q,
		mu:                 nPhiInv,
		crtNResidueParams:  crtNResidueParams,
		crtNNResidueParams: crtNNResidueParams,
	}

	return nil
}
