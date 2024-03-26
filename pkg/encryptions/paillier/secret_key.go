package paillier

import (
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"github.com/copperexchange/krypton-primitives/pkg/base/bignum"
	"io"
	"math/big"
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils"
)

type SecretKeyPrecomputed struct {
	p  *saferith.Nat
	q  *saferith.Nat
	mu *saferith.Nat

	// CRT parameters
	crtN  bignum.CrtParams
	crtNN bignum.CrtParams
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
		return nil, errs.NewFailed("unsupported p/q size (must be of equivalent length)")
	}
	if p.Eq(q) == 1 {
		return nil, errs.NewFailed("p == q")
	}

	pMinusOne := new(saferith.Nat).Sub(p, natOne, p.AnnouncedLen())
	qMinusOne := new(saferith.Nat).Sub(q, natOne, q.AnnouncedLen())
	n := new(saferith.Nat).Mul(p, q, -1)
	phi := new(saferith.Nat).Mul(pMinusOne, qMinusOne, 2*n.AnnouncedLen())

	key := &SecretKey{
		PublicKey: PublicKey{
			N: n,
		},
		Phi: phi,
	}

	key.precompute()
	return key, nil
}

func (sk *SecretKey) EncryptWithNonce(plainText *PlainText, nonce *saferith.Nat) (*CipherText, error) {
	nMod := sk.GetNModulus()
	if plainText == nil || !utils.IsLess(plainText, sk.N) {
		return nil, errs.NewFailed("invalid plainText")
	}
	if nonce == nil || nonce.EqZero() == 1 || !utils.IsLess(nonce, sk.N) || nonce.IsUnit(nMod) != 1 {
		return nil, errs.NewFailed("invalid nonce")
	}

	nnMod := sk.GetNNModulus()
	crt := sk.GetCrtNNParams()

	gToM := new(saferith.Nat).ModAdd(new(saferith.Nat).ModMul(plainText, sk.N, nnMod), natOne, nnMod)
	rToN := bignum.FastExpCrt(crt, nonce, sk.N, nnMod)
	cipherText := new(saferith.Nat).ModMul(gToM, rToN, nnMod)

	return &CipherText{
		C: cipherText,
	}, nil
}

func (sk *SecretKey) EncryptManyWithNonce(plainTexts []*PlainText, rs []*saferith.Nat) ([]*CipherText, error) {
	if len(plainTexts) != len(rs) {
		return nil, errs.NewIsNil("message or nonce mismatch")
	}

	for _, plainText := range plainTexts {
		if plainText == nil || !utils.IsLess(plainText, sk.N) {
			return nil, errs.NewFailed("invalid plainText")
		}
	}

	nMod := sk.GetNModulus()
	for _, r := range rs {
		if r == nil || r.EqZero() == 1 || !utils.IsLess(r, sk.N) || r.IsUnit(nMod) != 1 {
			return nil, errs.NewFailed("invalid nonce")
		}
	}

	nnMod := sk.GetNNModulus()
	gToMs := make([]*saferith.Nat, len(plainTexts))
	for i, plainText := range plainTexts {
		gToMs[i] = new(saferith.Nat).ModAdd(new(saferith.Nat).ModMul(plainText, sk.N, nnMod), natOne, nnMod)
	}
	rToNs := bignum.FastFixedExponentMultiExpCrt(sk.GetCrtNNParams(), rs, sk.N, sk.GetNNModulus().Nat())

	cs := make([]*CipherText, len(plainTexts))
	for i := range plainTexts {
		cs[i] = &CipherText{C: new(saferith.Nat).ModMul(gToMs[i], rToNs[i], sk.GetNNModulus())}
	}

	return cs, nil
}

func (sk *SecretKey) Encrypt(plainText *PlainText, prng io.Reader) (*CipherText, *saferith.Nat, error) {
	if prng == nil {
		return nil, nil, errs.NewIsNil("prng")
	}
	if plainText == nil || !utils.IsLess(plainText, sk.N) {
		return nil, nil, errs.NewFailed("invalid plainText")
	}

	nMod := sk.GetNModulus()
	var nonce *saferith.Nat
	for {
		nonceBig, err := crand.Int(prng, sk.N.Big())
		if err != nil {
			return nil, nil, errs.NewRandomSample("cannot sample nonce")
		}
		nonce = new(saferith.Nat).SetBig(nonceBig, sk.N.AnnouncedLen())
		if nonce.EqZero() != 1 && nonce.IsUnit(nMod) == 1 {
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

	nonces := make([]*saferith.Nat, len(plainTexts))
	for i := range plainTexts {
		for {
			nonceCandidateBig, err := crand.Int(prng, sk.N.Big())
			if err != nil {
				return nil, nil, errs.WrapFailed(err, "cannot generate nonce")
			}
			nonceCandidate := new(saferith.Nat).SetBig(nonceCandidateBig, sk.N.AnnouncedLen())
			if nonceCandidate.IsUnit(sk.GetNModulus()) != 1 || nonceCandidate.EqZero() == 1 {
				continue
			}
			nonces[i] = nonceCandidate
			break
		}
	}

	cipherTexts, err := sk.EncryptManyWithNonce(plainTexts, nonces)
	if err != nil {
		return nil, nil, errs.NewFailed("encryption failed")
	}
	return cipherTexts, nonces, nil
}

func (sk *SecretKey) MulPlaintext(lhs *CipherText, rhs *PlainText) (*CipherText, error) {
	if err := lhs.Validate(&sk.PublicKey); err != nil {
		return nil, errs.WrapFailed(err, "invalid lhs")
	}
	if rhs == nil || !utils.IsLess(rhs, sk.N) {
		return nil, errs.NewFailed("invalid rhs")
	}

	nnMod := sk.GetNNModulus()
	crt := sk.GetCrtNNParams()
	result := bignum.FastExpCrt(crt, lhs.C, rhs, nnMod)

	return &CipherText{
		C: result,
	}, nil
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
	sk.precompute()
	return nil
}

func (sk *SecretKey) GetP() *saferith.Nat {
	sk.precomputedOnce.Do(func() { sk.precompute() })
	return sk.precomputed.p
}

func (sk *SecretKey) GetQ() *saferith.Nat {
	sk.precomputedOnce.Do(func() { sk.precompute() })
	return sk.precomputed.q
}

func (sk *SecretKey) GetMu() *saferith.Nat {
	sk.precomputedOnce.Do(func() { sk.precompute() })
	return sk.precomputed.mu
}

func (sk *SecretKey) GetCrtNParams() *bignum.CrtParams {
	sk.precomputedOnce.Do(func() { sk.precompute() })
	return &sk.precomputed.crtN
}

func (sk *SecretKey) GetCrtNNParams() *bignum.CrtParams {
	sk.precomputedOnce.Do(func() { sk.precompute() })
	return &sk.precomputed.crtNN
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
	if !utils.IsLess(sk.Phi, sk.N) {
		return errs.NewValue("Phi >= N")
	}

	return nil
}

func (sk *SecretKey) L(x *saferith.Nat) *saferith.Nat {
	nMod := sk.GetNModulus()

	xMinusOne := new(saferith.Nat).Sub(x, natOne, sk.GetNNModulus().BitLen())
	l := new(saferith.Nat).Div(xMinusOne, nMod, nMod.BitLen())
	return l
}

func (sk *SecretKey) precompute() {
	sk.PublicKey.precompute()

	minusB := new(saferith.Nat).Sub(new(saferith.Nat).Add(sk.N, natOne, -1), sk.Phi, -1)
	bb := new(saferith.Nat).Mul(minusB, minusB, -1)
	fourN := new(saferith.Nat).Lsh(sk.N, 2, -1)
	delta := new(saferith.Nat).Sub(bb, fourN, -1)
	sqrtDeltaBig := new(big.Int).Sqrt(delta.Big())
	sqrtDelta := new(saferith.Nat).SetBig(sqrtDeltaBig, sqrtDeltaBig.BitLen())
	p := new(saferith.Nat).Rsh(new(saferith.Nat).Sub(minusB, sqrtDelta, -1), 1, -1)
	q := new(saferith.Nat).Rsh(new(saferith.Nat).Add(minusB, sqrtDelta, -1), 1, -1)
	qMod := saferith.ModulusFromNat(q)
	pMinusOne := saferith.ModulusFromNat(new(saferith.Nat).Sub(p, natOne, -1))
	qMinusOne := saferith.ModulusFromNat(new(saferith.Nat).Sub(q, natOne, -1))
	nPhi := new(saferith.Nat).Mul(pMinusOne.Nat(), qMinusOne.Nat(), -1)
	nPhiInv := new(saferith.Nat).ModInverse(nPhi, sk.GetNModulus())
	pInvQ := new(saferith.Nat).ModInverse(p, qMod)
	pp := new(saferith.Nat).Mul(p, p, -1)
	qq := new(saferith.Nat).Mul(q, q, -1)
	qqMod := saferith.ModulusFromNat(qq)
	ppPhi := saferith.ModulusFromNat(new(saferith.Nat).Sub(pp, p, -1))
	qqPhi := saferith.ModulusFromNat(new(saferith.Nat).Sub(qq, q, -1))
	ppInvQQ := new(saferith.Nat).ModInverse(pp, qqMod)

	sk.precomputed = &SecretKeyPrecomputed{
		p:  p,
		q:  q,
		mu: nPhiInv,
		crtN: bignum.NewCrtParams(
			saferith.ModulusFromNat(p),
			pMinusOne,
			qMod,
			qMinusOne,
			pInvQ,
		),
		crtNN: bignum.NewCrtParams(
			saferith.ModulusFromNat(pp),
			ppPhi,
			qqMod,
			qqPhi,
			ppInvQQ,
		),
	}
}

func expCrt(crtParams *bignum.CrtParams, base, exponent *saferith.Nat, modulus *saferith.Modulus) *saferith.Nat {
	eModPhiM1 := new(saferith.Nat).Mod(exponent, crtParams.GetPhiM1())
	eModPhiM2 := new(saferith.Nat).Mod(exponent, crtParams.GetPhiM2())
	r1 := new(saferith.Nat).Exp(base, eModPhiM1, crtParams.GetM1())
	r2 := new(saferith.Nat).Exp(base, eModPhiM2, crtParams.GetM2())
	t1 := new(saferith.Nat).ModSub(r2, r1, crtParams.GetM2())
	t2 := new(saferith.Nat).ModMul(t1, crtParams.GetM1InvM2(), crtParams.GetM2())
	t3 := new(saferith.Nat).ModMul(t2, crtParams.GetM1().Nat(), modulus)
	return new(saferith.Nat).ModAdd(t3, r1, modulus)
}
