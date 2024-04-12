package paillier

import (
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	saferithUtils "github.com/copperexchange/krypton-primitives/pkg/base/utils/saferith"
)

type CrtParams struct {
	m1      *saferith.Modulus
	phiM1   *saferith.Modulus
	m2      *saferith.Modulus
	phiM2   *saferith.Modulus
	m1InvM2 *saferith.Nat
}

func (p *CrtParams) GetM1() *saferith.Modulus {
	return p.m1
}

func (p *CrtParams) GetPhiM1() *saferith.Modulus {
	return p.phiM1
}

func (p *CrtParams) GetM2() *saferith.Modulus {
	return p.m2
}

func (p *CrtParams) GetPhiM2() *saferith.Modulus {
	return p.phiM2
}

func (p *CrtParams) GetM1InvM2() *saferith.Nat {
	return p.m1InvM2
}

type SecretKeyPrecomputed struct {
	p  *saferith.Nat
	q  *saferith.Nat
	mu *saferith.Nat

	// CRT parameters
	crtN  CrtParams
	crtNN CrtParams
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

	key.precompute()
	return key, nil
}

func (sk *SecretKey) EncryptWithNonce(plainText *PlainText, nonce *saferith.Nat) (*CipherText, error) {
	nMod := sk.GetNModulus()
	if plainText == nil || !saferithUtils.NatIsLess(plainText, sk.N) {
		return nil, errs.NewValidation("invalid plainText")
	}
	if nonce == nil || nonce.EqZero() == 1 || !saferithUtils.NatIsLess(nonce, sk.N) || nonce.IsUnit(nMod) != 1 {
		return nil, errs.NewValidation("invalid nonce")
	}

	nnMod := sk.GetNNModulus()
	crt := sk.GetCrtNNParams()

	rToN := expCrt(crt, nonce, sk.N, nnMod)
	gToM := new(saferith.Nat).ModAdd(new(saferith.Nat).ModMul(plainText, sk.N, nnMod), saferithUtils.NatOne, nnMod)
	cipherText := new(saferith.Nat).ModMul(gToM, rToN, nnMod)

	return &CipherText{
		C: cipherText,
	}, nil
}

func (sk *SecretKey) Encrypt(plainText *PlainText, prng io.Reader) (*CipherText, *saferith.Nat, error) {
	if prng == nil {
		return nil, nil, errs.NewIsNil("prng")
	}
	if plainText == nil || !saferithUtils.NatIsLess(plainText, sk.N) {
		return nil, nil, errs.NewValidation("invalid plainText")
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

func (sk *SecretKey) MulPlaintext(lhs *CipherText, rhs *PlainText) (*CipherText, error) {
	if err := lhs.Validate(&sk.PublicKey); err != nil {
		return nil, errs.WrapValidation(err, "invalid lhs")
	}
	if rhs == nil || !saferithUtils.NatIsLess(rhs, sk.N) {
		return nil, errs.NewValidation("invalid rhs")
	}

	nnMod := sk.GetNNModulus()
	crt := sk.GetCrtNNParams()
	result := expCrt(crt, lhs.C, rhs, nnMod)

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

func (sk *SecretKey) GetCrtNParams() *CrtParams {
	sk.precomputedOnce.Do(func() { sk.precompute() })
	return &sk.precomputed.crtN
}

func (sk *SecretKey) GetCrtNNParams() *CrtParams {
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
	if !saferithUtils.NatIsLess(sk.Phi, sk.N) {
		return errs.NewValue("Phi >= N")
	}

	return nil
}

func (sk *SecretKey) L(x *saferith.Nat) *saferith.Nat {
	nMod := sk.GetNModulus()

	xMinusOne := saferithUtils.NatDec(x)
	l := new(saferith.Nat).Div(xMinusOne, nMod, nMod.BitLen())
	return l
}

func (sk *SecretKey) precompute() {
	sk.PublicKey.precompute()

	minusB := new(saferith.Nat).Sub(saferithUtils.NatInc(sk.N), sk.Phi, -1)
	bb := new(saferith.Nat).Mul(minusB, minusB, -1)
	fourN := new(saferith.Nat).Lsh(sk.N, 2, -1)
	delta := new(saferith.Nat).Sub(bb, fourN, -1)
	sqrtDeltaBig := new(big.Int).Sqrt(delta.Big())
	sqrtDelta := new(saferith.Nat).SetBig(sqrtDeltaBig, sqrtDeltaBig.BitLen())
	p := new(saferith.Nat).Rsh(new(saferith.Nat).Sub(minusB, sqrtDelta, -1), 1, -1)
	q := new(saferith.Nat).Rsh(new(saferith.Nat).Add(minusB, sqrtDelta, -1), 1, -1)
	qMod := saferith.ModulusFromNat(q)
	pMinusOne := saferith.ModulusFromNat(saferithUtils.NatDec(p))
	qMinusOne := saferith.ModulusFromNat(saferithUtils.NatDec(q))
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
		crtN: CrtParams{
			m1:      saferith.ModulusFromNat(p),
			phiM1:   pMinusOne,
			m2:      qMod,
			phiM2:   qMinusOne,
			m1InvM2: pInvQ,
		},
		crtNN: CrtParams{
			m1:      saferith.ModulusFromNat(pp),
			phiM1:   ppPhi,
			m2:      qqMod,
			phiM2:   qqPhi,
			m1InvM2: ppInvQQ,
		},
	}
}

func expCrt(crtParams *CrtParams, base, exponent *saferith.Nat, modulus *saferith.Modulus) *saferith.Nat {
	eModPhiM1 := new(saferith.Nat).Mod(exponent, crtParams.phiM1)
	eModPhiM2 := new(saferith.Nat).Mod(exponent, crtParams.phiM2)
	r1 := new(saferith.Nat).Exp(base, eModPhiM1, crtParams.m1)
	r2 := new(saferith.Nat).Exp(base, eModPhiM2, crtParams.m2)
	t1 := new(saferith.Nat).ModSub(r2, r1, crtParams.m2)
	t2 := new(saferith.Nat).ModMul(t1, crtParams.m1InvM2, crtParams.m2)
	t3 := new(saferith.Nat).ModMul(t2, crtParams.m1.Nat(), modulus)
	return new(saferith.Nat).ModAdd(t3, r1, modulus)
}
