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
	"github.com/copperexchange/krypton-primitives/pkg/base/utils"
)

type CrtParams struct {
	M1      *saferith.Modulus
	PhiM1   *saferith.Modulus
	M2      *saferith.Modulus
	PhiM2   *saferith.Modulus
	M1InvM2 *saferith.Nat
}

type SecretKeyPrecomputed struct {
	P  *saferith.Nat
	Q  *saferith.Nat
	Mu *saferith.Nat

	// CRT parameters
	CrtN  CrtParams
	CrtNN CrtParams
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
	nMod := sk.PublicKey.GetPrecomputed().NModulus
	if plainText == nil || !utils.IsLess(plainText, sk.N) {
		return nil, errs.NewFailed("invalid plainText")
	}
	if nonce == nil || nonce.EqZero() == 1 || !utils.IsLess(nonce, sk.N) || nonce.IsUnit(nMod) != 1 {
		return nil, errs.NewFailed("invalid nonce")
	}

	nnMod := sk.PublicKey.GetPrecomputed().NNModulus
	crt := &sk.GetPrecomputed().CrtNN

	rToN := expCrt(crt, nonce, sk.N, nnMod)
	gToM := new(saferith.Nat).ModAdd(new(saferith.Nat).ModMul(plainText, sk.N, nnMod), natOne, nnMod)
	cipherText := new(saferith.Nat).ModMul(gToM, rToN, nnMod)

	return &CipherText{
		C: cipherText,
	}, nil
}

func (sk *SecretKey) Encrypt(plainText *PlainText, prng io.Reader) (*CipherText, *saferith.Nat, error) {
	if prng == nil {
		return nil, nil, errs.NewIsNil("prng")
	}
	if plainText == nil || !utils.IsLess(plainText, sk.N) {
		return nil, nil, errs.NewFailed("invalid plainText")
	}

	n := sk.PublicKey.GetPrecomputed().NModulus
	var nonce *saferith.Nat
	for {
		nonceBig, err := crand.Int(prng, sk.N.Big())
		if err != nil {
			return nil, nil, errs.NewRandomSample("cannot sample nonce")
		}
		nonce = new(saferith.Nat).SetBig(nonceBig, sk.N.AnnouncedLen())
		if nonce.EqZero() != 1 && nonce.IsUnit(n) == 1 {
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
		return nil, errs.WrapFailed(err, "invalid lhs")
	}
	if rhs == nil || !utils.IsLess(rhs, sk.N) {
		return nil, errs.NewFailed("invalid rhs")
	}

	nnMod := sk.PublicKey.GetPrecomputed().NNModulus
	crt := &sk.GetPrecomputed().CrtNN
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

func (sk *SecretKey) GetPrecomputed() *SecretKeyPrecomputed {
	sk.precomputedOnce.Do(func() { sk.precompute() })
	return sk.precomputed
}

func (sk *SecretKey) Validate() error {
	if sk == nil {
		return errs.NewIsNil("sk")
	}
	if sk.Phi == nil {
		return errs.NewIsNil("phi")
	}
	if sk.N == nil {
		return errs.NewIsNil("n")
	}

	return nil
}

func (sk *SecretKey) L(x *saferith.Nat) *saferith.Nat {
	n := sk.PublicKey.GetPrecomputed().NModulus

	xMinusOne := new(saferith.Nat).Sub(x, natOne, sk.PublicKey.GetPrecomputed().NNModulus.BitLen())
	l := new(saferith.Nat).Div(xMinusOne, n, n.BitLen())
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
	nPhiInv := new(saferith.Nat).ModInverse(nPhi, sk.PublicKey.GetPrecomputed().NModulus)
	pInvQ := new(saferith.Nat).ModInverse(p, qMod)
	pp := new(saferith.Nat).Mul(p, p, -1)
	qq := new(saferith.Nat).Mul(q, q, -1)
	qqMod := saferith.ModulusFromNat(qq)
	ppPhi := saferith.ModulusFromNat(new(saferith.Nat).Sub(pp, p, -1))
	qqPhi := saferith.ModulusFromNat(new(saferith.Nat).Sub(qq, q, -1))
	ppInvQQ := new(saferith.Nat).ModInverse(pp, qqMod)

	sk.precomputed = &SecretKeyPrecomputed{
		P:  p,
		Q:  q,
		Mu: nPhiInv,
		CrtN: CrtParams{
			M1:      saferith.ModulusFromNat(p),
			PhiM1:   pMinusOne,
			M2:      qMod,
			PhiM2:   qMinusOne,
			M1InvM2: pInvQ,
		},
		CrtNN: CrtParams{
			M1:      saferith.ModulusFromNat(pp),
			PhiM1:   ppPhi,
			M2:      qqMod,
			PhiM2:   qqPhi,
			M1InvM2: ppInvQQ,
		},
	}
}

func expCrt(crtParams *CrtParams, base, exponent *saferith.Nat, modulus *saferith.Modulus) *saferith.Nat {
	eModPhiM1 := new(saferith.Nat).Mod(exponent, crtParams.PhiM1)
	eModPhiM2 := new(saferith.Nat).Mod(exponent, crtParams.PhiM2)
	r1 := new(saferith.Nat).Exp(base, eModPhiM1, crtParams.M1)
	r2 := new(saferith.Nat).Exp(base, eModPhiM2, crtParams.M2)
	t1 := new(saferith.Nat).ModSub(r2, r1, crtParams.M2)
	t2 := new(saferith.Nat).ModMul(t1, crtParams.M1InvM2, crtParams.M2)
	t3 := new(saferith.Nat).ModMul(t2, crtParams.M1.Nat(), modulus)
	return new(saferith.Nat).ModAdd(t3, r1, modulus)
}
