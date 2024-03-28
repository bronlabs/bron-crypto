package paillier

import (
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"github.com/copperexchange/krypton-primitives/pkg/base/saferith_ex"
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

	modNEx  saferith_ex.Modulus
	modNNEx saferith_ex.Modulus
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
		return nil, errs.NewValidation("invalid plainText")
	}
	if nonce == nil || nonce.EqZero() == 1 || !utils.IsLess(nonce, sk.N) || nonce.IsUnit(nMod.Modulus()) != 1 {
		return nil, errs.NewValidation("invalid nonce")
	}

	nnMod := sk.GetNNModulus()

	rToN := nnMod.Exp(nonce, sk.N)
	gToM := new(saferith.Nat).ModAdd(new(saferith.Nat).ModMul(plainText, sk.N, nnMod.Modulus()), natOne, nnMod.Modulus())
	cipherText := new(saferith.Nat).ModMul(gToM, rToN, nnMod.Modulus())

	return &CipherText{
		C: cipherText,
	}, nil
}

func (sk *SecretKey) EncryptManyWithNonce(plainTexts []*PlainText, nonces []*saferith.Nat) ([]*CipherText, error) {
	if plainTexts == nil {
		return nil, errs.NewValidation("invalid plainText")
	}
	for _, p := range plainTexts {
		if !utils.IsLess(p, sk.N) {
			return nil, errs.NewValidation("invalid plainText")
		}
	}

	nMod := sk.GetNModulus()
	if nonces == nil || len(nonces) != len(plainTexts) {
		return nil, errs.NewValidation("invalid nonce")
	}
	for _, r := range nonces {
		if r.EqZero() == 1 || !utils.IsLess(r, sk.N) || r.IsUnit(nMod.Modulus()) != 1 {
			return nil, errs.NewValidation("invalid nonce")
		}
	}

	nnMod := sk.GetNNModulus()
	rToN := nnMod.MultiBaseExp(nonces, sk.N)

	cipherTexts := make([]*CipherText, len(plainTexts))
	for i, p := range plainTexts {
		gToM := new(saferith.Nat).ModAdd(new(saferith.Nat).ModMul(p, sk.N, nnMod.Modulus()), natOne, nnMod.Modulus())
		cipherTexts[i] = &CipherText{C: new(saferith.Nat).ModMul(gToM, rToN[i], nnMod.Modulus())}
	}

	return cipherTexts, nil
}

func (sk *SecretKey) Encrypt(plainText *PlainText, prng io.Reader) (*CipherText, *saferith.Nat, error) {
	if prng == nil {
		return nil, nil, errs.NewIsNil("prng")
	}
	if plainText == nil || !utils.IsLess(plainText, sk.N) {
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
		if nonce.EqZero() != 1 && nonce.IsUnit(nMod.Modulus()) == 1 {
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
		if !utils.IsLess(p, sk.N) {
			return nil, nil, errs.NewValidation("invalid plainText")
		}
	}

	nMod := sk.GetNModulus()
	nonces := make([]*saferith.Nat, len(plainTexts))
	for i := 0; i < len(plainTexts); i++ {
		for {
			nonceBig, err := crand.Int(prng, sk.N.Big())
			if err != nil {
				return nil, nil, errs.NewRandomSample("cannot sample nonce")
			}
			nonces[i] = new(saferith.Nat).SetBig(nonceBig, sk.N.AnnouncedLen())
			if nonces[i].EqZero() != 1 && nonces[i].IsUnit(nMod.Modulus()) == 1 {
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
	if rhs == nil || !utils.IsLess(rhs, sk.N) {
		return nil, errs.NewValidation("invalid rhs")
	}

	nnMod := sk.GetNNModulus()
	result := nnMod.Exp(lhs.C, rhs)

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

func (sk *SecretKey) GetNModulus() saferith_ex.Modulus {
	sk.precomputedOnce.Do(func() { sk.precompute() })
	return sk.precomputed.modNEx
}

func (sk *SecretKey) GetNNModulus() saferith_ex.Modulus {
	sk.precomputedOnce.Do(func() { sk.precompute() })
	return sk.precomputed.modNNEx
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
	nnMod := sk.GetNNModulus()
	nMod := sk.GetNModulus()

	xMinusOne := new(saferith.Nat).Sub(x, natOne, nnMod.Modulus().BitLen())
	l := new(saferith.Nat).Div(xMinusOne, nMod.Modulus(), nMod.Modulus().BitLen())
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
	pMinusOne := saferith.ModulusFromNat(new(saferith.Nat).Sub(p, natOne, -1))
	qMinusOne := saferith.ModulusFromNat(new(saferith.Nat).Sub(q, natOne, -1))
	nPhi := new(saferith.Nat).Mul(pMinusOne.Nat(), qMinusOne.Nat(), -1)
	nPhiInv := new(saferith.Nat).ModInverse(nPhi, sk.PublicKey.GetNModulus().Modulus())

	modNEx, err := saferith_ex.NewTwoPrimePowersModulus(p, 1, q, 1)
	if err != nil {
		panic(err)
	}
	modNNEx, err := saferith_ex.NewTwoPrimePowersModulus(p, 2, q, 2)
	if err != nil {
		panic(err)
	}

	sk.precomputed = &SecretKeyPrecomputed{
		p:       p,
		q:       q,
		mu:      nPhiInv,
		modNEx:  modNEx,
		modNNEx: modNNEx,
	}
}
