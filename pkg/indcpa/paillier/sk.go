package paillier

import (
	"encoding"
	"encoding/hex"
	"encoding/json"
	"io"
	"slices"

	"github.com/cronokirby/saferith"
	"golang.org/x/sync/errgroup"

	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/base/modular"
	"github.com/bronlabs/krypton-primitives/pkg/base/utils/numutils"
	"github.com/bronlabs/krypton-primitives/pkg/indcpa"
)

var (
	_ indcpa.DecryptionKey[*PlainText, *Nonce, *CipherText, *PublicKey] = (*SecretKey)(nil)
	_ indcpa.EncryptionKey[*PlainText, *Nonce, *CipherText]             = (*SecretKey)(nil)
	_ json.Marshaler                                                    = (*SecretKey)(nil)
	_ json.Unmarshaler                                                  = (*SecretKey)(nil)
	_ encoding.BinaryMarshaler                                          = (*SecretKey)(nil)
	_ encoding.BinaryUnmarshaler                                        = (*SecretKey)(nil)

	one = new(saferith.Nat).SetUint64(1).Resize(1)
)

type SecretKey struct {
	PublicKey
	P *saferith.Modulus
	Q *saferith.Modulus

	pm1   *saferith.Modulus
	pp    *saferith.Modulus
	phiPP *saferith.Modulus
	hp    *saferith.Nat
	nInvP *saferith.Nat
	np    *saferith.Nat

	qm1   *saferith.Modulus
	qq    *saferith.Modulus
	phiQQ *saferith.Modulus
	hq    *saferith.Nat
	nInvQ *saferith.Nat
	nq    *saferith.Nat

	phi   *saferith.Modulus
	phiNN *saferith.Modulus
	qInv  *saferith.Nat
	qqInv *saferith.Nat
}

func NewSecretKey(p, q *saferith.Nat) (*SecretKey, error) {
	if p == nil || q == nil {
		return nil, errs.NewIsNil("p/q is nil")
	}
	if p.TrueLen() != q.TrueLen() {
		return nil, errs.NewLength("unsupported p/q size (must be of equivalent length)")
	}
	if p.Eq(q) == 1 {
		return nil, errs.NewValidation("p == q")
	}
	if !p.Big().ProbablyPrime(2) || !q.Big().ProbablyPrime(2) {
		return nil, errs.NewValidation("p/q is not prime")
	}

	sk := &SecretKey{
		P: saferith.ModulusFromNat(p),
		Q: saferith.ModulusFromNat(q),
	}
	sk.precompute()
	return sk, nil
}

func (sk *SecretKey) Equal(rhs *SecretKey) bool {
	if sk == nil || rhs == nil {
		return sk == rhs
	}

	return sk.PublicKey.Equal(&rhs.PublicKey)
}

func (sk *SecretKey) Validate() error {
	if sk == nil {
		return errs.NewIsNil("sk is nil")
	}
	if !sk.P.Big().ProbablyPrime(2) {
		return errs.NewValidation("p is not prime")
	}
	if !sk.Q.Big().ProbablyPrime(2) {
		return errs.NewValidation("q is not prime")
	}
	if sk.P.Nat().Eq(sk.Q.Nat()) != 0 {
		return errs.NewValidation("p == q")
	}
	if sk.P.BitLen() != sk.Q.BitLen() {
		return errs.NewValidation("len(p) != len(q)")
	}
	if new(saferith.Nat).Mul(sk.P.Nat(), sk.Q.Nat(), -1).Eq(sk.N.Nat()) == 0 {
		return errs.NewValidation("n != p * q")
	}

	return nil
}

func (sk *SecretKey) ToEncryptionKey() (encryptionKey *PublicKey, err error) {
	return &sk.PublicKey, nil
}

func (sk *SecretKey) Decrypt(cipherText *CipherText) (plainText *PlainText, err error) {
	if !sk.validCiphertext(cipherText) {
		return nil, errs.NewValidation("invalid ciphertext")
	}

	var cToPm1, cToQm1 *saferith.Nat
	var eg errgroup.Group
	eg.Go(func() error {
		var err error
		cToPm1, err = modular.FastExp(&cipherText.C, sk.pm1.Nat(), sk.pp)
		return err //nolint:wrapcheck // wrapped at eg.Wait()
	})
	eg.Go(func() error {
		var err error
		cToQm1, err = modular.FastExp(&cipherText.C, sk.qm1.Nat(), sk.qq)
		return err //nolint:wrapcheck // wrapped at eg.Wait()
	})
	err = eg.Wait()
	if err != nil {
		return nil, errs.NewFailed("failed to decrypt ciphertext")
	}

	lmp := sk.lp(cToPm1)
	mp := new(saferith.Nat).ModMul(lmp, sk.hp, sk.P)

	lmq := sk.lq(cToQm1)
	mq := new(saferith.Nat).ModMul(lmq, sk.hq, sk.Q)

	m := numutils.CrtWithPrecomputation(mp, mq, sk.P, sk.Q.Nat(), sk.qInv)
	return new(saferith.Int).SetModSymmetric(m, sk.N), nil
}

func (sk *SecretKey) Open(cipherText *CipherText) (plainText *PlainText, nonce *Nonce, err error) {
	if !sk.validCiphertext(cipherText) {
		return nil, nil, errs.NewValidation("invalid ciphertext")
	}

	var cToPm1, cToQm1, rp, rq *saferith.Nat
	var eg errgroup.Group
	eg.Go(func() error {
		var err error
		cToPm1, err = modular.FastExp(&cipherText.C, sk.pm1.Nat(), sk.pp)
		return err //nolint:wrapcheck // wrapped at eg.Wait()
	})
	eg.Go(func() error {
		var err error
		cToQm1, err = modular.FastExp(&cipherText.C, sk.qm1.Nat(), sk.qq)
		return err //nolint:wrapcheck // wrapped at eg.Wait()
	})
	eg.Go(func() error {
		var err error
		rp, err = modular.FastExp(&cipherText.C, sk.nInvP, sk.P)
		return err //nolint:wrapcheck // wrapped at eg.Wait()
	})
	eg.Go(func() error {
		var err error
		rq, err = modular.FastExp(&cipherText.C, sk.nInvQ, sk.Q)
		return err //nolint:wrapcheck // wrapped at eg.Wait()
	})
	err = eg.Wait()
	if err != nil {
		return nil, nil, errs.NewFailed("failed to open ciphertext")
	}

	lmp := sk.lp(cToPm1)
	mp := new(saferith.Nat).ModMul(lmp, sk.hp, sk.P)
	lmq := sk.lq(cToQm1)
	mq := new(saferith.Nat).ModMul(lmq, sk.hq, sk.Q)
	m := numutils.CrtWithPrecomputation(mp, mq, sk.P, sk.Q.Nat(), sk.qInv)
	plainText = new(saferith.Int).SetModSymmetric(m, sk.N)
	nonce = numutils.CrtWithPrecomputation(rp, rq, sk.P, sk.Q.Nat(), sk.qInv)

	return plainText, nonce, nil
}

func (sk *SecretKey) EncryptWithNonce(plainText *PlainText, nonce *Nonce) (cipherText *CipherText, err error) {
	if !sk.validPlaintext(plainText) {
		return nil, errs.NewValidation("invalid plaintext")
	}
	if !sk.validNonce(nonce) {
		return nil, errs.NewValidation("invalid nonce")
	}

	gToM := sk.gToM(plainText)
	rToN, err := sk.rToN(nonce)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to encrypt plaintext")
	}

	c := new(CipherText)
	c.C.ModMul(gToM, rToN, sk.nn)
	return c, nil
}

func (sk *SecretKey) Encrypt(plainText *PlainText, prng io.Reader) (cipherText *CipherText, nonce *Nonce, err error) {
	if prng == nil {
		return nil, nil, errs.NewIsNil("prng")
	}
	if !sk.validPlaintext(plainText) {
		return nil, nil, errs.NewValidation("invalid plaintext")
	}

	r, err := sk.RandomNonce(prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "failed to generate random nonce")
	}

	c, err := sk.EncryptWithNonce(plainText, r)
	if err != nil {
		return nil, nil, err
	}

	return c, r, nil
}

func (sk *SecretKey) EncryptManyWithNonce(plainTexts []*PlainText, nonces []*saferith.Nat) ([]*CipherText, error) {
	if len(plainTexts) != len(nonces) {
		return nil, errs.NewValidation("length mismatch")
	}

	ciphertexts := make([]*CipherText, len(plainTexts))
	var eg errgroup.Group
	for i, p := range plainTexts {
		eg.Go(func() error {
			var err error
			ciphertexts[i], err = sk.EncryptWithNonce(p, nonces[i])
			return err
		})
	}
	err := eg.Wait()
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to encrypt plaintexts")
	}

	return ciphertexts, nil
}

func (sk *SecretKey) EncryptMany(plainTexts []*PlainText, prng io.Reader) ([]*CipherText, []*saferith.Nat, error) {
	nonces := make([]*Nonce, len(plainTexts))
	for i := range plainTexts {
		var err error
		nonces[i], err = sk.RandomNonce(prng)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "failed to generate random nonce")
		}
	}

	ciphertexts, err := sk.EncryptManyWithNonce(plainTexts, nonces)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "failed to encrypt plaintexts")
	}

	return ciphertexts, nonces, nil
}

func (sk *SecretKey) Phi() *saferith.Modulus {
	return sk.phi
}

func (sk *SecretKey) MarshalJSON() ([]byte, error) {
	skJson := &secretKeyJson{
		P: hex.EncodeToString(sk.P.Bytes()),
		Q: hex.EncodeToString(sk.Q.Bytes()),
	}
	data, err := json.Marshal(skJson)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "unable to marshal secret key")
	}

	return data, nil
}

func (sk *SecretKey) UnmarshalJSON(bytes []byte) error {
	var skJson secretKeyJson
	err := json.Unmarshal(bytes, &skJson)
	if err != nil {
		return errs.WrapSerialisation(err, "unable to deserialise secret key")
	}

	pBytes, err := hex.DecodeString(skJson.P)
	if err != nil {
		return errs.WrapSerialisation(err, "invalid p")
	}
	qBytes, err := hex.DecodeString(skJson.Q)
	if err != nil {
		return errs.WrapSerialisation(err, "invalid q")
	}

	p := saferith.ModulusFromBytes(pBytes)
	q := saferith.ModulusFromBytes(qBytes)
	sk.P = p
	sk.Q = q
	sk.precompute()
	return nil
}

func (sk *SecretKey) MarshalBinary() (data []byte, err error) {
	pBytes, err := sk.P.MarshalBinary()
	if err != nil {
		return nil, errs.WrapSerialisation(err, "unable to deserialise secret key")
	}
	qBytes, err := sk.Q.MarshalBinary()
	if err != nil {
		return nil, errs.WrapSerialisation(err, "invalid q")
	}

	return slices.Concat(pBytes, qBytes), nil
}

func (sk *SecretKey) UnmarshalBinary(data []byte) error {
	pBytes := data[0 : len(data)/2]
	qBytes := data[len(data)/2:]
	p := new(saferith.Modulus)
	err := p.UnmarshalBinary(pBytes)
	if err != nil {
		return errs.WrapSerialisation(err, "invalid p")
	}
	q := new(saferith.Modulus)
	err = q.UnmarshalBinary(qBytes)
	if err != nil {
		return errs.WrapSerialisation(err, "invalid q")
	}

	sk.P = p
	sk.Q = q
	sk.precompute()
	return nil
}

func (sk *SecretKey) precompute() {
	n := new(saferith.Nat).Mul(sk.P.Nat(), sk.Q.Nat(), sk.P.BitLen()+sk.Q.BitLen())
	sk.PublicKey.N = saferith.ModulusFromNat(n)
	sk.PublicKey.precompute()

	sk.pm1 = saferith.ModulusFromNat(new(saferith.Nat).Sub(sk.P.Nat(), one, sk.P.BitLen()))
	pp := new(saferith.Nat).Mul(sk.P.Nat(), sk.P.Nat(), 2*sk.P.BitLen())
	sk.pp = saferith.ModulusFromNat(pp)
	sk.phiPP = saferith.ModulusFromNat(new(saferith.Nat).Mul(sk.P.Nat(), sk.pm1.Nat(), 2*sk.P.BitLen()))
	gToPm1 := new(saferith.Nat).ModSub(one, sk.N.Nat(), sk.pp)
	hpInv := sk.lp(gToPm1)
	sk.hp = new(saferith.Nat).ModInverse(hpInv, sk.P)
	sk.np = new(saferith.Nat).Mod(sk.N.Nat(), sk.pm1)

	sk.qm1 = saferith.ModulusFromNat(new(saferith.Nat).Sub(sk.Q.Nat(), one, sk.Q.BitLen()))
	qq := new(saferith.Nat).Mul(sk.Q.Nat(), sk.Q.Nat(), 2*sk.Q.BitLen())
	sk.qq = saferith.ModulusFromNat(qq)
	sk.phiQQ = saferith.ModulusFromNat(new(saferith.Nat).Mul(sk.Q.Nat(), sk.qm1.Nat(), 2*sk.Q.BitLen()))
	gToQm1 := new(saferith.Nat).ModSub(one, sk.N.Nat(), sk.qq)
	hqInv := sk.lq(gToQm1)
	sk.hq = new(saferith.Nat).ModInverse(hqInv, sk.Q)
	sk.nq = new(saferith.Nat).Mod(sk.N.Nat(), sk.qm1)

	sk.qInv = new(saferith.Nat).ModInverse(sk.Q.Nat(), sk.P)
	sk.qqInv = new(saferith.Nat).ModInverse(sk.qq.Nat(), sk.pp)
	sk.phi = saferith.ModulusFromNat(new(saferith.Nat).Mul(sk.pm1.Nat(), sk.qm1.Nat(), sk.N.BitLen()))
	sk.phiNN = saferith.ModulusFromNat(new(saferith.Nat).Mul(sk.phiPP.Nat(), sk.phiQQ.Nat(), 2*sk.N.BitLen()))
	nInv := new(saferith.Nat).ModInverse(sk.N.Nat(), sk.phi)
	sk.nInvP = new(saferith.Nat).Mod(nInv, sk.pm1)
	sk.nInvQ = new(saferith.Nat).Mod(nInv, sk.qm1)
}

func (sk *SecretKey) lp(x *saferith.Nat) *saferith.Nat {
	xm1 := new(saferith.Nat).Sub(x, one, sk.pp.BitLen())
	return new(saferith.Nat).Div(xm1, sk.P, sk.P.BitLen())
}

func (sk *SecretKey) lq(x *saferith.Nat) *saferith.Nat {
	xm1 := new(saferith.Nat).Sub(x, one, sk.qq.BitLen())
	return new(saferith.Nat).Div(xm1, sk.Q, sk.Q.BitLen())
}

func (sk *SecretKey) rToN(r *saferith.Nat) (*saferith.Nat, error) {
	var rpp, rqq *saferith.Nat
	var eg errgroup.Group
	eg.Go(func() error {
		var err error
		rpp, err = modular.FastExp(r, sk.N.Nat(), sk.pp)
		return err //nolint:wrapcheck // checked in eg.Wait()
	})
	eg.Go(func() error {
		var err error
		rqq, err = modular.FastExp(r, sk.N.Nat(), sk.qq)
		return err //nolint:wrapcheck // checked in eg.Wait()
	})

	err := eg.Wait()
	if err != nil {
		return nil, errs.NewFailed("failed to compute r^N")
	}

	return numutils.CrtWithPrecomputation(rpp, rqq, sk.pp, sk.qq.Nat(), sk.qqInv), nil
}

func (sk *SecretKey) validCiphertext(cipherText *CipherText) bool {
	if cipherText == nil {
		return false
	}
	_, _, l := cipherText.C.CmpMod(sk.nn)
	if l == 0 || cipherText.C.IsUnit(sk.P) == 0 || cipherText.C.IsUnit(sk.Q) == 0 {
		return false
	}

	return true
}

func (sk *SecretKey) validNonce(nonce *Nonce) bool {
	if nonce == nil {
		return false
	}
	_, _, l := nonce.CmpMod(sk.N)
	if l == 0 || nonce.IsUnit(sk.P) == 0 || nonce.IsUnit(sk.Q) == 0 {
		return false
	}

	return true
}

type secretKeyJson struct {
	P string `json:"p"`
	Q string `json:"q"`
}
