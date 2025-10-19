package paillier

// import (
// 	"io"
// 	"sync"

// 	"github.com/bronlabs/bron-crypto/pkg/base"
// 	"github.com/bronlabs/bron-crypto/pkg/base/errs"
// 	"github.com/bronlabs/bron-crypto/pkg/base/nt/modular"
// 	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
// 	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
// 	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
// 	"github.com/bronlabs/bron-crypto/pkg/encryption"
// ).

// const Name encryption.Name = "paillier-gift".

// type Scheme struct{}.

// type KeyGenerator struct{}.

// type Encrypter struct{}.

// type SelfEncrypter struct{}.

// type Decrypter struct{}.

// func NewPrivateKey(group znstar.PaillierGroupKnownOrder) (*PrivateKey, error) {
// 	if group == nil {
// 		return nil, errs.NewIsNil("m")
// 	}
// 	var hp, hq numct.Nat
// 	group.Arithmetic().P.Factor.ModInv(&hp, group.Arithmetic().Q.Factor.Nat())
// 	group.Arithmetic().P.Factor.ModNeg(&hp, &hp)
// 	group.Arithmetic().Q.Factor.ModInv(&hq, group.Arithmetic().P.Factor.Nat())
// 	group.Arithmetic().Q.Factor.ModNeg(&hq, &hq)

// 	pk, err := NewPublicKey(group.ForgetOrder())
// 	if err != nil {
// 		return nil, err
// 	}

// 	return &PrivateKey{
// 		// arith: group.Arithmetic(),
// 		group: group,
// 		pk:    pk,
// 		hp:    &hp,
// 		hq:    &hq,
// 	}, nil
// }.

// type PrivateKey struct {
// 	group znstar.PaillierGroupKnownOrder

// 	hp *numct.Nat
// 	hq *numct.Nat

// 	pk *PublicKey
// }.

// func (sk *PrivateKey) Arithmetic() *modular.OddPrimeSquareFactors {
// 	return sk.group.Arithmetic()
// }.

// func (sk *PrivateKey) PublicKey() *PublicKey {
// 	return sk.pk
// }.

// func (sk *PrivateKey) Equal(other *PrivateKey) bool {
// 	if sk == nil || other == nil {
// 		return sk == other
// 	}
// 	return sk.group.Modulus().Equal(other.group.Modulus())
// }.

// func NewPublicKey(group znstar.PaillierGroup) (*PublicKey, error) {
// 	if group == nil {
// 		return nil, errs.NewIsNil("group")
// 	}
// 	if !group.Order().IsUnknown() {
// 		return nil, errs.NewValue("group order must be unknown")
// 	}
// 	return &PublicKey{
// 		group: group,
// 	}, nil
// }.

// type PublicKey struct {
// 	group znstar.PaillierGroup

// 	// n2   numct.Modulus
// 	// n    numct.Modulus
// 	// nNat *numct.Nat

// 	plaintextSpace  *PlaintextSpace
// 	nonceSpace      *NonceSpace
// 	ciphertextSpace *CiphertextSpace
// 	once            sync.Once
// }.

// func (pk *PublicKey) Equal(other *PublicKey) bool {
// 	if pk == nil || other == nil {
// 		return pk == other
// 	}
// 	return pk.group.Modulus().Equal(other.group.Modulus())
// }.

// func (pk *PublicKey) Modulus() numct.Modulus {
// 	return pk.group.ModulusCT()
// }.

// func (pk *PublicKey) N() numct.Modulus {
// 	return pk.group.N().ModulusCT()
// }.

// func (pk *PublicKey) N2() numct.Modulus {
// 	return pk.Modulus()
// }.

// func (pk *PublicKey) Clone() *PublicKey {
// 	g, err := znstar.NewPaillierGroupOfUnknownOrder(pk.group.Modulus(), pk.group.N())
// 	if err != nil {
// 		panic("failed to clone public key")
// 	}
// 	return &PublicKey{
// 		group: g,
// 	}
// }.

// func (pk *PublicKey) HashCode() base.HashCode {
// 	return pk.group.Modulus().HashCode().Combine(pk.group.N().HashCode())
// }.

// func (pk *PublicKey) cacheSpaces() {
// 	pk.once.Do(func() {
// 		var errPlaintext, errNonce, errCiphertext error
// 		n := num.NPlus().FromModulus(pk.n)
// 		nn := num.NPlus().FromModulus(pk.n2)
// 		pk.plaintextSpace, errPlaintext = NewPlaintextSpace(n)
// 		pk.nonceSpace, errNonce = NewNonceSpace(nn)
// 		pk.ciphertextSpace, errCiphertext = NewCiphertextSpace(nn, n)
// 		if errPlaintext != nil {
// 			panic(errPlaintext)
// 		}
// 		if errNonce != nil {
// 			panic(errNonce)
// 		}
// 		if errCiphertext != nil {
// 			panic(errCiphertext)
// 		}
// 	})
// }.

// func (pk *PublicKey) PlaintextSpace() *PlaintextSpace {
// 	pk.cacheSpaces()
// 	return pk.plaintextSpace
// }.

// func (pk *PublicKey) NonceSpace() *NonceSpace {
// 	pk.cacheSpaces()
// 	return pk.nonceSpace
// }.

// func (pk *PublicKey) CiphertextSpace() *CiphertextSpace {
// 	pk.cacheSpaces()
// 	return pk.ciphertextSpace
// }.

// func NewCiphertextSpace(n2, n *num.NatPlus) (*CiphertextSpace, error) {
// 	g, err := znstar.NewPaillierGroupOfUnknownOrder(n2, n)
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "failed to create unit group for ciphertext space")
// 	}
// 	return &CiphertextSpace{PaillierGroup: g}, nil
// }.

// type CiphertextSpace struct {
// 	znstar.PaillierGroup
// }.

// func (cts *CiphertextSpace) N2() *num.NatPlus {
// 	return cts.PaillierGroup.Modulus()
// }.

// func (cts *CiphertextSpace) Sample(prng io.Reader) (*Ciphertext, error) {
// 	v, err := cts.PaillierGroup.Random(prng)
// 	if err != nil {
// 		return nil, errs.WrapRandomSample(err, "failed to sample from ciphertext space")
// 	}
// 	return (*Ciphertext)(v), nil
// }.

// func (cts *CiphertextSpace) New(x *numct.Nat) (*Ciphertext, error) {
// 	y, err := num.NewUintGivenModulus(x, cts.N2().ModulusCT())
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "failed to create ciphertext from nat")
// 	}
// 	u, err := cts.PaillierGroup.FromUint(y)
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "failed to create ciphertext from n")
// 	}
// 	return (*Ciphertext)(u), nil
// }.

// func (cts *CiphertextSpace) Contains(ct *Ciphertext) bool {
// 	return ct != nil && cts.N2().Equal(ct.N2())
// }.

// type Ciphertext znstar.Unit.

// func (ct *Ciphertext) Value() *znstar.Unit {
// 	return (*znstar.Unit)(ct)
// }.

// func (ct *Ciphertext) ValueCT() *numct.Nat {
// 	return ct.Value().Value().Value()
// }.

// func (ct *Ciphertext) N2() *num.NatPlus {
// 	return ct.Value().Modulus()
// }.

// func (ct *Ciphertext) Op(other *Ciphertext) *Ciphertext {
// 	return (*Ciphertext)(ct.Value().Mul(other.Value()))
// }.

// func (ct *Ciphertext) ScalarOp(scalar *num.Nat) *Ciphertext {
// 	return (*Ciphertext)(ct.Value().Exp(scalar))
// }.

// func (ct *Ciphertext) ReRandomise(pk *PublicKey, prng io.Reader) (*Ciphertext, *Nonce, error) {
// 	nonce, err := pk.NonceSpace().Sample(prng)
// 	if err != nil {
// 		return nil, nil, errs.WrapRandomSample(err, "failed to sample nonce from nonce space")
// 	}
// 	ciphertext, err := ct.ReRandomiseWithNonce(pk, nonce)
// 	if err != nil {
// 		return nil, nil, errs.WrapFailed(err, "failed to re-randomise with nonce")
// 	}
// 	return ciphertext, nonce, nil
// }.

// func (ct *Ciphertext) ReRandomiseWithNonce(pk *PublicKey, nonce *Nonce) (*Ciphertext, error) {
// 	rn, err := pk.CiphertextSpace().PaillierGroup.LiftToNthResidues(nonce.Value())
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "failed to lift nonce to n-th residues")
// 	}
// 	// c' = c * r^n mod n^2
// 	return ct.Op((*Ciphertext)(rn)), nil
// }.
