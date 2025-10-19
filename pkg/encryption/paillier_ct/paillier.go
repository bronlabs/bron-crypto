package paillier

import (
	"io"
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/modular"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
)

const Name encryption.Name = "paillier"

func NewScheme() *Scheme {
	return &Scheme{}
}

type Scheme struct{}

func (s *Scheme) Name() encryption.Name {
	return Name
}

func (s *Scheme) Keygen(opts ...KeyGeneratorOption) (*KeyGenerator, error) {
	kg := &KeyGenerator{}
	for _, opt := range opts {
		if err := opt(kg); err != nil {
			return nil, errs.WrapFailed(err, "failed to apply key generator option")
		}
	}
	return kg, nil
}

func (s *Scheme) Encrypter(opts ...EncrypterOption) (*Encrypter, error) {
	e := &Encrypter{}
	for _, opt := range opts {
		if err := opt(e); err != nil {
			return nil, errs.WrapFailed(err, "failed to apply encrypter option")
		}
	}
	return e, nil
}

func (s *Scheme) SelfEncrypter(sk *PrivateKey, opts ...SelfEncrypterOption) (*SelfEncrypter, error) {
	if sk == nil {
		return nil, errs.NewIsNil("sk")
	}
	se := &SelfEncrypter{sk: sk, pk: sk.PublicKey()}
	se.pk.cacheSpaces()
	for _, opt := range opts {
		if err := opt(se); err != nil {
			return nil, errs.WrapFailed(err, "failed to apply self-encrypter option")
		}
	}
	return se, nil
}

func (s *Scheme) Decrypter(sk *PrivateKey, opts ...DecrypterOption) (*Decrypter, error) {
	if sk == nil {
		return nil, errs.NewIsNil("sk")
	}
	d := &Decrypter{sk: sk}
	for _, opt := range opts {
		if err := opt(d); err != nil {
			return nil, errs.WrapFailed(err, "failed to apply decrypter option")
		}
	}
	return d, nil
}

type KeyGeneratorOption = encryption.KeyGeneratorOption[*KeyGenerator, *PrivateKey, *PublicKey]

type KeyGenerator struct{}

func (kg *KeyGenerator) Generate(prng io.Reader) (*PrivateKey, *PublicKey, error) {
	if prng == nil {
		return nil, nil, errs.NewIsNil("prng")
	}
	p, q, err := nt.GeneratePrimePair(num.NPlus(), 2048, prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "failed to generate prime pair")
	}
	group, err := znstar.NewPaillierGroup(p, q)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "failed to create paillier group")
	}
	sk, err := NewPrivateKey(group)
	if err != nil {
		return nil, nil, err
	}
	pk, err := NewPublicKey(group.ForgetOrder())
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "failed to create public key")
	}
	// pk := &PublicKey{n2: sk.arith.N2, n: sk.arith.N, nNat: sk.arith.N.Nat()}
	return sk, pk, nil
}

type EncrypterOption = encryption.EncrypterOption[*Encrypter, *PublicKey, *Plaintext, *Ciphertext, *Nonce]

type Encrypter struct{}

func (e *Encrypter) Encrypt(plaintext *Plaintext, receiver *PublicKey, prng io.Reader) (*Ciphertext, *Nonce, error) {
	nonce, err := receiver.NonceSpace().Sample(prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "failed to sample nonce from nonce space")
	}
	ciphertext, err := e.EncryptWithNonce(plaintext, receiver, nonce)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "failed to encrypt with nonce")
	}
	return ciphertext, nonce, nil
}

func (e *Encrypter) EncryptWithNonce(plaintext *Plaintext, receiver *PublicKey, nonce *Nonce) (*Ciphertext, error) {
	var rn numct.Nat
	receiver.n2.ModExp(&rn, nonce.Value(), receiver.nNat)

	// c = g^m * r^n mod n^2
	var out numct.Nat
	receiver.n2.ModMul(&out, Phi(receiver, plaintext), &rn)

	// Ensure the result is in range [0, n^2)
	receiver.n2.Mod(&out, &out)

	ct, err := receiver.CiphertextSpace().New(&out)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create ciphertext from nat")
	}
	return ct, nil
}

type SelfEncrypterOption = func(*SelfEncrypter) error

type SelfEncrypter struct {
	sk *PrivateKey
	pk *PublicKey
}

func (se *SelfEncrypter) SelfEncrypt(plaintext *Plaintext, prng io.Reader) (*Ciphertext, *Nonce, error) {
	nonce, err := se.pk.NonceSpace().Sample(prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "failed to sample nonce from nonce space")
	}
	ciphertext, err := se.SelfEncryptWithNonce(plaintext, nonce)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "failed to self-encrypt with nonce")
	}
	return ciphertext, nonce, nil
}

func (se *SelfEncrypter) SelfEncryptWithNonce(plaintext *Plaintext, nonce *Nonce) (*Ciphertext, error) {
	var rn numct.Nat
	se.sk.arith.ExpToN(&rn, nonce.Value())

	// c = g^m * r^n mod n^2
	var out numct.Nat
	se.sk.arith.N2.ModMul(&out, Phi(se.pk, plaintext), &rn)

	ct, err := se.pk.CiphertextSpace().New(&out)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create ciphertext from nat")
	}
	return ct, nil
}

type DecrypterOption = encryption.DecrypterOption[*Decrypter, *Plaintext, *Ciphertext]

type Decrypter struct {
	sk *PrivateKey
}

func (d *Decrypter) Decrypt(ciphertext *Ciphertext) (*Plaintext, error) {
	var mp, mq numct.Nat
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		d.sk.arith.P.Squared.ModExp(&mp, ciphertext.Value(), d.sk.arith.P.PhiFactor.Nat())
		d.lp(&mp)
		d.sk.arith.P.Factor.ModMul(&mp, &mp, d.sk.hp)
	}()
	go func() {
		defer wg.Done()
		d.sk.arith.Q.Squared.ModExp(&mq, ciphertext.Value(), d.sk.arith.Q.PhiFactor.Nat())
		d.lq(&mq)
		d.sk.arith.Q.Factor.ModMul(&mq, &mq, d.sk.hq)
	}()
	wg.Wait()
	out, err := d.sk.PublicKey().PlaintextSpace().New(d.sk.arith.CrtModN.Params.Recombine(&mp, &mq))
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create plaintext from recombined nat")
	}
	return out, nil
}

func (d *Decrypter) lp(x *numct.Nat) {
	d.sk.arith.P.Squared.ModSub(x, x, numct.NatOne())
	d.sk.arith.P.Factor.Quo(x, x)
}

func (d *Decrypter) lq(x *numct.Nat) {
	d.sk.arith.Q.Squared.ModSub(x, x, numct.NatOne())
	d.sk.arith.Q.Factor.Quo(x, x)
}

func NewPrivateKey(group znstar.PaillierGroupKnownOrder) (*PrivateKey, error) {
	if group == nil {
		return nil, errs.NewIsNil("m")
	}
	var hp, hq numct.Nat
	group.Arithmetic().P.Factor.ModInv(&hp, group.Arithmetic().Q.Factor.Nat())
	group.Arithmetic().P.Factor.ModNeg(&hp, &hp)
	group.Arithmetic().Q.Factor.ModInv(&hq, group.Arithmetic().P.Factor.Nat())
	group.Arithmetic().Q.Factor.ModNeg(&hq, &hq)

	return &PrivateKey{
		arith: group.Arithmetic(),
		hp:    &hp,
		hq:    &hq,
	}, nil
}

type PrivateKey struct {
	// group znstar.PaillierGroupKnownOrder

	arith *modular.OddPrimeSquareFactors
	hp    *numct.Nat
	hq    *numct.Nat

	pk   *PublicKey
	once sync.Once
}

func (sk *PrivateKey) cachePublicKey() {
	sk.once.Do(func() {
		sk.pk = &PublicKey{n2: sk.arith.N2, n: sk.arith.CrtModN.N, nNat: sk.arith.CrtModN.N.Nat()}
	})
}

func (sk *PrivateKey) Arithmetic() *modular.OddPrimeSquareFactors {
	return sk.arith
}

func (sk *PrivateKey) PublicKey() *PublicKey {
	sk.cachePublicKey()
	return sk.pk
}

func (sk *PrivateKey) Equal(other *PrivateKey) bool {
	if sk == nil || other == nil {
		return sk == other
	}
	return (sk.arith.P.Factor.Nat().Equal(other.arith.P.Factor.Nat()) & sk.arith.Q.Factor.Nat().Equal(other.arith.Q.Factor.Nat())) == ct.True
}

func NewPublicKey(group znstar.PaillierGroup) (*PublicKey, error) {
	if group == nil {
		return nil, errs.NewIsNil("group")
	}
	return &PublicKey{
		// group: group,
		n2:   group.ModulusCT(),
		n:    group.N().ModulusCT(),
		nNat: group.N().Value(),
	}, nil
}

type PublicKey struct {
	// group znstar.PaillierGroup

	n2   numct.Modulus
	n    numct.Modulus
	nNat *numct.Nat

	plaintextSpace  *PlaintextSpace
	nonceSpace      *NonceSpace
	ciphertextSpace *CiphertextSpace
	once            sync.Once
}

func (pk *PublicKey) Equal(other *PublicKey) bool {
	if pk == nil || other == nil {
		return pk == other
	}
	return (pk.n2.Nat().Equal(other.n2.Nat()) & pk.n.Nat().Equal(other.n.Nat())) == ct.True
}

func (pk *PublicKey) Modulus() numct.Modulus {
	return pk.n2
}

func (pk *PublicKey) N() numct.Modulus {
	return pk.n
}

func (pk *PublicKey) N2() numct.Modulus {
	return pk.n2
}

func (pk *PublicKey) Clone() *PublicKey {
	n2, ok1 := numct.NewModulus(pk.n2.Nat())
	n, ok2 := numct.NewModulus(pk.nNat)
	if ok1&ok2 == ct.False {
		panic("failed to clone public key")
	}
	return &PublicKey{
		n2:   n2,
		n:    n,
		nNat: pk.nNat.Clone(),
	}
}

func (pk *PublicKey) HashCode() base.HashCode {
	return pk.n2.HashCode().Combine(pk.n.HashCode())
}

func (pk *PublicKey) cacheSpaces() {
	pk.once.Do(func() {
		pk.plaintextSpace = &PlaintextSpace{
			n: pk.n,
		}
		pk.ciphertextSpace = &CiphertextSpace{
			n2: pk.n2,
		}
		pk.nonceSpace = &NonceSpace{
			n: pk.n,
		}
	})
}

func (pk *PublicKey) PlaintextSpace() *PlaintextSpace {
	// pk.cacheSpaces()
	if pk.plaintextSpace == nil {
		pk.cacheSpaces()
	}
	return pk.plaintextSpace
}

func (pk *PublicKey) NonceSpace() *NonceSpace {
	// pk.cacheSpaces()
	if pk.nonceSpace == nil {
		pk.cacheSpaces()
	}
	return pk.nonceSpace
}

func (pk *PublicKey) CiphertextSpace() *CiphertextSpace {
	// pk.cacheSpaces()
	if pk.ciphertextSpace == nil {
		pk.cacheSpaces()
	}
	return pk.ciphertextSpace
}

func Phi(receiver *PublicKey, plaintext *Plaintext) *numct.Nat {
	var out numct.Nat
	receiver.n2.ModMul(&out, plaintext.Value(), receiver.nNat)
	out.Increment()
	return &out
}

func NewCiphertextSpace(x *numct.Nat) (*CiphertextSpace, error) {
	n2, ok := numct.NewModulus(x)
	if ok == ct.False {
		return nil, errs.NewFailed("failed to create ZMod for ciphertext space")
	}
	return &CiphertextSpace{n2: n2}, nil
}

type CiphertextSpace struct {
	n2 numct.Modulus
}

func (cts *CiphertextSpace) N2() numct.Modulus {
	return cts.n2
}

func (cts *CiphertextSpace) Sample(prng io.Reader) (*Ciphertext, error) {
	v, err := cts.n2.Random(prng)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "failed to sample from ciphertext space")
	}
	return (*Ciphertext)(v), nil
}

func (cts *CiphertextSpace) New(x *numct.Nat) (*Ciphertext, error) {
	if cts.n2.IsInRange(x) == ct.False {
		return nil, errs.NewValue("not in range of ciphertext space")
	}
	return (*Ciphertext)(x), nil
}

func (cts *CiphertextSpace) Contains(c *Ciphertext) bool {
	return cts.n2.IsInRange(c.Value()) == ct.True
}

type Ciphertext numct.Nat

func (c *Ciphertext) Value() *numct.Nat {
	return (*numct.Nat)(c)
}

func (c *Ciphertext) Op(other *Ciphertext) *Ciphertext {
	if other == nil {
		panic("cannot operate on ciphertexts with different moduli")
	}
	var out numct.Nat
	out.Mul(c.Value(), other.Value())
	return (*Ciphertext)(&out)
}

func (c *Ciphertext) Equal(other *Ciphertext) bool {
	return c.Value().Equal(other.Value()) == ct.True
}

// func (ct *Ciphertext) ScalarOp(scalar *numct.Nat) *Ciphertext {
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

// func (ct *Ciphertext) Shift(message *Plaintext) *Ciphertext {
// 	var out numct.Nat
// 	receiver.n2.ModMul(&out, plaintext.ValueCT(), receiver.nNat)
// 	out.Increment()
// 	return nil
// }.

func NewNonceSpace(n *numct.Nat) (*NonceSpace, error) {
	g, ok := numct.NewModulus(n)
	if ok == ct.False {
		return nil, errs.NewFailed("failed to create ZMod for nonce space")
	}
	return &NonceSpace{n: g}, nil
}

type NonceSpace struct {
	n numct.Modulus
}

func (ns *NonceSpace) N() numct.Modulus {
	return ns.n
}

func (ns *NonceSpace) Sample(prng io.Reader) (*Nonce, error) {
	v, err := ns.n.Random(prng)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "failed to sample from nonce space")
	}
	return (*Nonce)(v), nil
}

func (ns *NonceSpace) New(x *numct.Nat) (*Nonce, error) {
	if ns.n.IsInRange(x) == ct.False {
		return nil, errs.NewValue("not in range of nonce space")
	}
	return (*Nonce)(x), nil
}

func (ns *NonceSpace) Contains(n *Nonce) bool {
	return ns.n.IsInRange(n.Value()) == ct.True
}

type Nonce numct.Nat

func (n *Nonce) Value() *numct.Nat {
	return (*numct.Nat)(n)
}

func (n *Nonce) Op(other *Nonce) *Nonce {
	if other == nil {
		panic("cannot operate on nonce with different moduli")
	}
	var out numct.Nat
	out.Add(n.Value(), other.Value())
	return (*Nonce)(&out)
}

func (n *Nonce) Equal(other *Nonce) bool {
	return n.Value().Equal(other.Value()) == ct.True
}

func NewPlaintextSpace(n *numct.Nat) (*PlaintextSpace, error) {
	out, ok := numct.NewModulus(n)
	if ok == ct.False {
		return nil, errs.NewFailed("failed to create ZMod for plaintext space")
	}
	return &PlaintextSpace{n: out}, nil
}

type PlaintextSpace struct {
	n numct.Modulus
}

func (pts *PlaintextSpace) N() numct.Modulus {
	return pts.n
}

func (pts *PlaintextSpace) Sample(prng io.Reader) (*Plaintext, error) {
	v, err := pts.n.Random(prng)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "failed to sample from plaintext space")
	}
	return (*Plaintext)(v), nil
}

func (pts *PlaintextSpace) CenterAtZero(m *Plaintext) (*numct.Int, error) {
	if m == nil {
		return nil, errs.NewIsNil("m")
	}
	var out numct.Int
	pts.n.ModSymmetric(&out, m.Value())
	return &out, nil
}

func (pts *PlaintextSpace) Normalise(centred *numct.Int) (*Plaintext, error) {
	if centred == nil {
		return nil, errs.NewIsNil("centred")
	}
	if pts.n.IsInRangeSymmetric(centred) == ct.False {
		return nil, errs.NewValue("not in range of plaintext space")
	}
	var out numct.Nat
	pts.n.ModInt(&out, centred)
	return (*Plaintext)(&out), nil
}

func (pts *PlaintextSpace) Contains(m *Plaintext) bool {
	return pts.n.IsInRange((*numct.Nat)(m)) == ct.True
}

func (pts *PlaintextSpace) New(x *numct.Nat) (*Plaintext, error) {
	if pts.n.IsInRange(x) == ct.False {
		return nil, errs.NewValue("not in range of plaintext space")
	}
	return (*Plaintext)(x), nil
}

type Plaintext numct.Nat

func (pt *Plaintext) Value() *numct.Nat {
	return (*numct.Nat)(pt)
}

func (pt *Plaintext) Op(other *Plaintext) *Plaintext {
	if other == nil {
		panic("cannot operate on plaintexts with different moduli")
	}
	var out numct.Nat
	out.Add(pt.Value(), other.Value())
	return (*Plaintext)(&out)
}

func (pt *Plaintext) Equal(other *Plaintext) bool {
	return pt.Value().Equal(other.Value()) == ct.True
}
