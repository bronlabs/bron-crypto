package paillier

import (
	"io"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
)

type KeyGeneratorOption = encryption.KeyGeneratorOption[*KeyGenerator, *PrivateKey, *PublicKey]

func WithEachPrimeBitLen(bits uint) KeyGeneratorOption {
	return func(kg *KeyGenerator) error {
		kg.bits = bits
		return nil
	}
}

type KeyGenerator struct {
	bits uint
}

func (kg *KeyGenerator) Generate(prng io.Reader) (*PrivateKey, *PublicKey, error) {
	group, err := znstar.SamplePaillierGroup(kg.bits, prng)
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
	rn, err := receiver.group.LiftToNthResidues(nonce.Value())
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to lift nonce to n-th residues")
	}
	return &Ciphertext{u: rn.Mul(Phi(receiver, plaintext))}, nil
}

func (e *Encrypter) EncryptMany(plaintexts []*Plaintext, receiver *PublicKey, prng io.Reader) ([]*Ciphertext, []*Nonce, error) {
	nonces := make([]*Nonce, len(plaintexts))
	var eg errgroup.Group
	for i := range plaintexts {
		eg.Go(func() error {
			var err error
			nonces[i], err = receiver.NonceSpace().Sample(prng)
			return err
		})
	}
	if err := eg.Wait(); err != nil {
		return nil, nil, errs.WrapFailed(err, "failed to sample nonces")
	}
	cts, err := e.EncryptManyWithNonces(plaintexts, receiver, nonces)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "failed to encrypt many with nonces")
	}
	return cts, nonces, nil
}

func (e *Encrypter) EncryptManyWithNonces(plaintexts []*Plaintext, receiver *PublicKey, nonces []*Nonce) ([]*Ciphertext, error) {
	cts := make([]*Ciphertext, len(plaintexts))
	var eg errgroup.Group
	for i, p := range plaintexts {
		eg.Go(func() error {
			var err error
			cts[i], err = e.EncryptWithNonce(p, receiver, nonces[i])
			return err
		})
	}
	if err := eg.Wait(); err != nil {
		return nil, errs.WrapFailed(err, "failed to encrypt many with nonces")
	}
	return cts, nil
}

type SelfEncrypterOption = func(*SelfEncrypter) error

type SelfEncrypter struct {
	sk *PrivateKey
	pk *PublicKey
}

func (se *SelfEncrypter) PrivateKey() *PrivateKey {
	return se.sk
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
	rn, err := se.sk.group.LiftToNthResidues(nonce.Value())
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to lift nonce to n-th residues")
	}
	gm := Phi(se.pk, plaintext).LearnOrder(rn.Group())
	return &Ciphertext{u: rn.Mul(gm)}, nil
}

func (se *SelfEncrypter) SelfEncryptMany(plaintexts []*Plaintext, prng io.Reader) ([]*Ciphertext, []*Nonce, error) {
	nonces := make([]*Nonce, len(plaintexts))
	var eg errgroup.Group
	for i := range plaintexts {
		eg.Go(func() error {
			var err error
			nonces[i], err = se.pk.NonceSpace().Sample(prng)
			return err
		})
	}
	if err := eg.Wait(); err != nil {
		return nil, nil, errs.WrapFailed(err, "failed to sample nonces")
	}
	cts, err := se.SelfEncryptManyWithNonces(plaintexts, nonces)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "failed to self-encrypt many with nonces")
	}
	return cts, nonces, nil
}

func (se *SelfEncrypter) SelfEncryptManyWithNonces(plaintexts []*Plaintext, nonces []*Nonce) ([]*Ciphertext, error) {
	cts := make([]*Ciphertext, len(plaintexts))
	var eg errgroup.Group
	for i, p := range plaintexts {
		eg.Go(func() error {
			var err error
			cts[i], err = se.SelfEncryptWithNonce(p, nonces[i])
			return err
		})
	}
	if err := eg.Wait(); err != nil {
		return nil, errs.WrapFailed(err, "failed to self-encrypt many with nonces")
	}
	return cts, nil
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
		// TODO: put p.Squared and alike into a variable, everywhere here.
		d.sk.Arithmetic().P.Squared.ModExp(&mp, ciphertext.ValueCT(), d.sk.Arithmetic().P.PhiFactor.Nat())
		lp(d.sk, &mp)
		d.sk.Arithmetic().P.Factor.ModMul(&mp, &mp, d.sk.hp)
	}()
	go func() {
		defer wg.Done()
		d.sk.Arithmetic().Q.Squared.ModExp(&mq, ciphertext.ValueCT(), d.sk.Arithmetic().Q.PhiFactor.Nat())
		lq(d.sk, &mq)
		d.sk.Arithmetic().Q.Factor.ModMul(&mq, &mq, d.sk.hq)
	}()
	wg.Wait()
	out, err := d.sk.PublicKey().PlaintextSpace().FromNat(d.sk.Arithmetic().CrtModN.Params.Recombine(&mp, &mq))
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create plaintext from recombined nat")
	}
	return out, nil
}
