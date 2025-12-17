package paillier

import (
	"io"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
)

// KeyGeneratorOption is a functional option for configuring the key generator.
type KeyGeneratorOption = encryption.KeyGeneratorOption[*KeyGenerator, *PrivateKey, *PublicKey]

// WithEachPrimeBitLen sets the bit length for each prime factor (p and q).
// The resulting modulus n = p*q will have approximately 2*bits bits.
func WithEachPrimeBitLen(bits uint) KeyGeneratorOption {
	return func(kg *KeyGenerator) error {
		kg.bits = bits
		return nil
	}
}

// KeyGenerator generates Paillier key pairs with configurable parameters.
type KeyGenerator struct {
	bits uint
}

// Generate creates a new Paillier key pair using the configured parameters.
// Returns the private key, public key, and any error encountered.
func (kg *KeyGenerator) Generate(prng io.Reader) (*PrivateKey, *PublicKey, error) {
	group, err := znstar.SamplePaillierGroup(kg.bits, prng)
	if err != nil {
		return nil, nil, errs2.Wrap(err)
	}
	sk, err := NewPrivateKey(group)
	if err != nil {
		return nil, nil, err
	}
	pk, err := NewPublicKey(group.ForgetOrder())
	if err != nil {
		return nil, nil, errs2.Wrap(err)
	}
	return sk, pk, nil
}

// EncrypterOption is a functional option for configuring the encrypter.
type EncrypterOption = encryption.EncrypterOption[*Encrypter, *PublicKey, *Plaintext, *Ciphertext, *Nonce]

// Encrypter performs Paillier encryption using a receiver's public key.
type Encrypter struct{}

// Encrypt encrypts a plaintext for the given receiver using a fresh random nonce.
// Returns the ciphertext, the nonce used, and any error encountered.
func (e *Encrypter) Encrypt(plaintext *Plaintext, receiver *PublicKey, prng io.Reader) (*Ciphertext, *Nonce, error) {
	nonce, err := receiver.NonceSpace().Sample(prng)
	if err != nil {
		return nil, nil, errs2.Wrap(err)
	}
	ciphertext, err := e.EncryptWithNonce(plaintext, receiver, nonce)
	if err != nil {
		return nil, nil, errs2.Wrap(err)
	}
	return ciphertext, nonce, nil
}

// EncryptWithNonce encrypts a plaintext using a provided nonce.
// The ciphertext is computed as c = g^m * r^n mod n².
func (e *Encrypter) EncryptWithNonce(plaintext *Plaintext, receiver *PublicKey, nonce *Nonce) (*Ciphertext, error) {
	embeddedNonce, err := receiver.group.EmbedRSA(nonce.Value())
	if err != nil {
		return nil, errs2.Wrap(err)
	}
	rn, err := receiver.group.NthResidue(embeddedNonce)
	if err != nil {
		return nil, errs2.Wrap(err)
	}
	gm, err := receiver.group.Representative(plaintext.ValueCT())
	if err != nil {
		return nil, errs2.Wrap(err)
	}
	return &Ciphertext{u: rn.Mul(gm)}, nil
}

// EncryptMany encrypts multiple plaintexts in parallel using fresh random nonces.
// Returns the ciphertexts, the nonces used, and any error encountered.
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
		return nil, nil, errs2.Wrap(err)
	}
	cts, err := e.EncryptManyWithNonces(plaintexts, receiver, nonces)
	if err != nil {
		return nil, nil, errs2.Wrap(err)
	}
	return cts, nonces, nil
}

// EncryptManyWithNonces encrypts multiple plaintexts in parallel using provided nonces.
// The length of plaintexts and nonces must match.
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
		return nil, errs2.Wrap(err)
	}
	return cts, nil
}

// SelfEncrypterOption is a functional option for configuring the self-encrypter.
type SelfEncrypterOption = func(*SelfEncrypter) error

// SelfEncrypter performs Paillier encryption to oneself using CRT optimizations.
// This is more efficient than regular encryption when encrypting to one's own public key.
type SelfEncrypter struct {
	sk *PrivateKey
	pk *PublicKey
}

// PrivateKey returns the private key used by this self-encrypter.
func (se *SelfEncrypter) PrivateKey() *PrivateKey {
	return se.sk
}

// SelfEncrypt encrypts a plaintext to oneself using a fresh random nonce.
// Uses CRT optimizations for faster encryption.
func (se *SelfEncrypter) SelfEncrypt(plaintext *Plaintext, prng io.Reader) (*Ciphertext, *Nonce, error) {
	nonce, err := se.pk.NonceSpace().Sample(prng)
	if err != nil {
		return nil, nil, errs2.Wrap(err)
	}
	ciphertext, err := se.SelfEncryptWithNonce(plaintext, nonce)
	if err != nil {
		return nil, nil, errs2.Wrap(err)
	}
	return ciphertext, nonce, nil
}

// SelfEncryptWithNonce encrypts a plaintext to oneself using a provided nonce.
// Uses CRT optimizations for faster encryption.
func (se *SelfEncrypter) SelfEncryptWithNonce(plaintext *Plaintext, nonce *Nonce) (*Ciphertext, error) {
	embeddedNonce, err := se.pk.group.EmbedRSA(nonce.Value())
	if err != nil {
		return nil, errs2.Wrap(err)
	}
	rn, err := se.sk.group.NthResidue(embeddedNonce)
	if err != nil {
		return nil, errs2.Wrap(err)
	}
	gm, err := se.sk.group.Representative(plaintext.ValueCT())
	if err != nil {
		return nil, errs2.Wrap(err)
	}
	return &Ciphertext{u: rn.Mul(gm).ForgetOrder()}, nil
}

// SelfEncryptMany encrypts multiple plaintexts to oneself in parallel.
// Uses CRT optimizations for faster encryption.
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
		return nil, nil, errs2.Wrap(err)
	}
	cts, err := se.SelfEncryptManyWithNonces(plaintexts, nonces)
	if err != nil {
		return nil, nil, errs2.Wrap(err)
	}
	return cts, nonces, nil
}

// SelfEncryptManyWithNonces encrypts multiple plaintexts to oneself using provided nonces.
// The length of plaintexts and nonces must match.
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
		return nil, errs2.Wrap(err)
	}
	return cts, nil
}

// DecrypterOption is a functional option for configuring the decrypter.
type DecrypterOption = encryption.DecrypterOption[*Decrypter, *Plaintext, *Ciphertext]

// Decrypter performs Paillier decryption using the private key.
// Uses CRT for efficient decryption.
type Decrypter struct {
	sk *PrivateKey
}

// Decrypt decrypts a ciphertext and returns the plaintext.
// Uses CRT-based decryption for efficiency.
func (d *Decrypter) Decrypt(ciphertext *Ciphertext) (*Plaintext, error) {
	var mp, mq numct.Nat
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
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
		return nil, errs2.Wrap(err)
	}
	return out, nil
}
