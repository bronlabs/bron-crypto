package encryption

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/errs-go/errs"
	"golang.org/x/sync/errgroup"
)

func Encrypt[P Plaintext, N Nonce, C Ciphertext[C]](plaintext P, receiver encryptionKey[P, N, C], prng io.Reader) (C, N, error) {
	if utils.IsNil(plaintext) || receiver == nil || prng == nil {
		return *new(C), *new(N), ErrIsNil.WithMessage("plaintext, receiver, and prng must not be nil")
	}
	nonce, err := receiver.SampleNonce(prng)
	if err != nil {
		return *new(C), *new(N), errs.Wrap(err).WithMessage("could not sample nonce")
	}
	ciphertext, err := receiver.EncryptWithNonce(plaintext, nonce)
	if err != nil {
		return *new(C), *new(N), errs.Wrap(err).WithMessage("could not compute ciphertext")
	}
	return ciphertext, nonce, nil
}

func EncryptMany[P Plaintext, N Nonce, C Ciphertext[C]](plaintexts []P, receiver encryptionKey[P, N, C], prng io.Reader) ([]C, []N, error) {
	if len(plaintexts) < 2 {
		return nil, nil, ErrIsNil.WithMessage("must encrypt at least 2 plaintexts")
	}
	out := make([]C, len(plaintexts))
	nonces := make([]N, len(plaintexts))
	var eg errgroup.Group
	for i, p := range plaintexts {
		eg.Go(func() error {
			var err error
			out[i], nonces[i], err = Encrypt(p, receiver, prng)
			if err != nil {
				return errs.Wrap(err).WithMessage("could not encrypt plaintext at index %d", i)
			}
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not encrypt plaintexts")
	}
	return out, nonces, nil
}

func EncryptManyWithNonces[P Plaintext, N Nonce, C Ciphertext[C]](plaintexts []P, receiver encryptionKey[P, N, C], nonces []N) ([]C, error) {
	if receiver == nil {
		return nil, ErrIsNil.WithMessage("receiver must not be nil")
	}
	if len(plaintexts) != len(nonces) {
		return nil, ErrIsNil.WithMessage("number of plaintexts and nonces must be the same")
	}
	if len(plaintexts) < 2 {
		return nil, ErrIsNil.WithMessage("must encrypt at least 2 plaintexts")
	}
	out := make([]C, len(plaintexts))
	var eg errgroup.Group
	for i, p := range plaintexts {
		eg.Go(func() error {
			var err error
			out[i], err = receiver.EncryptWithNonce(p, nonces[i])
			if err != nil {
				return errs.Wrap(err).WithMessage("could not encrypt plaintext at index %d", i)
			}
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return nil, errs.Wrap(err).WithMessage("could not encrypt plaintexts")
	}
	return out, nil
}

func DecryptMany[EK EncryptionKey[EK, P, N, C], DK DecryptionKey[EK, DK, P, N, C], P Plaintext, N Nonce, C Ciphertext[C]](ciphertexts []C, receiver DK) ([]P, error) {
	if utils.IsNil(receiver) {
		return nil, ErrIsNil.WithMessage("receiver must not be nil")
	}
	if len(ciphertexts) < 2 {
		return nil, ErrIsNil.WithMessage("must decrypt at least 2 ciphertexts")
	}
	out := make([]P, len(ciphertexts))
	var eg errgroup.Group
	for i, c := range ciphertexts {
		eg.Go(func() error {
			var err error
			out[i], err = receiver.Decrypt(c)
			if err != nil {
				return errs.Wrap(err).WithMessage("could not decrypt ciphertext at index %d", i)
			}
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return nil, errs.Wrap(err).WithMessage("could not decrypt ciphertexts")
	}
	return out, nil
}

func OpenMany[EK EncryptionKey[EK, P, N, C], OK OpeningKey[EK, OK, P, N, C], P Plaintext, N Nonce, C Ciphertext[C]](ciphertexts []C, receiver OK) ([]P, []N, error) {
	if utils.IsNil(receiver) {
		return nil, nil, ErrIsNil.WithMessage("receiver must not be nil")
	}
	if len(ciphertexts) < 2 {
		return nil, nil, ErrIsNil.WithMessage("must decrypt at least 2 ciphertexts")
	}
	plaintexts := make([]P, len(ciphertexts))
	nonces := make([]N, len(ciphertexts))
	var eg errgroup.Group
	for i, c := range ciphertexts {
		eg.Go(func() error {
			var err error
			plaintexts[i], nonces[i], err = receiver.Open(c)
			if err != nil {
				return errs.Wrap(err).WithMessage("could not decrypt ciphertext at index %d", i)
			}
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not decrypt ciphertexts")
	}
	return plaintexts, nonces, nil
}
