package encryption

import (
	"io"

	"golang.org/x/sync/errgroup"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/utils"
)

func Encrypt[P Plaintext, N Nonce, C Ciphertext[C]](plaintext P, receiver encryptionKey[P, N, C], prng io.Reader) (ciphertext C, nonce N, err error) {
	if utils.IsNil(plaintext) || receiver == nil || prng == nil {
		return *new(C), *new(N), ErrIsNil.WithMessage("plaintext, receiver, and prng must not be nil")
	}
	nonce, err = receiver.SampleNonce(prng)
	if err != nil {
		return *new(C), *new(N), errs.Wrap(err).WithMessage("could not sample nonce")
	}
	ciphertext, err = receiver.EncryptWithNonce(plaintext, nonce)
	if err != nil {
		return *new(C), *new(N), errs.Wrap(err).WithMessage("could not compute ciphertext")
	}
	return ciphertext, nonce, nil
}

func EncryptMany[P Plaintext, N Nonce, C Ciphertext[C]](plaintexts []P, receiver encryptionKey[P, N, C], prng io.Reader) (ciphertexts []C, nonces []N, err error) {
	if len(plaintexts) < 2 {
		return nil, nil, ErrIsNil.WithMessage("must encrypt at least 2 plaintexts")
	}
	ciphertexts = make([]C, len(plaintexts))
	nonces = make([]N, len(plaintexts))
	var eg errgroup.Group
	for i, p := range plaintexts {
		eg.Go(func() error {
			var err error
			ciphertexts[i], nonces[i], err = Encrypt(p, receiver, prng)
			if err != nil {
				return errs.Wrap(err).WithMessage("could not encrypt plaintext at index %d", i)
			}
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not encrypt plaintexts")
	}
	return ciphertexts, nonces, nil
}

func EncryptManyWithNonces[P Plaintext, N Nonce, C Ciphertext[C]](plaintexts []P, receiver encryptionKey[P, N, C], nonces []N) (ciphertexts []C, err error) {
	if receiver == nil {
		return nil, ErrIsNil.WithMessage("receiver must not be nil")
	}

	obj, internallyDefined := any(receiver).(interface {
		EncryptManyWithNonces([]P, []N) ([]C, error)
	})
	if internallyDefined {
		ciphertexts, err = obj.EncryptManyWithNonces(plaintexts, nonces)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not encrypt plaintexts with nonces using receiver's internal implementation")
		}
		return ciphertexts, nil
	}

	if len(plaintexts) != len(nonces) {
		return nil, ErrIsNil.WithMessage("number of plaintexts and nonces must be the same")
	}
	if len(plaintexts) < 2 {
		return nil, ErrIsNil.WithMessage("must encrypt at least 2 plaintexts")
	}
	ciphertexts = make([]C, len(plaintexts))
	var eg errgroup.Group
	for i, p := range plaintexts {
		eg.Go(func() error {
			var err error
			ciphertexts[i], err = receiver.EncryptWithNonce(p, nonces[i])
			if err != nil {
				return errs.Wrap(err).WithMessage("could not encrypt plaintext at index %d", i)
			}
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return nil, errs.Wrap(err).WithMessage("could not encrypt plaintexts")
	}
	return ciphertexts, nil
}

func DecryptMany[EK EncryptionKey[EK, P, N, C], DK DecryptionKey[EK, DK, P, N, C], P Plaintext, N Nonce, C Ciphertext[C]](ciphertexts []C, receiver DK) (plaintexts []P, err error) {
	if utils.IsNil(receiver) {
		return nil, ErrIsNil.WithMessage("receiver must not be nil")
	}

	obj, internallyDefined := any(receiver).(interface {
		DecryptMany([]C) ([]P, error)
	})
	if internallyDefined {
		plaintexts, err = obj.DecryptMany(ciphertexts)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not decrypt ciphertexts using receiver's internal implementation")
		}
		return plaintexts, nil
	}

	if len(ciphertexts) < 2 {
		return nil, ErrIsNil.WithMessage("must decrypt at least 2 ciphertexts")
	}
	plaintexts = make([]P, len(ciphertexts))
	var eg errgroup.Group
	for i, c := range ciphertexts {
		eg.Go(func() error {
			var err error
			plaintexts[i], err = receiver.Decrypt(c)
			if err != nil {
				return errs.Wrap(err).WithMessage("could not decrypt ciphertext at index %d", i)
			}
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return nil, errs.Wrap(err).WithMessage("could not decrypt ciphertexts")
	}
	return plaintexts, nil
}

func OpenMany[EK EncryptionKey[EK, P, N, C], OK OpeningKey[EK, OK, P, N, C], P Plaintext, N Nonce, C Ciphertext[C]](ciphertexts []C, receiver OK) (plaintexts []P, nonces []N, err error) {
	if utils.IsNil(receiver) {
		return nil, nil, ErrIsNil.WithMessage("receiver must not be nil")
	}

	obj, internallyDefined := any(receiver).(interface {
		OpenMany([]C) ([]P, []N, error)
	})
	if internallyDefined {
		plaintexts, nonces, err = obj.OpenMany(ciphertexts)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("could not open ciphertexts using receiver's internal implementation")
		}
		return plaintexts, nonces, nil
	}

	if len(ciphertexts) < 2 {
		return nil, nil, ErrIsNil.WithMessage("must decrypt at least 2 ciphertexts")
	}
	plaintexts = make([]P, len(ciphertexts))
	nonces = make([]N, len(ciphertexts))
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
