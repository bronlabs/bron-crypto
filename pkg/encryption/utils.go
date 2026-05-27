package encryption

import (
	"io"

	"golang.org/x/sync/errgroup"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/utils"
)

// Encrypt samples a fresh nonce from prng and encrypts plaintext under it,
// returning both the ciphertext and the nonce. prng must be a cryptographically
// secure source; the returned nonce is secret randomness needed to open or
// re-randomise the ciphertext.
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

// EncryptMany encrypts each plaintext under its own freshly sampled nonce,
// concurrently, returning the ciphertexts and nonces in input order. It requires at
// least two plaintexts.
//
// prng is shared across the worker goroutines, so it MUST be safe for concurrent
// use (e.g. crypto/rand.Reader). A prng that is not concurrency-safe can race and,
// worse, hand out correlated or duplicated nonces across plaintexts — and nonce
// reuse breaks the scheme's security. Use EncryptManyWithNonces if your prng is not
// concurrency-safe.
func EncryptMany[P Plaintext, N Nonce, C Ciphertext[C]](plaintexts []P, receiver encryptionKey[P, N, C], prng io.Reader) (ciphertexts []C, nonces []N, err error) {
	if len(plaintexts) < 2 {
		return nil, nil, ErrOutOfRange.WithMessage("must encrypt at least 2 plaintexts")
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

// EncryptManyWithNonces encrypts each plaintext under the caller-supplied nonce at
// the same index. It samples no randomness, so there is no prng-concurrency
// concern. If receiver provides its own batched EncryptManyWithNonces it is used;
// otherwise the encryptions run concurrently. The plaintext and nonce counts must
// match, with at least two of each. The caller is responsible for supplying fresh,
// distinct nonces.
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
		return nil, ErrFailed.WithMessage("number of plaintexts and nonces must be the same")
	}
	if len(plaintexts) < 2 {
		return nil, ErrOutOfRange.WithMessage("must encrypt at least 2 plaintexts")
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

// DecryptMany decrypts each ciphertext, using receiver's own batched DecryptMany if
// it provides one (e.g. a CRT-batched implementation) and otherwise decrypting
// concurrently. It requires the decryption key and at least two ciphertexts.
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
		return nil, ErrOutOfRange.WithMessage("must decrypt at least 2 ciphertexts")
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

// OpenMany recovers the plaintext AND nonce of each ciphertext (see
// OpeningKey.Open), using receiver's own batched OpenMany if provided and otherwise
// running concurrently. It requires the opening key and at least two ciphertexts.
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
		return nil, nil, ErrOutOfRange.WithMessage("must decrypt at least 2 ciphertexts")
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
