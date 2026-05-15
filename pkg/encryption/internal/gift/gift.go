package gift

import (
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
	"github.com/bronlabs/errs-go/errs"
)

func Encrypt[M encryption.Plaintext, N encryption.Nonce, C encryption.Ciphertext[C]](key interface {
	Representative(M) (C, error)
	IdentityNoise(N) (C, error)
	CiphertextOp(C, C, ...C) (C, error)
}, message M, nonce N) (C, error) {
	if key == nil || utils.IsNil(message) || utils.IsNil(nonce) {
		return *new(C), encryption.ErrIsNil.WithMessage("key, message, and nonce must not be nil")
	}
	gm, err := key.Representative(message)
	if err != nil {
		return *new(C), errs.Wrap(err).WithMessage("could not compute representative of message")
	}
	rn, err := key.IdentityNoise(nonce)
	if err != nil {
		return *new(C), errs.Wrap(err).WithMessage("could not compute encryption of zero from nonce")
	}
	ciphertext, err := key.CiphertextOp(gm, rn)
	if err != nil {
		return *new(C), errs.Wrap(err).WithMessage("could not compute ciphertext operation")
	}
	return ciphertext, nil
}

func ReRandomise[N encryption.Nonce, C encryption.Ciphertext[C]](key interface {
	IdentityNoise(N) (C, error)
	CiphertextOp(C, C, ...C) (C, error)
}, ciphertext C, nonce N) (C, error) {
	if utils.IsNil(key) || utils.IsNil(ciphertext) || utils.IsNil(nonce) {
		return *new(C), encryption.ErrIsNil.WithMessage("key, ciphertext, and nonce must not be nil")
	}
	encryptionOfZero, err := key.IdentityNoise(nonce)
	if err != nil {
		return *new(C), errs.Wrap(err).WithMessage("could not compute encryption of zero")
	}
	out, err := key.CiphertextOp(ciphertext, encryptionOfZero)
	if err != nil {
		return *new(C), errs.Wrap(err).WithMessage("could not compute ciphertext operation")
	}
	return out, nil
}

func Shift[M encryption.Plaintext, C encryption.Ciphertext[C]](key interface {
	Representative(M) (C, error)
	CiphertextOp(C, C, ...C) (C, error)
}, ciphertext C, delta M) (C, error) {
	if utils.IsNil(key) || utils.IsNil(ciphertext) || utils.IsNil(delta) {
		return *new(C), encryption.ErrIsNil.WithMessage("key, ciphertext, and delta must not be nil")
	}
	deltaCiphertext, err := key.Representative(delta)
	if err != nil {
		return *new(C), errs.Wrap(err).WithMessage("could not compute representative of delta")
	}
	out, err := key.CiphertextOp(ciphertext, deltaCiphertext)
	if err != nil {
		return *new(C), errs.Wrap(err).WithMessage("could not compute ciphertext operation")
	}
	return out, nil
}
