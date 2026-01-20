package indcpacom

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
)

type Commitment[C encryption.ReRandomisableCiphertext[C, N, PK], N encryption.Nonce, PK encryption.PublicKey[PK]] struct {
	v C
}

func (c *Commitment[C, N, PK]) Value() C {
	return c.v
}

func (c *Commitment[C, N, PK]) Equal(other *Commitment[C, N, PK]) bool {
	if c == nil || other == nil {
		return c == other
	}
	return c.v.Equal(other.v)
}

func (c *Commitment[C, N, PK]) ReRandomiseWithWitness(k *Key[PK], w *Witness[N]) (*Commitment[C, N, PK], error) {
	if k == nil || w == nil {
		return nil, ErrIsNil.WithStackFrame()
	}
	newCiphertext, err := c.v.ReRandomiseWithNonce(k.v, w.v)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot re-randomise commitment")
	}
	return &Commitment[C, N, PK]{v: newCiphertext}, nil
}

func (c *Commitment[C, N, PK]) ReRandomise(k *Key[PK], prng io.Reader) (*Commitment[C, N, PK], *Witness[N], error) {
	if k == nil || prng == nil {
		return nil, nil, ErrIsNil.WithStackFrame()
	}
	newCiphertext, newNonce, err := c.v.ReRandomise(k.v, prng)
	if err != nil {
		return nil, nil, errs2.Wrap(err).WithMessage("cannot re-randomise commitment")
	}
	return &Commitment[C, N, PK]{v: newCiphertext}, &Witness[N]{v: newNonce}, nil
}

type Key[PK encryption.PublicKey[PK]] struct {
	v PK
}

func (k *Key[PK]) Value() PK {
	return k.v
}

func NewKey[PK encryption.PublicKey[PK]](v PK) (*Key[PK], error) {
	if utils.IsNil(v) {
		return nil, ErrIsNil.WithStackFrame()
	}
	return &Key[PK]{v: v}, nil
}

type Message[M encryption.Plaintext] struct {
	v M
}

func (m *Message[M]) Value() M {
	return m.v
}

func NewMessage[M encryption.Plaintext](v M) (*Message[M], error) {
	if utils.IsNil(v) {
		return nil, ErrIsNil.WithStackFrame()
	}
	return &Message[M]{v: v}, nil
}

type Witness[N encryption.Nonce] struct {
	v N
}

func (w *Witness[N]) Value() N {
	return w.v
}

var (
	ErrIsNil              = errs2.New("value is nil")
	ErrVerificationFailed = errs2.New("commitment verification failed")
)
