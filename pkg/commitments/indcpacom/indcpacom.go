package indcpacom

import (
	"fmt"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
	"github.com/bronlabs/errs-go/errs"
)

// Scheme represents an IND-CPA commitment scheme constructed from an encryption scheme.
// It wraps an encryption scheme and a public key, using encryption as the commitment
// mechanism.
type Scheme[
	SK encryption.PrivateKey[SK], PK encryption.PublicKey[PK], M encryption.Plaintext, C encryption.ReRandomisableCiphertext[C, N, PK], N interface {
		encryption.Nonce
		algebra.Operand[N]
	}, KG encryption.KeyGenerator[SK, PK], ENC encryption.Encrypter[PK, M, C, N], DEC encryption.Decrypter[M, C],
] struct {
	encScheme encryption.Scheme[SK, PK, M, C, N, KG, ENC, DEC]
	key       *Key[PK]
}

// Name returns the name of the commitment scheme, which includes the underlying
// encryption scheme name.
func (s *Scheme[SK, PK, M, C, N, KG, ENC, DEC]) Name() commitments.Name {
	return commitments.Name(fmt.Sprintf("IND-CPA-Com-%s", s.encScheme.Name()))
}

// Committer creates a new Committer instance for creating commitments.
// The underlying encryption scheme must implement LinearlyRandomisedEncrypter.
func (s *Scheme[SK, PK, M, C, N, KG, ENC, DEC]) Committer(opts ...CommitterOption[N, M, C, PK]) (*Committer[N, M, C, PK], error) {
	enc, err := s.encScheme.Encrypter()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create encrypter for IND-CPA commitment scheme")
	}
	lenc, ok := any(enc).(encryption.LinearlyRandomisedEncrypter[PK, M, C, N])
	if !ok {
		return nil, ErrInvalidType.WithMessage("encrypter does not implement LinearlyRandomisedEncrypter required for IND-CPA commitment scheme")
	}
	out := &Committer[N, M, C, PK]{enc: lenc, key: s.key}
	for _, opt := range opts {
		if err := opt(out); err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot apply committer option")
		}
	}
	return out, nil
}

// Verifier creates a new Verifier instance for verifying commitments.
func (s *Scheme[SK, PK, M, C, N, KG, ENC, DEC]) Verifier(opts ...VerifierOption[N, M, C, PK]) (*Verifier[N, M, C, PK], error) {
	committer, err := s.Committer()
	if err != nil {
		return nil, err
	}
	out := &Verifier[N, M, C, PK]{commitments.NewGenericVerifier(committer)}
	for _, opt := range opts {
		if err := opt(out); err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot apply verifier option")
		}
	}
	return out, nil
}

// Key returns the public key used by this commitment scheme.
func (s *Scheme[SK, PK, M, C, N, KG, ENC, DEC]) Key() *Key[PK] {
	return s.key
}

// NewScheme creates a new IND-CPA commitment scheme from an encryption scheme and public key.
// Returns an error if either argument is nil.
func NewScheme[
	SK encryption.PrivateKey[SK], PK encryption.PublicKey[PK], M encryption.Plaintext,
	C encryption.ReRandomisableCiphertext[C, N, PK], N interface {
		encryption.Nonce
		algebra.Operand[N]
	}, KG encryption.KeyGenerator[SK, PK], ENC encryption.Encrypter[PK, M, C, N], DEC encryption.Decrypter[M, C],
](
	encScheme encryption.Scheme[SK, PK, M, C, N, KG, ENC, DEC],
	key *Key[PK],
) (*Scheme[SK, PK, M, C, N, KG, ENC, DEC], error) {
	if encScheme == nil || key == nil {
		return nil, ErrIsNil.WithStackFrame()
	}
	return &Scheme[SK, PK, M, C, N, KG, ENC, DEC]{
		encScheme: encScheme,
		key:       key,
	}, nil
}
