package gift

// import (
// 	"io"

// 	"github.com/bronlabs/bron-crypto/pkg/base"
// 	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
// 	"github.com/bronlabs/bron-crypto/pkg/base/errs"
// 	"github.com/bronlabs/bron-crypto/pkg/base/nt/modular"
// 	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
// 	"github.com/bronlabs/bron-crypto/pkg/base/utils"
// 	"github.com/bronlabs/bron-crypto/pkg/encryption"
// )

// type Scalar = num.Nat

// // C Hat
// type CipherGroup[C Ciphertext[C, CV, M, PK, N, NV], CV algebra.AbelianGroupElement[CV, *Scalar], M Plaintext, PK PublicKey[PK], N Nonce[NV], NV algebra.AbelianGroupElement[NV, *Scalar]] interface {
// 	base.Transparent[algebra.AbelianGroup[CV, *Scalar]]
// 	New(CV) (C, error)
// }

// type Ciphertext[C Encryption[C, CV, M, PK, N, NV], CV algebra.AbelianGroupElement[CV, *Scalar], M Plaintext, PK PublicKey[PK], N Nonce[NV], NV algebra.AbelianGroupElement[NV, *Scalar]] Encryption[C, CV, M, PK, N, NV]

// // C
// type EncryptionSet[E Encryption[E, EV, M, PK, N, NV], EV algebra.AbelianGroupElement[EV, *Scalar], C Ciphertext[C, CV, M, PK, N, NV], CV algebra.AbelianGroupElement[CV, *Scalar], M Plaintext, PK PublicKey[PK], N Nonce[NV], NV algebra.AbelianGroupElement[NV, *Scalar]] interface {
// 	base.Transparent[algebra.AbelianGroup[EV, *Scalar]]
// 	Contains(C) bool // Delta
// 	New(EV) (E, error)
// }

// type Encryption[E encryption.ShiftTypeCiphertext[E, EV, M, PK, N, *Scalar], EV algebra.AbelianGroupElement[EV, *Scalar], M Plaintext, PK PublicKey[PK], N Nonce[NV], NV algebra.AbelianGroupElement[NV, *Scalar]] interface {
// 	encryption.ShiftTypeCiphertext[E, EV, M, PK, N, *Scalar]
// }

// // N

// type NonceGroup[N Nonce[NV], NV algebra.AbelianGroupElement[NV, *Scalar]] interface {
// 	base.Transparent[NV]
// 	Sample(io.Reader) (N, error)
// }

// type Nonce[NV algebra.AbelianGroupElement[NV, *Scalar]] interface {
// 	algebra.AbelianGroupElement[NV, *Scalar]
// 	encryption.Nonce
// }

// type NewRandomiser[R algebra.AbelianGroupElement[R, *Scalar], N Nonce[NV], NV algebra.AbelianGroupElement[NV, *Scalar]] func(N) (R, error)

// // Phi

// type Phi[M Plaintext, R algebra.AbelianGroupElement[R, *Scalar]] func(M) R

// // P
// type PlaintextGroup interface {
// 	algebra.AbelianGroup[Plaintext, *Scalar]
// }

// type Plaintext interface {
// 	algebra.AbelianGroupElement[Plaintext, *Scalar]
// 	encryption.HomomorphicPlaintext[Plaintext, *Scalar]
// }

// type PublicKey[PK encryption.PublicKey[PK]] encryption.PublicKey[PK]

// type PrivateKey[SK encryption.PrivateKey[SK], A modular.Arithmetic] interface {
// 	encryption.PrivateKey[SK]
// 	Arithmetic() A
// }

// type KeyGenerator[SK PrivateKey[SK, A], PK PublicKey[PK], A modular.Arithmetic] encryption.KeyGenerator[SK, PK]

// type Trapdoor[C Ciphertext[C, CV, M, PK, N, NV], CV algebra.AbelianGroupElement[CV, *Scalar], M Plaintext, PK PublicKey[PK], N Nonce[NV], NV algebra.AbelianGroupElement[NV, *Scalar]] func(C) (M, error)

// func Encrypt[ES EncryptionSet[E, EV, C, CV, M, PK, N, NV], E Encryption[E, EV, M, PK, N, NV], EV algebra.AbelianGroupElement[EV, *Scalar], C Ciphertext[C, CV, M, PK, N, NV], CV algebra.AbelianGroupElement[CV, *Scalar], M Plaintext, PK PublicKey[PK], NS NonceGroup[N, NV], N Nonce[NV], NV algebra.AbelianGroupElement[NV, *Scalar]](
// 	message M, f NewRandomiser[EV, N, NV], nonceGroup NS, encryptionSet ES, phi Phi[M, EV], prng io.Reader,
// ) (E, N, error) {
// 	if utils.IsNil(nonceGroup) || utils.IsNil(encryptionSet) || f == nil || phi == nil || prng == nil {
// 		return *new(E), *new(N), errs.NewIsNil("at least one of the arguments is nil")
// 	}
// 	nonce, err := nonceGroup.Sample(prng)
// 	if err != nil {
// 		return *new(E), *new(N), errs.WrapRandomSample(err, "couldn't sample nonce")
// 	}
// 	randomiser, err := f(nonce)
// 	if err != nil {
// 		return *new(E), *new(N), errs.WrapFailed(err, "couldn't lift nonce to randomiser")
// 	}
// 	ciphertext, err := encryptionSet.New(randomiser.Op(phi(message)))
// 	if err != nil {
// 		return *new(E), *new(N), errs.WrapFailed(err, "couldn't create new ciphertext")
// 	}
// 	return ciphertext, nonce, nil
// }

// func Decrypt[C Ciphertext[C, CV, M, PK, N, NV], CV algebra.AbelianGroupElement[CV, *Scalar], E Encryption[E, EV, M, PK, N, NV], EV algebra.AbelianGroupElement[EV, *Scalar], M Plaintext, PK PublicKey[PK], N Nonce[NV], NV algebra.AbelianGroupElement[NV, *Scalar]](
// 	ciphertext C, trapdoor Trapdoor[C, CV, M, PK, N, NV], encryptionSet EncryptionSet[E, EV, C, CV, M, PK, N, NV],
// ) (M, error) {
// 	if utils.IsNil(ciphertext) || encryptionSet == nil || trapdoor == nil {
// 		return *new(M), errs.NewIsNil("at least one of the arguments is nil")
// 	}
// 	if !encryptionSet.Contains(ciphertext) {
// 		return *new(M), errs.NewValue("ciphertext not in encryption set")
// 	}
// 	plaintext, err := trapdoor(ciphertext)
// 	if err != nil {
// 		return *new(M), errs.WrapFailed(err, "couldn't decrypt ciphertext")
// 	}
// 	return plaintext, nil
// }
