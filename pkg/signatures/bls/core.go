package bls

import (
	"crypto/sha3"
	"io"
	"slices"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/sync/errgroup"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	bls12381Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/errs-go/pkg/errs"
)

// RandomOracleHashFunction is the hash function used for key derivation.
// SHA3-256 is used as it models a random oracle for salt generation.
var RandomOracleHashFunction = sha3.New256

// HKDFKeyGenSalt is the initial salt value for key generation using HKDF.
// Per the spec, if the initial hash produces a zero scalar, the salt is re-hashed
// and the process repeated until a valid non-zero key is derived.
//
// See: https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-06.html#section-2.3
const HKDFKeyGenSalt = "BLS-SIG-KEYGEN-SALT-"

func generateWithSeed[K curves.Point[K, FK, S], FK algebra.FieldElement[FK], S algebra.PrimeFieldElement[S]](group curves.Curve[K, FK, S], ikm []byte) (secret S, publicKey K, err error) {
	sf := algebra.StructureMustBeAs[algebra.PrimeField[S]](group.ScalarStructure())
	if len(ikm) < sf.ElementSize() {
		return *new(S), *new(K), ErrInvalidArgument.WithMessage("ikm is too short, must be at least %d bytes", sf.ElementSize())
	}
	d := sf.Zero()
	// We assume h models a random oracle, so we don't parametrize salt.
	// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#choosesalt
	salt, err := hashing.Hash(RandomOracleHashFunction, []byte(HKDFKeyGenSalt))
	if err != nil {
		return *new(S), *new(K), errs.Wrap(err)
	}
	// step 2.3.1
	for d.IsZero() {
		// step 2.3.2
		kdf := hkdf.New(hashing.HashFuncTypeErase(RandomOracleHashFunction), slices.Concat(ikm, []byte{0}), salt, []byte{0, bls12381Impl.FpBytes}) // TODO: make sure this is correct
		// Leaves key_info parameter as the default empty string
		// step 2.3.3
		okm := make([]byte, bls12381Impl.FpBytes)
		if _, err := io.ReadFull(kdf, okm); err != nil {
			return *new(S), *new(K), errs.Wrap(err)
		}

		// step 2.3.4
		d, err = sf.FromWideBytes(okm)
		if err != nil {
			return *new(S), *new(K), errs.Wrap(err)
		}
		salt, err = hashing.Hash(RandomOracleHashFunction, salt)
		if err != nil {
			return *new(S), *new(K), errs.Wrap(err)
		}
	}
	// 2.4: https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-sktopk
	Y := group.ScalarBaseMul(d)
	return d, Y, nil
}

// Warning: this is an internal method. We don't check if key and signature subgroups are different.
// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-coresign
func coreSign[
	Sig curves.Point[Sig, SigFE, S], SigFE algebra.FieldElement[SigFE], S algebra.PrimeFieldElement[S],
](signatureSubGroup curves.Curve[Sig, SigFE, S], privateKey S, message []byte, dst string) (Sig, error) {
	if signatureSubGroup == nil || message == nil || dst == "" {
		return *new(Sig), ErrInvalidArgument.WithMessage("signature subgroup, private key, message or dst cannot be nil or zero")
	}
	if privateKey.IsZero() {
		return *new(Sig), ErrInvalidSubGroup.WithMessage("private key is zero")
	}
	// step 2.6.1
	Hm, err := signatureSubGroup.HashWithDst(dst, message)
	if err != nil {
		return *new(Sig), errs.Wrap(err)
	}
	// step 2.6.2
	result := Hm.ScalarMul(privateKey)
	if !result.IsTorsionFree() {
		return *new(Sig), ErrInvalidSubGroup.WithMessage("point is not on correct subgroup")
	}
	return result, nil
}

func coreAggregateSign[
	Sig curves.Point[Sig, SigFE, S], SigFE algebra.FieldElement[SigFE], S algebra.PrimeFieldElement[S],
](signatureSubGroup curves.Curve[Sig, SigFE, S], privateKey S, messages [][]byte, dst string) (Sig, error) {
	if signatureSubGroup == nil || dst == "" {
		return *new(Sig), ErrInvalidArgument.WithMessage("signature subgroup or dst cannot be nil or zero")
	}
	if privateKey.IsZero() {
		return *new(Sig), ErrInvalidArgument.WithMessage("private key is zero")
	}
	var err error
	Hms := make([]Sig, len(messages))
	for i, message := range messages {
		Hms[i], err = signatureSubGroup.HashWithDst(dst, message)
		if err != nil {
			return *new(Sig), errs.Wrap(err)
		}
	}
	scs := sliceutils.Repeat[[]S](privateKey, len(messages))
	sig := algebrautils.MultiScalarMul(scs, Hms)
	return sig, nil
}

func coreBatchSign[
	Sig curves.Point[Sig, SigFE, S], SigFE algebra.FieldElement[SigFE], S algebra.PrimeFieldElement[S],
](signatureSubGroup curves.Curve[Sig, SigFE, S], privateKey S, messages [][]byte, dst string) ([]Sig, error) {
	if signatureSubGroup == nil || dst == "" {
		return nil, ErrInvalidArgument.WithMessage("signature subgroup or dst cannot be nil or zero")
	}
	if privateKey.IsZero() {
		return nil, ErrInvalidArgument.WithMessage("private key is zero")
	}
	batch := make([]Sig, len(messages))
	var err error
	errGroup := errgroup.Group{}
	for i, message := range messages {
		errGroup.Go(func() error {
			batch[i], err = coreSign(signatureSubGroup, privateKey, message, dst)
			if err != nil {
				return errs.Wrap(err).WithMessage("could not sign message %s", message)
			}
			return nil
		})
	}
	if err := errGroup.Wait(); err != nil {
		return nil, errs.Wrap(err)
	}
	return batch, nil
}

// Warning: this is an internal method. We don't check if key and signature subgroups are different.
// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-coreverify
func coreVerify[
	PK curves.PairingFriendlyPoint[PK, PKFE, Sig, SigFE, ET, S], PKFE algebra.FieldElement[PKFE],
	Sig curves.PairingFriendlyPoint[Sig, SigFE, PK, PKFE, ET, S], SigFE algebra.FieldElement[SigFE],
	ET algebra.MultiplicativeGroupElement[ET], S algebra.PrimeFieldElement[S],
](publicKey PK, message []byte, signature Sig, dst string, signatureSubGroup curves.PairingFriendlyCurve[Sig, SigFE, PK, PKFE, ET, S]) error {
	// step 2.7.2
	if message == nil || signatureSubGroup == nil || dst == "" {
		return ErrInvalidArgument.WithMessage("signature or message or public key or signature subgroup or pairing or dst cannot be nil or zero")
	}
	// step 2.7.3
	if signature.IsOpIdentity() {
		return ErrInvalidArgument.WithMessage("signature is identity")
	}
	if !signature.IsTorsionFree() {
		return ErrInvalidSubGroup.WithMessage("signature is not torsion free")
	}

	// step 2.7.4
	if publicKey.IsOpIdentity() {
		return ErrInvalidArgument.WithMessage("public key is identity")
	}
	if !publicKey.IsTorsionFree() {
		return ErrInvalidSubGroup.WithMessage("public key is not torsion free")
	}

	// e(pk, H(m)) == e(g1, s)  OR if signature in G1  e(H(m), pk) == e(s, g2)
	// However, we can reduce the number of miller loops
	// by doing the equivalent of
	// e(pk^-1, H(m)) * e(g1, s) == 1  OR if signature in G1 e(H(m), pk^-1) * e(s, g2) == 1
	// that'll be done in multipairing

	// step 2.7.6
	Hm, err := signatureSubGroup.HashWithDst(dst, message)
	if err != nil {
		return errs.Wrap(err)
	}

	out, err := signatureSubGroup.MultiPair(
		[]Sig{Hm, signature},
		[]PK{publicKey.Neg(), signatureSubGroup.DualStructure().Generator()},
	)
	if err != nil {
		return errs.Wrap(err)
	}
	if !out.IsOpIdentity() {
		return ErrVerificationFailed.WithMessage("incorrect multipairing result")
	}
	return nil
}

// Warning: this is an internal method. We don't check if K and S are different subgroups.
// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-coreaggregateverify
func coreAggregateVerify[
	PK curves.PairingFriendlyPoint[PK, PKFE, Sig, SigFE, ET, S], PKFE algebra.FieldElement[PKFE],
	Sig curves.PairingFriendlyPoint[Sig, SigFE, PK, PKFE, ET, S], SigFE algebra.FieldElement[SigFE],
	ET algebra.MultiplicativeGroupElement[ET], S algebra.PrimeFieldElement[S],
](publicKeys []PK, messages [][]byte, aggregatedSignature Sig, dst string, signatureSubGroup curves.PairingFriendlyCurve[Sig, SigFE, PK, PKFE, ET, S]) error {
	if len(publicKeys) == 0 {
		return ErrInvalidArgument.WithMessage("at least one public key is required")
	}
	if len(publicKeys) != len(messages) {
		return ErrInvalidArgument.WithMessage("the number of public keys does not match the number of messages: %v != %v", len(publicKeys), len(messages))
	}
	if dst == "" || signatureSubGroup == nil {
		return ErrInvalidArgument.WithMessage("dst or signature subgroup cannot be nil or zero")
	}

	// step 2.9.3
	if aggregatedSignature.IsOpIdentity() {
		return ErrInvalidArgument.WithMessage("signature is identity")
	}
	if !aggregatedSignature.IsTorsionFree() {
		return ErrInvalidSubGroup.WithMessage("signature is not torsion free")
	}

	// e(pk_1, H(m_1))*...*e(pk_N, H(m_N)) == e(g1, s) OR if signature in G1 e(H(m_1), pk_1)*...*e(H(m_N), pk_N) == e(s, g2)
	// However, we use only one miller loop
	// by doing the equivalent of
	// e(pk_1, H(m_1))*...*e(pk_N, H(m_N)) * e(g1, s^-1) == 1 OR if signature in G1 e(H(m_1), pk_1)*...*e(H(m_N), pk_N) * e(s^-1, g2) == 1

	var err error
	keySubGroupInputs := make([]PK, len(publicKeys)+1)
	signatureSubGroupInputs := make([]Sig, len(publicKeys)+1)
	for i, pk := range publicKeys {
		message := messages[i]
		if message == nil {
			return ErrInvalidArgument.WithMessage("nil message is not allowed at index %d", i)
		}
		keySubGroupInputs[i] = pk
		signatureSubGroupInputs[i], err = signatureSubGroup.HashWithDst(dst, message)
		if err != nil {
			return errs.Wrap(err).WithMessage("could not hash message %d", i)
		}
		// step 2.9.6
		if pk.IsOpIdentity() {
			return ErrInvalidArgument.WithMessage("invalid public key")
		}
		if !pk.IsTorsionFree() {
			return ErrInvalidSubGroup.WithMessage("public key is not torsion free")
		}
	}
	keySubGroupInputs[len(publicKeys)] = signatureSubGroup.DualStructure().Generator()
	signatureSubGroupInputs[len(publicKeys)] = aggregatedSignature.Neg()

	out, err := signatureSubGroup.MultiPair(signatureSubGroupInputs, keySubGroupInputs)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not compute multipairing")
	}
	if !out.IsOpIdentity() {
		return ErrVerificationFailed.WithMessage("incorrect multipairing result")
	}
	return nil
}

// PopProve(SK) -> (proof, error): an algorithm that generates a proof of possession for the public key corresponding to secret key SK.
// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-popprove
func popProve[
	PK curves.PairingFriendlyPoint[PK, PKFE, Sig, SigFE, ET, S], PKFE algebra.FieldElement[PKFE],
	Sig curves.PairingFriendlyPoint[Sig, SigFE, PK, PKFE, ET, S], SigFE algebra.FieldElement[SigFE],
	ET algebra.MultiplicativeGroupElement[ET], S algebra.PrimeFieldElement[S],
](privateKey S, publicKey PK, signatureSubGroup curves.Curve[Sig, SigFE, S], dst string) (Sig, error) {
	message := publicKey.Bytes()
	pop, err := coreSign(signatureSubGroup, privateKey, message, dst)
	if err != nil {
		return *new(Sig), errs.Wrap(err).WithMessage("could not produce pop")
	}
	return pop, nil
}

// PopVerify verifies proof of possession of public key
// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-popverify
func popVerify[
	PK curves.PairingFriendlyPoint[PK, PKFE, Sig, SigFE, ET, S], PKFE algebra.FieldElement[PKFE],
	Sig curves.PairingFriendlyPoint[Sig, SigFE, PK, PKFE, ET, S], SigFE algebra.FieldElement[SigFE],
	ET algebra.MultiplicativeGroupElement[ET], S algebra.PrimeFieldElement[S],
](publicKey PK, pop Sig, signatureSubGroup curves.PairingFriendlyCurve[Sig, SigFE, PK, PKFE, ET, S], popDst string) error {
	if publicKey.IsOpIdentity() {
		return ErrInvalidArgument.WithMessage("public key is identity")
	}
	if !publicKey.IsTorsionFree() {
		return ErrInvalidSubGroup.WithMessage("Public Key not in the prime subgroup")
	}
	message := publicKey.Bytes()
	return coreVerify(publicKey, message, pop, popDst, signatureSubGroup)
}

// AugmentMessage prepends the serialised public key to the message for the Message Augmentation
// signature scheme. This creates a unique message per signer, preventing rogue key attacks
// without requiring additional proofs or message distinctness checks.
//
// The augmented message is: pk || msg
//
// See: https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-06.html#section-3.2.1
func AugmentMessage[
	PK curves.Point[PK, PKFE, S], PKFE algebra.FieldElement[PKFE], S algebra.PrimeFieldElement[S],
](message []byte, publicKey PK) ([]byte, error) {
	if publicKey.IsOpIdentity() {
		return nil, ErrInvalidArgument.WithMessage("public key is identity")
	}
	if !publicKey.IsTorsionFree() {
		return nil, ErrInvalidSubGroup.WithMessage("Public Key not in the prime subgroup")
	}
	return slices.Concat(publicKey.Bytes(), message), nil
}
