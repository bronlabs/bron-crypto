package frost

import (
	"crypto/ed25519"
	"crypto/sha512"
	"hash"
	"reflect"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves/native"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/pkg/errors"
)

type Participant interface {
	GetIdentityKey() integration.IdentityKey
	GetShamirId() int
	GetCohortConfig() *integration.CohortConfig

	IsSignatureAggregator() bool
}

type SigningKeyShare struct {
	Share     curves.Scalar
	PublicKey curves.Point
}

func (s *SigningKeyShare) Validate() error {
	if s == nil {
		return errors.New("signing key share is nil")
	}
	if s.Share.IsZero() {
		return errors.New("share can't be zero")
	}
	if s.PublicKey.IsIdentity() {
		return errors.New("public key can't be at infinity")
	}
	if !s.PublicKey.IsOnCurve() {
		return errors.New("public key is not on curve")
	}
	return nil
}

type PublicKeyShares struct {
	Curve     *curves.Curve
	PublicKey curves.Point
	SharesMap map[integration.IdentityKey]curves.Point
}

// TODO: write down validation (lambda trick)
// func (p *PublicKeyShares) Validate() error {
// 	derivedPublicKey := p.Curve.Point.Identity()
// 	for _, share := range p.SharesMap {
// 		derivedPublicKey = derivedPublicKey.Add(share)
// 	}
// 	if !derivedPublicKey.Equal(p.PublicKey) {
// 		return errors.New("public key shares can't be combined to the entire public key")
// 	}
// 	return nil
// }

type PartialSignature struct {
	Zi curves.Scalar
}

type Signature struct {
	R curves.Point
	Z curves.Scalar
}

func (s *Signature) MarshalBinary() ([]byte, error) {
	curve, err := curves.GetCurveByName(s.R.CurveName())
	if err != nil {
		return nil, errors.Wrap(err, "could not get curve")
	}
	signatureSize := 64
	if curve.Name == curves.K256Name || curve.Name == curves.P256Name {
		// these two curves add a bit at the beginning to denote compressed or uncompressed
		signatureSize = 65
	}
	serializedSignature := []byte{}
	RSerialized := s.R.ToAffineCompressed()
	zSerialized := s.Z.Bytes()
	if len(RSerialized)+len(zSerialized) != signatureSize {
		return serializedSignature[:], errors.Errorf("serialized signature is too large")
	}
	serializedSignature = append(serializedSignature, RSerialized...)
	serializedSignature = append(serializedSignature, zSerialized...)
	return serializedSignature, nil
}

// TODO: curve+hashFunction -> ciphersuite
func Verify(curve *curves.Curve, hashFunction func() hash.Hash, signature *Signature, publicKey curves.Point, message []byte) error {
	if curve == curves.ED25519() && reflect.ValueOf(hashFunction).Pointer() == reflect.ValueOf(sha512.New).Pointer() {
		serializedSignature, err := signature.MarshalBinary()
		if err != nil {
			return errors.Wrap(err, "could not serialize signature to binary")
		}
		if ok := ed25519.Verify(publicKey.ToAffineCompressed(), message, serializedSignature); !ok {
			return errors.New("could not verify frost signature using ed25519 verifier")
		}

		return nil
	} else {
		challengeHasher := hashFunction()
		if _, err := challengeHasher.Write(signature.R.ToAffineCompressed()); err != nil {
			return errors.Wrap(err, "could not write R to challenge hasher")
		}
		if _, err := challengeHasher.Write(publicKey.ToAffineCompressed()); err != nil {
			return errors.Wrap(err, "could not write public key to challenge hasher")
		}
		if _, err := challengeHasher.Write(message); err != nil {
			return errors.Wrap(err, "could not write the message to challenge hasher")
		}
		challengeDigest := challengeHasher.Sum(nil)
		var setBytesFunc func([]byte) (curves.Scalar, error)
		switch len(challengeDigest) {
		case native.WideFieldBytes:
			setBytesFunc = curve.Scalar.SetBytesWide
		case native.FieldBytes:
			setBytesFunc = curve.Scalar.SetBytes
		default:
			return errors.Errorf("challenge digest is %d which is neither 64 nor 32", len(challengeDigest))
		}
		c, err := setBytesFunc(challengeDigest)
		if err != nil {
			return errors.Wrap(err, "converting hash to c failed")
		}

		zG := curve.ScalarBaseMult(signature.Z)
		negCY := publicKey.Mul(c.Neg())
		RPrime := zG.Add(negCY)
		if ok := signature.R.Equal(RPrime); !ok {
			return errors.New("failed to verify")
		}

		return nil
	}
}

func DeriveShamirIds(myIdentityKey integration.IdentityKey, identityKeys []integration.IdentityKey) (idToKey map[int]integration.IdentityKey, keyToId map[integration.IdentityKey]int, myShamirId int) {
	idToKey = make(map[int]integration.IdentityKey)
	keyToId = make(map[integration.IdentityKey]int)
	myShamirId = -1

	for shamirIdMinusOne, identityKey := range identityKeys {
		shamirId := shamirIdMinusOne + 1
		idToKey[shamirId] = identityKey
		keyToId[identityKey] = shamirId
		if myIdentityKey != nil && identityKey.PublicKey().Equal(myIdentityKey.PublicKey()) {
			myShamirId = shamirId
		}
	}

	return idToKey, keyToId, myShamirId
}
