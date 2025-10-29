package internal

import (
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
)

// type privateKeyDTO[V algebra.PrimeFieldElement[V]] struct {
// 	V   V      `cbor:"v"`
// 	Ikm []byte `cbor:"ikm"`
// }

// func (sk *PrivateKey[S]) MarshalCBOR() ([]byte, error) {
// 	dto := &privateKeyDTO[S]{
// 		V:   sk.v,
// 		Ikm: sk.ikm,
// 	}
// 	return serde.MarshalCBOR(dto)
// }

// func (sk *PrivateKey[S]) UnmarshalCBOR(data []byte) error {
// 	dto, err := serde.UnmarshalCBOR[privateKeyDTO[S]](data)
// 	if err != nil {
// 		return errs.WrapSerialisation(err, "could not serialise private key")
// 	}
// 	if _, err := NewPrivateKey(dto.V); err != nil {
// 		return errs.WrapValidation(err, "invalid private key")
// 	}
// 	// Note: ikm may differ from dto.V.Bytes() for curves like X25519 where
// 	// ikm stores unclamped bytes while v stores the clamped scalar.
// 	// This is intentional and valid behavior.
// 	if !slices.Equal(dto.Ikm, dto.V.Bytes()) && ct.SliceIsZero(dto.Ikm) == ct.True {
// 		return errs.NewValidation("invalid ikm")
// 	}
// 	sk.v = dto.V
// 	sk.ikm = dto.Ikm
// 	return nil
// }

// type publicKeyDTO[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
// 	V P
// }

// func (pk *PublicKey[P, B, S]) MarshalCBOR() ([]byte, error) {
// 	dto := &publicKeyDTO[P, B, S]{
// 		V: pk.v,
// 	}
// 	return serde.MarshalCBOR(dto)
// }

// func (pk *PublicKey[P, B, S]) UnmarshalCBOR(data []byte) error {
// 	dto, err := serde.UnmarshalCBOR[publicKeyDTO[P, B, S]](data)
// 	if err != nil {
// 		return errs.WrapSerialisation(err, "could not serialise public key")
// 	}
// 	if _, err := NewPublicKey(dto.V); err != nil {
// 		return errs.WrapValidation(err, "invalid public key")
// 	}
// 	pk.v = dto.V
// 	return nil
// }

type cipherSuiteDTO struct {
	KDF  KDFID  `cbor:"kdf"`
	KEM  KEMID  `cbor:"kem"`
	AEAD AEADID `cbor:"aead"`
}

func (cs *CipherSuite) MarshalCBOR() ([]byte, error) {
	dto := &cipherSuiteDTO{
		KDF:  cs.kdf,
		KEM:  cs.kem,
		AEAD: cs.aead,
	}
	return serde.MarshalCBOR(dto)
}

func (cs *CipherSuite) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[cipherSuiteDTO](data)
	if err != nil {
		return errs.WrapSerialisation(err, "could not serialise cipher suite")
	}
	if dto.KDF == KDF_HKDF_RESERVED {
		return errs.NewValidation("invalid cipher suite: reserved KDF")
	}
	if dto.KDF != KDF_HKDF_SHA256 && dto.KDF != KDF_HKDF_SHA512 {
		return errs.NewValidation("invalid cipher suite: unknown KDF")
	}
	if dto.KEM == DHKEM_RESERVED {
		return errs.NewValidation("invalid cipher suite: reserved KEM")
	}
	if dto.KEM != DHKEM_P256_HKDF_SHA256 && dto.KEM != DHKEM_X25519_HKDF_SHA256 {
		return errs.NewValidation("invalid cipher suite: unknown KEM")
	}
	if dto.AEAD == AEAD_RESERVED {
		return errs.NewValidation("invalid cipher suite: reserved AEAD")
	}
	if dto.AEAD != AEAD_AES_128_GCM && dto.AEAD != AEAD_AES_256_GCM && dto.AEAD != AEAD_CHACHA_20_POLY_1305 && dto.AEAD != AEAD_EXPORT_ONLY {
		return errs.NewValidation("invalid cipher suite: unknown AEAD")
	}
	cs.kdf = dto.KDF
	cs.kem = dto.KEM
	cs.aead = dto.AEAD
	return nil
}
