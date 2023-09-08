package hpke

import (
	"crypto/aes"
	"crypto/cipher"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/copperexchange/knox-primitives/pkg/base/errs"
)

type AEADID uint16

// https://www.rfc-editor.org/rfc/rfc9180.html#name-authenticated-encryption-wi
const (
	AEAD_RESERVED            AEADID = 0x0000
	AEAD_AES_128_GCM         AEADID = 0x0001
	AEAD_AES_256_GCM         AEADID = 0x0002
	AEAD_CHACHA_20_POLY_1305 AEADID = 0x0003
	AEAD_EXPORT_ONLY         AEADID = 0xffff
)

//nolint:exhaustive // reserved and export only will not have have parameters below.
var (
	// https://www.rfc-editor.org/rfc/rfc9180.html#name-authenticated-encryption-wi
	nks = map[AEADID]int{
		AEAD_AES_128_GCM:         16,
		AEAD_AES_256_GCM:         32,
		AEAD_CHACHA_20_POLY_1305: 32,
	}
	nns = map[AEADID]int{
		AEAD_AES_128_GCM:         12,
		AEAD_AES_256_GCM:         12,
		AEAD_CHACHA_20_POLY_1305: 12,
	}
	nts = map[AEADID]int{
		AEAD_AES_128_GCM:         16,
		AEAD_AES_256_GCM:         16,
		AEAD_CHACHA_20_POLY_1305: 16,
	}
	aeads = map[AEADID]*AEADScheme{
		AEAD_AES_128_GCM:         NewAEADAES128GCMScheme(),
		AEAD_AES_256_GCM:         NewAEADAES256GCMScheme(),
		AEAD_CHACHA_20_POLY_1305: NewAEADChaCha20Poly1305Scheme(),
	}
)

type AEADScheme struct {
	id AEADID
}

// NewAEADAES128GCMScheme returns an instantiation of AEAD_AES_128_GCM.
func NewAEADAES128GCMScheme() *AEADScheme {
	return &AEADScheme{
		id: AEAD_AES_128_GCM,
	}
}

// NewAEADAES256GCMScheme returns an instantiation of AEAD_AES_256_GCM.
func NewAEADAES256GCMScheme() *AEADScheme {
	return &AEADScheme{
		id: AEAD_AES_256_GCM,
	}
}

// NewAEADChaCha20Poly1305Scheme returns an instantiation of AEAD_CHACHA_20_POLY_1305.
func NewAEADChaCha20Poly1305Scheme() *AEADScheme {
	return &AEADScheme{
		id: AEAD_CHACHA_20_POLY_1305,
	}
}

// New accepts a key and returns the corresponding AEAD cipher to the type of the scheme, which can then Seal or Open.
func (s *AEADScheme) New(key []byte) (cipher.AEAD, error) {
	if len(key) != s.Nk() {
		return nil, errs.NewInvalidLength("key length is %d whereas it should be %d", len(key), s.Nk())
	}
	if s.isAES() {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not construct block cipher")
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not construct gcm block cipher")
		}
		return gcm, nil
	}
	chacha, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct chacha cipher")
	}
	return chacha, nil
}

// ID returns the AEAD Id as per https://www.rfc-editor.org/rfc/rfc9180.html#name-authenticated-encryption-wi
func (s *AEADScheme) ID() AEADID {
	return s.id
}

// Nk returns the length in bytes of a key for this algorithm.
// https://www.rfc-editor.org/rfc/rfc9180.html#section-4-2.3.2.3
func (s *AEADScheme) Nk() int {
	return nks[s.ID()]
}

// Nn returns the length in bytes of a nonce for this algorithm.
// https://www.rfc-editor.org/rfc/rfc9180.html#section-4-2.3.2.4
func (s *AEADScheme) Nn() int {
	return nns[s.ID()]
}

// Nt returns the length in bytes of the authentication tag for this algorithm.
// https://www.rfc-editor.org/rfc/rfc9180.html#section-4-2.3.2.5
func (s *AEADScheme) Nt() int {
	return nts[s.ID()]
}

func (s *AEADScheme) isAES() bool {
	return s.ID() == AEAD_AES_128_GCM || s.ID() == AEAD_AES_256_GCM
}
