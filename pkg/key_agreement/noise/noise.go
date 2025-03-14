package noise

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"hash"
	"io"
	"math"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/curve25519"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/bron-crypto/pkg/key_agreement/dh"
)

type SupportedAEAD string
type SupportedHash string

const (
	NOISE_AEAD_CHACHA  SupportedAEAD = "ChaChaPoly"
	NOISE_HASH_BLAKE2S SupportedHash = "BLAKE2s"
	NOISE_HASH_SHA3256 SupportedHash = "SHA3_256"
)

var (
	SupportedAeads = map[SupportedAEAD]func([]byte) cipher.AEAD{
		NOISE_AEAD_CHACHA: func(key []byte) cipher.AEAD {
			enc, _ := chacha20poly1305.New(key)
			return enc
		},
	}
	SupportedHashes = map[SupportedHash]func() hash.Hash{
		NOISE_HASH_BLAKE2S: func() hash.Hash {
			h, err := blake2s.New256(nil)
			if err != nil {
				panic(err)
			}
			return h
		},
		NOISE_HASH_SHA3256: sha3.New256,
	}
)

func isEmptyKey(curve curves.Curve, k [32]byte) bool {
	return subtle.ConstantTimeCompare(k[:], curve.Point().ToAffineCompressed()) == 1
}

func MapToNoiseCurve(curve curves.Curve) string {
	switch curve.Name() {
	case curve25519.Name:
		return "25519"
	default:
		return "unknown-curve"
	}
}

func incrementNonce(n uint64) uint64 {
	return n + 1
}

// Dh execute a Diffie-Hellman key exchange function.
func Dh(curve curves.Curve, privateKey curves.Scalar, publicKey curves.Point) curves.BaseFieldElement {
	if curve.Name() == curve25519.Name {
		publicKeyCurve22519, ok := publicKey.(*curve25519.Point)
		if ok {
			// curve25519's internal is using X25519
			return publicKeyCurve22519.X25519(privateKey).AffineX()
		}
		panic("could not cast public key to curve25519 point")
	}
	field, err := dh.DiffieHellman(privateKey, publicKey)
	if err != nil {
		panic(err)
	}
	return field
}

func NewSigner(prng io.Reader, curve curves.Curve, privateKey curves.Scalar) Signer {
	var err error
	if privateKey == nil {
		privateKey, err = curve.ScalarField().Random(prng)
		if err != nil {
			panic("Could not sample private key")
		}
	}
	publicKey := curve.ScalarBaseMult(privateKey)
	return Signer{publicKey, privateKey}
}

// Encrypt encrypts the plaintext with the key and nonce using the AEAD.
func Encrypt(aead func([]byte) cipher.AEAD, k [32]byte, n uint64, ad, plaintext []byte) []byte {
	var nonce [12]byte
	var ciphertext []byte
	enc := aead(k[:])
	binary.LittleEndian.PutUint64(nonce[4:], n)
	ciphertext = enc.Seal(nil, nonce[:], plaintext, ad)
	return ciphertext
}

func decrypt(aead func([]byte) cipher.AEAD, k [32]byte, n uint64, ad, ciphertext []byte) (valid bool, ad_, plaintext_ []byte) {
	var nonce [12]byte
	var plaintext []byte
	enc := aead(k[:])
	binary.LittleEndian.PutUint64(nonce[4:], n)
	plaintext, err := enc.Open(nil, nonce[:], ciphertext, ad)
	return err == nil, ad, plaintext
}

// GetHash Hashes some arbitrary-length data with a collision-resistant cryptographic hash function and returns an output of 32 bytes.
func GetHash(hashFunc func() hash.Hash, a, b []byte) ([32]byte, error) {
	var result [32]byte
	hasher := hashFunc()
	hasher.Write(append(a, b...))
	hashed, err := hashing.Hash(hashFunc, a, b)
	if err != nil {
		return result, errs.WrapHashing(err, "could not hash")
	}
	copy(result[:], hashed)
	return result, nil
}

func HashProtocolName(hashFunc func() hash.Hash, protocolName []byte) ([32]byte, error) {
	var h [32]byte
	var err error
	if len(protocolName) <= 32 {
		copy(h[:], protocolName)
	} else {
		h, err = GetHash(hashFunc, protocolName, []byte{})
		if err != nil {
			return [32]byte{}, errs.WrapFailed(err, "could not hash")
		}
	}
	return h, nil
}

// GetHkdf Takes a chaining_key byte sequence of length HASHLEN, and an input_key_material byte
// sequence with length either zero bytes, 32 bytes, or DHLEN bytes.
// Returns a pair or triple of byte sequences each of length 32.
// In our pattern, we only need the first two ks, so we skip the last byte sequences.
func GetHkdf(hashFunc func() hash.Hash, ck [32]byte, ikm []byte) (k1, k2 [32]byte) {
	output := hkdf.New(hashFunc, ikm, ck[:], []byte{})
	_, err := io.ReadFull(output, k1[:])
	if err != nil {
		panic(err)
	}
	_, err = io.ReadFull(output, k2[:])
	if err != nil {
		panic(err)
	}
	return k1, k2
}

func InitializeKey(k [32]byte) CipherState {
	return CipherState{k, uint64(0)}
}

func HasKey(curve curves.Curve, cs *CipherState) bool {
	return !isEmptyKey(curve, cs.K)
}

// SetNonce This function is used for handling out-of-order transport messages.
func SetNonce(cs *CipherState, newNonce uint64) {
	cs.Nonce = newNonce
}

func EncryptWithAd(aead func([]byte) cipher.AEAD, cs *CipherState, ad, plaintext []byte) (cs_ *CipherState, e []byte, err error) {
	if cs.Nonce == math.MaxUint64-1 {
		return cs, []byte{}, errs.NewFailed("EncryptWithAd: maximum nonce size reached")
	}
	e = Encrypt(aead, cs.K, cs.Nonce, ad, plaintext)
	SetNonce(cs, incrementNonce(cs.Nonce))
	return cs, e, nil
}

func decryptWithAd(aead func([]byte) cipher.AEAD, cs *CipherState, ad, ciphertext []byte) (plaintext []byte, valid bool, err error) {
	if cs.Nonce == math.MaxUint64-1 {
		err = errs.NewFailed("decryptWithAd: maximum nonce size reached")
		return []byte{}, false, err
	}
	valid, _, plaintext = decrypt(aead, cs.K, cs.Nonce, ad, ciphertext)
	if valid {
		SetNonce(cs, incrementNonce(cs.Nonce))
	}
	return plaintext, valid, err
}

func InitializeSymmetric(curve curves.Curve, hashFunc func() hash.Hash, protocolName []byte) (SymmetricState, error) {
	h, err := HashProtocolName(hashFunc, protocolName)
	if err != nil {
		return SymmetricState{}, errs.WrapFailed(err, "could not hash protocol name")
	}
	ck := h
	var k [32]byte
	copy(k[:], curve.Point().ToAffineCompressed())
	cs := InitializeKey(k)
	return SymmetricState{cs, ck, h}, nil
}

func EncryptAndHash(curve curves.Curve, hashFunc func() hash.Hash, aead func([]byte) cipher.AEAD, ss *SymmetricState, plaintext []byte) ([]byte, error) {
	var ciphertext []byte
	var err error
	if HasKey(curve, &ss.Cs) {
		_, ciphertext, err = EncryptWithAd(aead, &ss.Cs, ss.H[:], plaintext)
		if err != nil {
			return []byte{}, err
		}
	} else {
		ciphertext = plaintext
	}
	err = ss.MixHash(hashFunc, ciphertext)
	if err != nil {
		return []byte{}, errs.WrapFailed(err, "could not mix hash ciphertext")
	}
	return ciphertext, err
}

func DecryptAndHash(curve curves.Curve, hashFunc func() hash.Hash, aead func([]byte) cipher.AEAD, ss *SymmetricState, ciphertext []byte) (plaintext []byte, valid bool, err error) {
	if HasKey(curve, &ss.Cs) {
		plaintext, valid, err = decryptWithAd(aead, &ss.Cs, ss.H[:], ciphertext)
		if err != nil {
			return []byte{}, false, err
		}
	} else {
		plaintext, valid = ciphertext, true
	}
	err = ss.MixHash(hashFunc, ciphertext)
	if err != nil {
		return []byte{}, false, errs.WrapFailed(err, "could not mix hash ciphertext")
	}
	return plaintext, valid, err
}

// Split Returns a pair of CipherState objects for encrypting/decrypting transport messages.
func Split(hashFunc func() hash.Hash, ss *SymmetricState) (cs1, cs2 CipherState) {
	tempK1, tempK2 := GetHkdf(hashFunc, ss.Ck, []byte{})
	cs1 = InitializeKey(tempK1)
	cs2 = InitializeKey(tempK2)
	return cs1, cs2
}

func InitializeInitiator(curve curves.Curve, hashFunc func() hash.Hash, name string, prologue []byte, s Signer, rs curves.Point) (HandshakeState, error) {
	var ss SymmetricState
	var e Signer
	var re curves.Point
	// step 1.2 if initiator
	ss, err := InitializeSymmetric(curve, hashFunc, []byte(name))
	if err != nil {
		return HandshakeState{}, errs.WrapFailed(err, "could not initialise symmetric state")
	}
	err = ss.MixHash(hashFunc, prologue)
	if err != nil {
		return HandshakeState{}, errs.WrapFailed(err, "could not mix hash prologue")
	}
	err = ss.MixHash(hashFunc, s.PublicKey.ToAffineCompressed())
	if err != nil {
		return HandshakeState{}, errs.WrapFailed(err, "could not mix hash s.PublicKey")
	}
	err = ss.MixHash(hashFunc, rs.ToAffineCompressed())
	if err != nil {
		return HandshakeState{}, errs.WrapFailed(err, "could not mix hash rs")
	}
	return HandshakeState{ss, s, e, rs, re}, nil
}

func InitializeResponder(curve curves.Curve, hashFunc func() hash.Hash, name string, prologue []byte, s Signer, rs curves.Point) (HandshakeState, error) {
	var ss SymmetricState
	var e Signer
	var re curves.Point
	// step 1.2 if responder
	ss, err := InitializeSymmetric(curve, hashFunc, []byte(name))
	if err != nil {
		return HandshakeState{}, errs.WrapFailed(err, "could not initialise symmetric state")
	}
	err = ss.MixHash(hashFunc, prologue)
	if err != nil {
		return HandshakeState{}, errs.WrapFailed(err, "could not mix hash prologue")
	}
	err = ss.MixHash(hashFunc, rs.ToAffineCompressed())
	if err != nil {
		return HandshakeState{}, errs.WrapFailed(err, "could not mix hash rs")
	}
	err = ss.MixHash(hashFunc, s.PublicKey.ToAffineCompressed())
	if err != nil {
		return HandshakeState{}, errs.WrapFailed(err, "could not mix hash s.PublicKey")
	}
	return HandshakeState{ss, s, e, rs, re}, nil
}

func writeMessageRegular(curve curves.Curve, aead func([]byte) cipher.AEAD, cs *CipherState, payload []byte) (messageBuffer P2PMessage, err error) {
	var ciphertext []byte
	ne := curve.Point()
	_, ciphertext, err = EncryptWithAd(aead, cs, []byte{}, payload)
	if err != nil {
		return messageBuffer, err
	}
	messageBuffer = P2PMessage{ne, ciphertext}
	return messageBuffer, err
}

func readMessageRegular(aead func([]byte) cipher.AEAD, cs *CipherState, message *P2PMessage) (plaintext []byte, valid bool, err error) {
	plaintext, valid, err = decryptWithAd(aead, cs, []byte{}, message.Ciphertext)
	return plaintext, valid, err
}
