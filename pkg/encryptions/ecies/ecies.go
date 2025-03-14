package ecies

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha512"
	"crypto/subtle"
	"io"

	"golang.org/x/crypto/hkdf"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/key_agreement/dh"
)

const (
	P1 = "KRYPTON_ECIES_IEEE_1363A_HKDF_512_INFO-"
	P2 = "KRYPTON_ECIES_IEEE_1363A_HMAC_512_ENCODING_PARAMETER-"
	L2 = 64
)

type PrivateKey struct {
	S curves.Scalar
	PublicKey

	_ ds.Incomparable
}

type PublicKey = curves.Point

func Encrypt(myPrivateKey *PrivateKey, receiverPublicKey PublicKey, message, AD []byte, prng io.Reader) (ciphertext, tag []byte, err error) {
	if myPrivateKey == nil || receiverPublicKey == nil || message == nil || prng == nil {
		return nil, nil, errs.NewIsNil("nil arguments")
	}
	// step 1.1
	if myPrivateKey.S.IsZero() {
		return nil, nil, errs.NewIsZero("my private key is zero")
	}
	if !receiverPublicKey.IsInPrimeSubGroup() {
		return nil, nil, errs.NewValidation("Public Key not in the prime subgroup")
	}
	// step 1.2
	z, err := dh.DiffieHellman(myPrivateKey.S, receiverPublicKey)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not derive shared secret")
	}

	// step 1.3
	Z := z.Bytes()

	// step 1.4
	V := myPrivateKey.PublicKey.ToAffineUncompressed()

	// step 1.5
	VZ := make([]byte, len(V)+len(Z))
	copy(VZ, V)
	copy(VZ[len(V):], Z)

	// step 1.6
	K1, K2, err := deriveKeys(VZ)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not derive keys")
	}

	// step 1.7
	C, err := aes256CBCEncrypt(K1, message, prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not encrypt message using AES 256 CBC")
	}

	// step 1.8
	T, err := produceTag(K2, ciphertext, AD)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not produce authentication tag")
	}

	// step 1.9
	return C, T, nil
}

func EncryptEphemeral(myPrivateKey *PrivateKey, message, AD []byte, prng io.Reader) (ephemeralPublicKey PublicKey, ciphertext, tag []byte, err error) {
	if myPrivateKey == nil {
		return nil, nil, nil, errs.NewIsNil("my private key is nil")
	}
	for ephemeralPublicKey == nil || ephemeralPublicKey.IsAdditiveIdentity() {
		ephemeralPublicKey, err = myPrivateKey.S.ScalarField().Curve().Random(prng)
		if err != nil {
			return nil, nil, nil, errs.WrapFailed(err, "could not generate random point")
		}
	}
	ciphertext, tag, err = Encrypt(myPrivateKey, ephemeralPublicKey, message, AD, prng)
	if err != nil {
		return nil, nil, nil, errs.WrapFailed(err, "could not encrypt")
	}
	return ephemeralPublicKey, ciphertext, tag, nil
}

func Decrypt(myPrivateKey *PrivateKey, senderPublicKey PublicKey, ciphertext, tag, AD []byte, prng io.Reader) (message []byte, err error) {
	if myPrivateKey == nil || senderPublicKey == nil || ciphertext == nil || tag == nil || prng == nil {
		return nil, errs.NewIsNil("nil arguments")
	}
	if !senderPublicKey.IsInPrimeSubGroup() {
		return nil, errs.NewValidation("Public Key not in the prime subgroup")
	}
	if len(ciphertext) == 0 {
		return nil, errs.NewLength("ciphertext length is zero")
	}
	if len(tag) != 64 {
		return nil, errs.NewLength("authentication tag's length is not 64: it is %d", len(tag))
	}
	// step 2.1: since the public key is deserialized, it's already on curve so just checking for identity.
	if myPrivateKey.S.IsZero() {
		return nil, errs.NewIsZero("my private key is zero")
	}

	// step 2.2
	z, err := dh.DiffieHellman(myPrivateKey.S, senderPublicKey)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not derive shared secret")
	}

	// step 2.3
	Z := z.Bytes()

	// step 2.4
	V := myPrivateKey.PublicKey.ToAffineUncompressed()

	// step 2.5
	VZ := make([]byte, len(V)+len(Z))
	copy(VZ, V)
	copy(VZ[len(V):], Z)

	// step 2.6
	K1, K2, err := deriveKeys(VZ)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not derive keys")
	}

	// step 2.7
	message, err = aes256CBCDecrypt(K1, ciphertext)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't decrypt ciphertext using AES-256 CBC")
	}

	// step 2.8
	tPrime, err := produceTag(K2, ciphertext, AD)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not recompute tag")
	}
	// step 2.9
	if subtle.ConstantTimeCompare(tag, tPrime) == 1 {
		return nil, errs.NewVerification("authentication check failed")
	}
	// step 2.10
	return message, nil
}

func deriveKeys(vz []byte) (k1, k2 []byte, err error) {
	kdf := hkdf.New(sha512.New, vz, nil, []byte(P1))
	aesKeyLength := 32
	hmacKeyLength := 64
	K := make([]byte, aesKeyLength+hmacKeyLength)
	_, err = io.ReadFull(kdf, K)
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "could not read bytes for K")
	}
	k1 = K[:aesKeyLength]
	k2 = K[aesKeyLength:]
	return k1, k2, nil
}

func aes256CBCEncrypt(key, message []byte, prng io.Reader) (ciphertext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct block cipher")
	}
	padded := pkcs7Padding(message, block.BlockSize())
	ciphertext = make([]byte, block.BlockSize()+len(padded))
	iv := ciphertext[:block.BlockSize()]
	if _, err := io.ReadFull(prng, iv); err != nil {
		return nil, errs.WrapRandomSample(err, "couldn't read iv")
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[block.BlockSize():], padded)
	return ciphertext, nil
}

func aes256CBCDecrypt(key, ciphertext []byte) (message []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct block cipher")
	}
	if len(ciphertext) < block.BlockSize() {
		return nil, errs.NewLength("ciphertext is too short: length is %d", len(ciphertext))
	}
	iv := ciphertext[:block.BlockSize()]
	ciphertext = ciphertext[block.BlockSize():]

	mode := cipher.NewCBCDecrypter(block, iv)
	paddedMessage := make([]byte, len(ciphertext))
	mode.CryptBlocks(paddedMessage, ciphertext)
	message = pkcs7Unpadding(paddedMessage)

	return message, nil
}

func produceTag(key, ciphertext, AD []byte) ([]byte, error) {
	mac1 := hmac.New(sha512.New, key)
	if _, err := mac1.Write(ciphertext); err != nil {
		return nil, errs.WrapFailed(err, "could not write ciphertext to mac1")
	}
	if _, err := mac1.Write([]byte(P2)); err != nil {
		return nil, errs.WrapFailed(err, "could not write P2 to mac1")
	}
	if _, err := mac1.Write(AD); err != nil {
		return nil, errs.WrapFailed(err, "could not write AD to mac1")
	}
	if _, err := mac1.Write([]byte{byte(L2)}); err != nil {
		return nil, errs.WrapFailed(err, "could not write L2 to mac1")
	}
	return mac1.Sum(nil), nil
}

func pkcs7Padding(data []byte, blockSize int) []byte {
	paddingSize := blockSize - len(data)%blockSize
	padding := bytes.Repeat([]byte{byte(paddingSize)}, paddingSize)
	return append(data, padding...)
}

func pkcs7Unpadding(data []byte) []byte {
	length := len(data)
	unpadding := int(data[length-1])
	return data[:(length - unpadding)]
}
