//go:debug rsa1024min=0
package paillier_test

import (
	"bytes"
	crand "crypto/rand"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/indcpa/paillier"
)

func Test_RoundTrip(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	const keyLen = 2048
	const iters = 128

	sk, pk := randomKeys(t, keyLen, prng)
	for range iters {
		plaintext, err := pk.RandomPlaintext(prng)
		require.NoError(t, err)
		ciphertext, nonce, err := pk.Encrypt(plaintext, prng)
		require.NoError(t, err)

		m, r, err := sk.Open(ciphertext)
		require.NoError(t, err)
		require.True(t, plaintext.Eq(m) == 1)
		require.True(t, nonce.Eq(r) == 1)

		m, err = sk.Decrypt(ciphertext)
		require.NoError(t, err)
		require.True(t, plaintext.Eq(m) == 1)

		c, err := pk.EncryptWithNonce(m, r)
		require.NoError(t, err)
		require.True(t, ciphertext.C.Eq(&c.C) == 1)
		require.True(t, pk.CipherTextEqual(ciphertext, c))
	}
}

func Test_RoundTripWithSecret(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	const keyLen = 2048
	const iters = 128

	sk, _ := randomKeys(t, keyLen, prng)
	for range iters {
		plaintext, err := sk.RandomPlaintext(prng)
		require.NoError(t, err)
		ciphertext, nonce, err := sk.Encrypt(plaintext, prng)
		require.NoError(t, err)

		m, r, err := sk.Open(ciphertext)
		require.NoError(t, err)
		require.True(t, plaintext.Eq(m) == 1)
		require.True(t, nonce.Eq(r) == 1)

		m, err = sk.Decrypt(ciphertext)
		require.NoError(t, err)
		require.True(t, plaintext.Eq(m) == 1)

		c, err := sk.EncryptWithNonce(m, r)
		require.NoError(t, err)
		require.True(t, ciphertext.C.Eq(&c.C) == 1)
		require.True(t, sk.CipherTextEqual(ciphertext, c))
	}
}

func Test_RoundTripMany(t *testing.T) {
	t.Parallel()

	var err error
	prng := crand.Reader
	const keyLen = 2048
	const iters = 128

	sk, pk := randomKeys(t, keyLen, prng)
	plaintexts := make([]*paillier.PlainText, iters)
	for i := range plaintexts {
		plaintexts[i], err = pk.RandomPlaintext(prng)
		require.NoError(t, err)
	}

	ciphertexts, nonces, err := pk.EncryptMany(plaintexts, prng)
	require.NoError(t, err)

	for i, ciphertext := range ciphertexts {
		m, r, err := sk.Open(ciphertext)
		require.NoError(t, err)
		require.True(t, plaintexts[i].Eq(m) == 1)
		require.True(t, nonces[i].Eq(r) == 1)
	}

	for i, ciphertext := range ciphertexts {
		m, err := sk.Decrypt(ciphertext)
		require.NoError(t, err)
		require.True(t, plaintexts[i].Eq(m) == 1)
	}

	for i, plaintext := range plaintexts {
		c, err := pk.EncryptWithNonce(plaintext, nonces[i])
		require.NoError(t, err)
		require.True(t, ciphertexts[i].C.Eq(&c.C) == 1)
		require.True(t, pk.CipherTextEqual(ciphertexts[i], c))
	}
}

func Test_RoundTripManyWithSecret(t *testing.T) {
	t.Parallel()

	var err error
	prng := crand.Reader
	const keyLen = 2048
	const iters = 128

	sk, _ := randomKeys(t, keyLen, prng)
	plaintexts := make([]*paillier.PlainText, iters)
	for i := range plaintexts {
		plaintexts[i], err = sk.RandomPlaintext(prng)
		require.NoError(t, err)
	}

	ciphertexts, nonces, err := sk.EncryptMany(plaintexts, prng)
	require.NoError(t, err)

	for i, ciphertext := range ciphertexts {
		m, r, err := sk.Open(ciphertext)
		require.NoError(t, err)
		require.True(t, plaintexts[i].Eq(m) == 1)
		require.True(t, nonces[i].Eq(r) == 1)
	}

	for i, ciphertext := range ciphertexts {
		m, err := sk.Decrypt(ciphertext)
		require.NoError(t, err)
		require.True(t, plaintexts[i].Eq(m) == 1)
	}

	for i, plaintext := range plaintexts {
		c, err := sk.EncryptWithNonce(plaintext, nonces[i])
		require.NoError(t, err)
		require.True(t, ciphertexts[i].C.Eq(&c.C) == 1)
		require.True(t, sk.CipherTextEqual(ciphertexts[i], c))
	}
}

func Test_JsonSerialization(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	const keyLen = 4096

	sk, pk := randomKeys(t, keyLen, prng)
	plaintext, err := pk.RandomPlaintext(prng)
	require.NoError(t, err)
	ciphertext, nonce, err := pk.Encrypt(plaintext, prng)
	require.NoError(t, err)

	pkSer, err := json.Marshal(pk)
	require.NoError(t, err)
	skSer, err := json.Marshal(sk)
	require.NoError(t, err)

	var pkDe paillier.PublicKey
	err = json.Unmarshal(pkSer, &pkDe)
	require.NoError(t, err)
	var skDe paillier.SecretKey
	err = json.Unmarshal(skSer, &skDe)
	require.NoError(t, err)

	m, r, err := skDe.Open(ciphertext)
	require.NoError(t, err)
	require.True(t, plaintext.Eq(m) == 1)
	require.True(t, nonce.Eq(r) == 1)

	m, err = skDe.Decrypt(ciphertext)
	require.NoError(t, err)
	require.True(t, plaintext.Eq(m) == 1)

	c, err := pkDe.EncryptWithNonce(m, r)
	require.NoError(t, err)
	require.True(t, ciphertext.C.Eq(&c.C) == 1)
	require.True(t, pk.CipherTextEqual(ciphertext, c))
}

func Test_JsonSerializationWithSecret(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	const keyLen = 4096

	sk, _ := randomKeys(t, keyLen, prng)
	plaintext, err := sk.RandomPlaintext(prng)
	require.NoError(t, err)
	ciphertext, nonce, err := sk.Encrypt(plaintext, prng)
	require.NoError(t, err)

	skSer, err := json.Marshal(sk)
	require.NoError(t, err)

	var skDe paillier.SecretKey
	err = json.Unmarshal(skSer, &skDe)
	require.NoError(t, err)

	m, r, err := skDe.Open(ciphertext)
	require.NoError(t, err)
	require.True(t, plaintext.Eq(m) == 1)
	require.True(t, nonce.Eq(r) == 1)

	m, err = skDe.Decrypt(ciphertext)
	require.NoError(t, err)
	require.True(t, plaintext.Eq(m) == 1)

	c, err := skDe.EncryptWithNonce(m, r)
	require.NoError(t, err)
	require.True(t, ciphertext.C.Eq(&c.C) == 1)
	require.True(t, sk.CipherTextEqual(ciphertext, c))
}

func Test_BinarySerialization(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	const keyLen = 4096

	sk, pk := randomKeys(t, keyLen, prng)
	plaintext, err := pk.RandomPlaintext(prng)
	require.NoError(t, err)
	ciphertext, nonce, err := pk.Encrypt(plaintext, prng)
	require.NoError(t, err)

	pkBuf := new(bytes.Buffer)
	pkGobEnc := gob.NewEncoder(pkBuf)
	err = pkGobEnc.Encode(pk)
	require.NoError(t, err)
	pkSer := pkBuf.Bytes()

	skBuf := new(bytes.Buffer)
	skGobEnc := gob.NewEncoder(skBuf)
	err = skGobEnc.Encode(sk)
	require.NoError(t, err)
	skSer := skBuf.Bytes()

	pkDeBuf := bytes.NewBuffer(pkSer)
	pkGobDec := gob.NewDecoder(pkDeBuf)
	var pkDe paillier.PublicKey
	err = pkGobDec.Decode(&pkDe)
	require.NoError(t, err)

	skDeBuf := bytes.NewBuffer(skSer)
	skGobDec := gob.NewDecoder(skDeBuf)
	var skDe paillier.SecretKey
	err = skGobDec.Decode(&skDe)
	require.NoError(t, err)

	m, r, err := skDe.Open(ciphertext)
	require.NoError(t, err)
	require.True(t, plaintext.Eq(m) == 1)
	require.True(t, nonce.Eq(r) == 1)

	m, err = skDe.Decrypt(ciphertext)
	require.NoError(t, err)
	require.True(t, plaintext.Eq(m) == 1)

	c, err := pkDe.EncryptWithNonce(m, r)
	require.NoError(t, err)
	require.True(t, ciphertext.C.Eq(&c.C) == 1)
	require.True(t, pk.CipherTextEqual(ciphertext, c))
}

func Test_BinarySerializationWithSecret(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	const keyLen = 4096

	sk, _ := randomKeys(t, keyLen, prng)
	plaintext, err := sk.RandomPlaintext(prng)
	require.NoError(t, err)
	ciphertext, nonce, err := sk.Encrypt(plaintext, prng)
	require.NoError(t, err)

	skBuf := new(bytes.Buffer)
	skGobEnc := gob.NewEncoder(skBuf)
	err = skGobEnc.Encode(sk)
	require.NoError(t, err)
	skSer := skBuf.Bytes()

	skDeBuf := bytes.NewBuffer(skSer)
	skGobDec := gob.NewDecoder(skDeBuf)
	var skDe paillier.SecretKey
	err = skGobDec.Decode(&skDe)
	require.NoError(t, err)

	m, r, err := skDe.Open(ciphertext)
	require.NoError(t, err)
	require.True(t, plaintext.Eq(m) == 1)
	require.True(t, nonce.Eq(r) == 1)

	m, err = skDe.Decrypt(ciphertext)
	require.NoError(t, err)
	require.True(t, plaintext.Eq(m) == 1)

	c, err := skDe.EncryptWithNonce(m, r)
	require.NoError(t, err)
	require.True(t, ciphertext.C.Eq(&c.C) == 1)
	require.True(t, sk.CipherTextEqual(ciphertext, c))
}

func Example_roundTrip() {
	message := []byte("Hello World!")
	mappedMessage := new(saferith.Int).SetBytes(message)

	pub, sec, err := paillier.KeyGen(256, crand.Reader)
	if err != nil {
		log.Fatalf("Error in generating keypair: %v", err)
	}

	// Ignoring the random value that was generated internally by `Encrypt`.
	cipher, _, err := pub.Encrypt(mappedMessage, crand.Reader)
	if err != nil {
		log.Fatalf("Error in Encrypting the message: %v", err)
	}

	// Now decrypt using the secret key.
	decrypted, err := sec.Decrypt(cipher)
	if err != nil {
		log.Fatalf("Error in Decrypting the ciphertext: %v", err)
	}

	decoded := string(decrypted.Big().Bytes())
	fmt.Println("Succeeded in encrypting and decrypting the input message:", decoded)

	// Output:
	// Succeeded in encrypting and decrypting the input message: Hello World!
}

func Example_homomorphicAddition() {
	pub, sec, err := paillier.KeyGen(256, crand.Reader)
	if err != nil {
		log.Fatalf("Error in generating keypair: %v", err)
	}

	msg1 := new(saferith.Int).SetUint64(123)
	msg2 := new(saferith.Int).SetUint64(456).Neg(1)
	fmt.Printf("Encrypting %s and %s separately.\n", msg1.Big().String(), msg2.Big().String())

	cipher1, _, err := pub.Encrypt(msg1, crand.Reader)
	if err != nil {
		log.Fatalf("Error in Encrypting the message: %v", err)
	}
	cipher2, _, err := pub.Encrypt(msg2, crand.Reader)
	if err != nil {
		log.Fatalf("Error in Encrypting the message: %v", err)
	}

	fmt.Println("Adding their encrypted versions together.")
	cipher3, err := pub.CipherTextAdd(cipher1, cipher2)
	if err != nil {
		log.Fatalf("Error in adding the two ciphertexts: %v", err)
	}

	decrypted3, err := sec.Decrypt(cipher3)
	if err != nil {
		log.Fatalf("Error in Decrypting the ciphertext: %v", err)
	}
	fmt.Println("Succeeded in decrypting", decrypted3.Big().String())

	// Output:
	// Encrypting 123 and -456 separately.
	// Adding their encrypted versions together.
	// Succeeded in decrypting -333
}

func Example_homomorphicMultiplication() {
	pub, sec, err := paillier.KeyGen(256, crand.Reader)
	if err != nil {
		log.Fatalf("Error in generating keypair: %v", err)
	}

	msg1 := new(saferith.Int).SetUint64(42).Neg(1)
	msg2 := new(saferith.Int).SetUint64(26).Neg(1)
	fmt.Printf("Encrypting %s.\n", msg1.Big().String())

	cipher1, _, err := pub.Encrypt(msg1, crand.Reader)
	if err != nil {
		log.Fatalf("Error in Encrypting the message: %v", err)
	}

	fmt.Printf("Multiplying plain %s with the encrypted %s.\n", msg2.Big().String(), msg1.Big().String())
	cipher3, err := pub.CipherTextMul(cipher1, msg2)
	if err != nil {
		log.Fatalf("Error in adding the two ciphertexts: %v", err)
	}
	decrypted3, err := sec.Decrypt(cipher3)
	if err != nil {
		log.Fatalf("Error in Decrypting the ciphertext: %v", err)
	}
	fmt.Printf("Succeeded in decrypting %s.\n", decrypted3.Big().String())

	// Output:
	// Encrypting -42.
	// Multiplying plain -26 with the encrypted -42.
	// Succeeded in decrypting 1092.
}

func randomKeys(tb testing.TB, keyLen int, prng io.Reader) (*paillier.SecretKey, *paillier.PublicKey) {
	tb.Helper()

	pBig, err := crand.Prime(prng, keyLen/2)
	require.NoError(tb, err)
	p := new(saferith.Nat).SetBig(pBig, keyLen/2)

	qBig, err := crand.Prime(prng, keyLen/2)
	require.NoError(tb, err)
	q := new(saferith.Nat).SetBig(qBig, keyLen/2)

	sk, err := paillier.NewSecretKey(p, q)
	require.NoError(tb, err)
	pk, err := sk.ToEncryptionKey()
	require.NoError(tb, err)

	return sk, pk
}
