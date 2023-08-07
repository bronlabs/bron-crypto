package paillierrange_test

import (
	"bytes"
	crand "crypto/rand"
	"fmt"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/paillier"
	"github.com/copperexchange/crypto-primitives-go/pkg/proofs/paillier/range"
	"github.com/copperexchange/crypto-primitives-go/pkg/transcript/merlin"
	"github.com/stretchr/testify/require"
	"io"
	"math/big"
	"strconv"
	"testing"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	pk, sk, err := paillier.NewKeys(128)
	require.NoError(t, err)
	q := big.NewInt(3_000_000)

	for i := 0; i < 128; i++ {
		sid := append([]byte("sessionId_"), []byte(strconv.Itoa(i))...)
		x, err := randomIntInRange(q, prng)
		require.NoError(t, err)

		t.Run(fmt.Sprintf("in range %s", x.String()), func(t *testing.T) {
			t.Parallel()

			xEncrypted, r, err := pk.Encrypt(x)
			require.NoError(t, err)

			err = doProof(x, xEncrypted, r, q, pk, sk, sid, prng)
			require.NoError(t, err)
		})
	}
}

func Test_OutOfRange(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	pk, sk, err := paillier.NewKeys(128)
	require.NoError(t, err)
	q := big.NewInt(3_000_000)

	for i := 0; i < 128; i++ {
		sid := append([]byte("LowSessionId_"), []byte(strconv.Itoa(i))...)
		x, err := randomIntOutRangeLow(q, prng)
		require.NoError(t, err)

		t.Run(fmt.Sprintf("below range %s", x.String()), func(t *testing.T) {
			t.Parallel()

			xEncrypted, r, err := pk.Encrypt(x)
			require.NoError(t, err)
			err = doProof(x, xEncrypted, r, q, pk, sk, sid, prng)
			require.Error(t, err)
		})
	}

	for i := 0; i < 128; i++ {
		sid := append([]byte("HighSessionId_"), []byte(strconv.Itoa(i))...)
		x, err := randomIntOutRangeHigh(q, prng)
		require.NoError(t, err)

		t.Run(fmt.Sprintf("above range %s", x.String()), func(t *testing.T) {
			t.Parallel()

			xEncrypted, r, err := pk.Encrypt(x)
			require.NoError(t, err)
			err = doProof(x, xEncrypted, r, q, pk, sk, sid, prng)
			require.Error(t, err)
		})
	}
}

func randomIntInRange(q *big.Int, prng io.Reader) (*big.Int, error) {
	l := new(big.Int).Div(q, big.NewInt(3))
	x, err := crand.Int(prng, l)
	if err != nil {
		return nil, err
	}
	return new(big.Int).Add(l, x), nil
}

func randomIntOutRangeLow(q *big.Int, prng io.Reader) (*big.Int, error) {
	// we should make x < 0 to make this 100% correct but this is good enough
	// and current Paillier encryption does not support negative numbers
	l := new(big.Int).Div(q, big.NewInt(4))
	return crand.Int(prng, l) // x < q/4
}

func randomIntOutRangeHigh(q *big.Int, prng io.Reader) (*big.Int, error) {
	x, err := crand.Int(prng, q)
	if err != nil {
		return nil, err
	}
	return new(big.Int).Add(x, q), nil // x >= q
}

func doProof(x *big.Int, xEncrypted paillier.CipherText, r *big.Int, q *big.Int, pk *paillier.PublicKey, sk *paillier.SecretKey, sid []byte, prng io.Reader) (err error) {
	appLabel := "Range"

	verifierTranscript := merlin.NewTranscript(appLabel)
	verifier, err := paillierrange.NewVerifier(128, q, sid, pk, xEncrypted, sid, verifierTranscript, prng)
	if err != nil {
		return err
	}
	proverTranscript := merlin.NewTranscript(appLabel)
	prover, err := paillierrange.NewProver(128, q, sid, sk, x, r, sid, proverTranscript, prng)
	if err != nil {
		return err
	}

	r1, err := verifier.Round1()
	if err != nil {
		return err
	}
	r2, err := prover.Round2(r1)
	if err != nil {
		return err
	}
	r3, err := verifier.Round3(r2)
	if err != nil {
		return err
	}
	r4, err := prover.Round4(r3)
	if err != nil {
		return err
	}
	err = verifier.Round5(r4)
	if err != nil {
		return err
	}

	label := "gimme, gimme"
	proverBytes := proverTranscript.ExtractBytes([]byte(label), 128)
	verifierBytes := verifierTranscript.ExtractBytes([]byte(label), 128)
	if !bytes.Equal(proverBytes, verifierBytes) {
		return errs.NewFailed("transcript record different data")
	}

	return nil
}
