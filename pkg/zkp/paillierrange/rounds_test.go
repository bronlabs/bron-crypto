package paillierrange_test

import (
	crand "crypto/rand"
	"github.com/copperexchange/crypto-primitives-go/pkg/paillier"
	"github.com/copperexchange/crypto-primitives-go/pkg/zkp/paillierrange"
	"github.com/stretchr/testify/require"
	"io"
	"math/big"
	"testing"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	pk, sk, err := paillier.NewKeys(128)
	require.NoError(t, err)

	q := big.NewInt(3_000_000)
	x, err := randomIntInRange(q, prng)
	require.NoError(t, err)
	xEncrypted, r, err := pk.Encrypt(x)
	require.NoError(t, err)

	sid := []byte("sessionId")
	err = doProof(x, xEncrypted, r, q, pk, sk, sid, prng)
	require.NoError(t, err)
}

// The way the proof is constructed in order to test that verifier fails to verify if x is out of range
// it would require to make a "cheating" prover implementation, so we do the best we can to test failed
// scenario, although it does not make prover cheating in this scenario.
func Test_OutOfRange(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	pk, sk, err := paillier.NewKeys(128)
	require.NoError(t, err)

	q := big.NewInt(3_000_000)

	x1, err := randomIntOutRangeLow(q, prng)
	require.NoError(t, err)
	x1Encrypted, r, err := pk.Encrypt(x1)
	require.NoError(t, err)

	x2, err := randomIntOutRangeHigh(q, prng)
	require.NoError(t, err)
	x2Encrypted, r, err := pk.Encrypt(x2)
	require.NoError(t, err)

	t.Run("x below the range", func(t *testing.T) {
		sid1 := []byte("sessionId1")
		err = doProof(x1, x1Encrypted, r, q, pk, sk, sid1, prng)
		require.Error(t, err)
	})

	t.Run("x above the range", func(t *testing.T) {
		sid2 := []byte("sessionId2")
		err = doProof(x2, x2Encrypted, r, q, pk, sk, sid2, prng)
		require.Error(t, err)
	})
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
	l := new(big.Int).Div(q, big.NewInt(3))
	return crand.Int(prng, l)
}

func randomIntOutRangeHigh(q *big.Int, prng io.Reader) (*big.Int, error) {
	l := new(big.Int).Div(q, big.NewInt(3))
	x, err := crand.Int(prng, l)
	if err != nil {
		return nil, err
	}
	return new(big.Int).Add(new(big.Int).Add(l, l), x), nil
}

func doProof(x *big.Int, xEncrypted paillier.CipherText, r *big.Int, q *big.Int, pk *paillier.PublicKey, sk *paillier.SecretKey, sid []byte, prng io.Reader) (err error) {
	verifier, err := paillierrange.NewVerifier(40, xEncrypted, q, pk, sid, prng)
	if err != nil {
		return err
	}
	prover, err := paillierrange.NewProver(40, x, r, q, sk, sid, prng)
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

	return nil
}
