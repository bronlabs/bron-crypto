package paillierdlog_test

import (
	crand "crypto/rand"
	"flag"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/paillier"
	"github.com/copperexchange/crypto-primitives-go/pkg/zkp/paillierdlog"
	"github.com/stretchr/testify/require"
	"io"
	"math/big"
	"os"
	"testing"
)

var (
	pk *paillier.PublicKey
	sk *paillier.SecretKey
)

// Paillier key generation is slow, do it once for all tests
func TestMain(m *testing.M) {
	flag.Parse()
	if !testing.Short() {
		var err error
		pk, sk, err = paillier.NewKeys(1024)
		if err != nil {
			os.Exit(1)
		}
	}

	code := m.Run()
	os.Exit(code)
}

func Test_HappyPath(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip()
	}

	prng := crand.Reader
	curve := curves.P256()
	elCurve, err := curve.ToEllipticCurve()
	require.NoError(t, err)
	q := elCurve.Params().N

	xInt, err := randomIntInRange(q, prng)
	require.NoError(t, err)

	x, err := curve.NewScalar().SetBigInt(xInt)
	require.NoError(t, err)

	bigQ := curve.ScalarBaseMult(x)
	xEncrypted, r, err := pk.Encrypt(x.BigInt())
	require.NoError(t, err)

	sid := []byte("sessionId")
	err = doProof(x, bigQ, xEncrypted, r, pk, sk, sid, prng)
	require.NoError(t, err)
}

// xEncrypted is not a dlog of Q
func Test_FailVerificationOnFalseClaim(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip()
	}

	prng := crand.Reader
	curve := curves.P256()
	elCurve, err := curve.ToEllipticCurve()
	require.NoError(t, err)
	q := elCurve.Params().N

	x1Int, err := randomIntInRange(q, prng)
	require.NoError(t, err)
	x1, err := curve.NewScalar().SetBigInt(x1Int)
	require.NoError(t, err)

	x2Int, err := randomIntInRange(q, prng)
	require.NoError(t, err)
	x2, err := curve.NewScalar().SetBigInt(x2Int)
	require.NoError(t, err)

	bigQ2 := curve.ScalarBaseMult(x2)
	x1Encrypted, r, err := pk.Encrypt(x1.BigInt())
	require.NoError(t, err)

	sid := []byte("sessionId")
	err = doProof(x1, bigQ2, x1Encrypted, r, pk, sk, sid, prng)
	require.Error(t, err)
}

// xEncrypted is not encryption of x
func Test_FailVerificationOnIncorrectDlog(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip()
	}

	prng := crand.Reader
	curve := curves.P256()
	elCurve, err := curve.ToEllipticCurve()
	require.NoError(t, err)
	q := elCurve.Params().N

	xInt, err := randomIntInRange(q, prng)
	require.NoError(t, err)
	x, err := curve.NewScalar().SetBigInt(xInt)
	require.NoError(t, err)
	bigQ := curve.ScalarBaseMult(x)

	x2Encrypted, r, err := pk.Encrypt(curve.NewScalar().Random(prng).BigInt())
	require.NoError(t, err)

	sid := []byte("sessionId")
	err = doProof(x, bigQ, x2Encrypted, r, pk, sk, sid, prng)
	require.Error(t, err)
}

func Test_FailOnOutOfRange(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	t.Parallel()

	prng := crand.Reader
	curve := curves.P256()
	elCurve, err := curve.ToEllipticCurve()
	require.NoError(t, err)
	q := elCurve.Params().N

	xLowInt, err := randomIntOutRangeLow(q, prng)
	require.NoError(t, err)
	xLow, err := curve.NewScalar().SetBigInt(xLowInt)
	require.NoError(t, err)
	bigQLow := curve.ScalarBaseMult(xLow)
	xLowEncrypted, r, err := pk.Encrypt(xLow.BigInt())
	require.NoError(t, err)

	xHighInt, err := randomIntOutRangeHigh(q, prng)
	require.NoError(t, err)
	xHigh, err := curve.NewScalar().SetBigInt(xHighInt)
	require.NoError(t, err)
	bigQHigh := curve.ScalarBaseMult(xHigh)
	xHighEncrypted, r, err := pk.Encrypt(xHigh.BigInt())
	require.NoError(t, err)

	t.Run("x below the range", func(t *testing.T) {
		t.Parallel()

		sidLow := []byte("sessionIdLow")
		err = doProof(xLow, bigQLow, xLowEncrypted, r, pk, sk, sidLow, prng)
		require.Error(t, err)
	})

	t.Run("x above the range", func(t *testing.T) {
		t.Parallel()

		sidHigh := []byte("sessionIdHigh")
		err = doProof(xHigh, bigQHigh, xHighEncrypted, r, pk, sk, sidHigh, prng)
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

func doProof(x curves.Scalar, bigQ curves.Point, xEncrypted paillier.CipherText, r *big.Int, pk *paillier.PublicKey, sk *paillier.SecretKey, sessionId []byte, prng io.Reader) (err error) {
	verifier, err := paillierdlog.NewVerifier(sessionId, pk, bigQ, xEncrypted, prng)
	if err != nil {
		return err
	}

	prover, err := paillierdlog.NewProver(sessionId, sk, x, r, prng)
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
