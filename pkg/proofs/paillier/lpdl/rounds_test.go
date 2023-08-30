package lpdl_test

import (
	"bytes"
	crand "crypto/rand"
	"io"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/p256"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/encryptions/paillier"
	"github.com/copperexchange/knox-primitives/pkg/proofs/paillier/lpdl"
	"github.com/copperexchange/knox-primitives/pkg/transcripts/hagrid"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	pk, sk, err := paillier.NewKeys(1024)
	require.NoError(t, err)
	prng := crand.Reader
	curve := p256.New()
	q := curve.Profile().SubGroupOrder()

	xNat, err := randomIntInRange(q.Nat(), prng)
	require.NoError(t, err)

	x, err := curve.Scalar().SetNat(xNat)
	require.NoError(t, err)

	bigQ := curve.ScalarBaseMult(x)
	xEncrypted, r, err := pk.Encrypt(xNat)
	require.NoError(t, err)

	sid := []byte("sessionId")
	err = doProof(x, bigQ, xEncrypted, r, pk, sk, sid, prng)
	require.NoError(t, err)
}

// xEncrypted is not a dlog of Q
func Test_FailVerificationOnFalseClaim(t *testing.T) {
	t.Parallel()

	pk, sk, err := paillier.NewKeys(1024)
	require.NoError(t, err)
	prng := crand.Reader
	curve := p256.New()
	q := curve.Profile().SubGroupOrder()

	x1Nat, err := randomIntInRange(q.Nat(), prng)
	require.NoError(t, err)
	x1, err := curve.Scalar().SetNat(x1Nat)
	require.NoError(t, err)

	x2Nat, err := randomIntInRange(q.Nat(), prng)
	require.NoError(t, err)
	x2, err := curve.Scalar().SetNat(x2Nat)
	require.NoError(t, err)

	bigQ2 := curve.ScalarBaseMult(x2)
	x1Encrypted, r, err := pk.Encrypt(x1Nat)
	require.NoError(t, err)

	sid := []byte("sessionId")
	err = doProof(x1, bigQ2, x1Encrypted, r, pk, sk, sid, prng)
	require.Error(t, err)
}

// xEncrypted is not encryption of x
func Test_FailVerificationOnIncorrectDlog(t *testing.T) {
	t.Parallel()

	pk, sk, err := paillier.NewKeys(1024)
	require.NoError(t, err)
	prng := crand.Reader
	curve := p256.New()
	q := curve.Profile().SubGroupOrder()

	xNat, err := randomIntInRange(q.Nat(), prng)
	require.NoError(t, err)
	x, err := curve.Scalar().SetNat(xNat)
	require.NoError(t, err)
	bigQ := curve.ScalarBaseMult(x)

	x2Int := curve.Scalar().Random(prng).Nat()
	x2Encrypted, r, err := pk.Encrypt(x2Int)
	require.NoError(t, err)

	sid := []byte("sessionId")
	err = doProof(x, bigQ, x2Encrypted, r, pk, sk, sid, prng)
	require.Error(t, err)
}

func Test_FailOnOutOfRange(t *testing.T) {
	t.Parallel()

	pk, sk, err := paillier.NewKeys(1024)
	require.NoError(t, err)
	prng := crand.Reader
	curve := p256.New()
	q := curve.Profile().SubGroupOrder()

	xLowNat, err := randomIntOutRangeLow(q.Nat(), prng)
	require.NoError(t, err)
	xLow, err := curve.Scalar().SetNat(xLowNat)
	require.NoError(t, err)
	bigQLow := curve.ScalarBaseMult(xLow)
	xLowEncrypted, _, err := pk.Encrypt(xLowNat)
	require.NoError(t, err)

	xHighNat, err := randomIntOutRangeHigh(q.Nat(), prng)
	require.NoError(t, err)
	xHigh, err := curve.Scalar().SetNat(xHighNat)
	require.NoError(t, err)
	bigQHigh := curve.ScalarBaseMult(xHigh)
	xHighEncrypted, r, err := pk.Encrypt(xHighNat)
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

func randomIntInRange(q *saferith.Nat, prng io.Reader) (*saferith.Nat, error) {
	l := new(saferith.Nat).Div(q, saferith.ModulusFromUint64(3), 2048)
	xInt, err := crand.Int(prng, l.Big())
	if err != nil {
		return nil, err
	}
	x := new(saferith.Nat).SetBig(xInt, 2048)
	return new(saferith.Nat).Add(l, x, 2048), nil
}

func randomIntOutRangeLow(q *saferith.Nat, prng io.Reader) (*saferith.Nat, error) {
	l := new(saferith.Nat).Div(q, saferith.ModulusFromUint64(4), 2048)
	xInt, err := crand.Int(prng, l.Big())
	if err != nil {
		return nil, err
	}
	x := new(saferith.Nat).SetBig(xInt, 2048)
	return x, nil
}

func randomIntOutRangeHigh(q *saferith.Nat, prng io.Reader) (*saferith.Nat, error) {
	xInt, err := crand.Int(prng, q.Big())
	if err != nil {
		return nil, err
	}
	x := new(saferith.Nat).SetBig(xInt, 2048)
	return new(saferith.Nat).Add(q, x, 2048), nil
}

func doProof(x curves.Scalar, bigQ curves.Point, xEncrypted *paillier.CipherText, r *saferith.Nat, pk *paillier.PublicKey, sk *paillier.SecretKey, sessionId []byte, prng io.Reader) (err error) {
	transcriptLabel := "LPDL"

	verifierTranscript := hagrid.NewTranscript(transcriptLabel)
	verifier, err := lpdl.NewVerifier(sessionId, pk, bigQ, xEncrypted, sessionId, verifierTranscript, prng)
	if err != nil {
		return err
	}

	proverTranscript := hagrid.NewTranscript(transcriptLabel)
	prover, err := lpdl.NewProver(sessionId, sk, x, r, sessionId, proverTranscript, prng)
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
	proverBytes := proverTranscript.ExtractBytes(label, 128)
	verifierBytes := verifierTranscript.ExtractBytes(label, 128)
	if !bytes.Equal(proverBytes, verifierBytes) {
		return errs.NewFailed("transcript record different data")
	}

	return nil
}
