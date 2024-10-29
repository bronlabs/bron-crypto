package paillierrange_test

import (
	"bytes"
	crand "crypto/rand"
	"fmt"
	"io"
	"strconv"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/indcpa/paillier"
	paillierrange "github.com/copperexchange/krypton-primitives/pkg/proofs/paillier/range"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	primesBitLength := 128
	nIter := 100
	pk, sk, err := paillier.KeyGen(primesBitLength, prng)
	require.NoError(t, err)
	q := new(saferith.Nat).SetUint64(3_000_000)

	for i := 0; i < nIter; i++ {
		sid := append([]byte("sessionId_"), []byte(strconv.Itoa(i))...)
		x, err := randomIntInRange(q, prng, primesBitLength)
		require.NoError(t, err)

		t.Run(fmt.Sprintf("in range %s", x.String()), func(t *testing.T) {
			t.Parallel()

			xEncrypted, r, err := pk.Encrypt(x, prng)
			require.NoError(t, err)

			err = doProof(x, xEncrypted, r, q, pk, sk, sid, prng, primesBitLength)
			require.NoError(t, err)
		})
	}
}

func Test_OutOfRange(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	primesBitLength := 128
	nIter := 100
	pk, sk, err := paillier.KeyGen(primesBitLength, prng)
	require.NoError(t, err)
	q := new(saferith.Nat).SetUint64(3_000_000)

	for i := 0; i < nIter; i++ {
		sid := append([]byte("LowSessionId_"), []byte(strconv.Itoa(i))...)
		x, err := randomIntOutRangeLow(q, prng, primesBitLength)
		require.NoError(t, err)

		t.Run(fmt.Sprintf("below range %s", x.String()), func(t *testing.T) {
			t.Parallel()

			xEncrypted, r, err := pk.Encrypt(x, prng)
			require.NoError(t, err)
			err = doProof(x, xEncrypted, r, q, pk, sk, sid, prng, primesBitLength)
			require.Error(t, err)
		})
	}

	for i := 0; i < nIter; i++ {
		sid := append([]byte("HighSessionId_"), []byte(strconv.Itoa(i))...)
		x, err := randomIntOutRangeHigh(q, prng)
		require.NoError(t, err)

		t.Run(fmt.Sprintf("above range %s", x.String()), func(t *testing.T) {
			t.Parallel()

			xEncrypted, r, err := pk.Encrypt(x, prng)
			require.NoError(t, err)
			err = doProof(x, xEncrypted, r, q, pk, sk, sid, prng, primesBitLength)
			require.Error(t, err)
		})
	}
}

func randomIntInRange(q *saferith.Nat, prng io.Reader, bitLength int) (*saferith.Nat, error) {
	l := new(saferith.Nat).Div(q, saferith.ModulusFromUint64(3), bitLength)
	xInt, err := crand.Int(prng, l.Big())
	if err != nil {
		return nil, errs.WrapRandomSample(err, "cannot sample integer")
	}
	x := new(saferith.Nat).SetBig(xInt, 256)
	return new(saferith.Nat).Add(l, x, 256), nil
}

func randomIntOutRangeLow(q *saferith.Nat, prng io.Reader, bitLength int) (*saferith.Nat, error) {
	// we should make x < 0 to make this 100% correct but this is good enough
	// and current Paillier encryption does not support negative numbers
	l := new(saferith.Nat).Div(q, saferith.ModulusFromUint64(4), bitLength)
	xInt, err := crand.Int(prng, l.Big()) // x < q/4
	if err != nil {
		return nil, errs.WrapRandomSample(err, "cannot sample integer")
	}
	return new(saferith.Nat).SetBig(xInt, 256), nil
}

func randomIntOutRangeHigh(q *saferith.Nat, prng io.Reader) (*saferith.Nat, error) {
	xInt, err := crand.Int(prng, q.Big())
	if err != nil {
		return nil, errs.WrapRandomSample(err, "cannot sample integer")
	}
	x := new(saferith.Nat).SetBig(xInt, 256)
	return new(saferith.Nat).Add(x, q, 256), nil // x >= q
}

func doProof(x *saferith.Nat, xEncrypted *paillier.CipherText, r, q *saferith.Nat, pk *paillier.PublicKey, sk *paillier.SecretKey, sid []byte, prng io.Reader, primesBitLength int) (err error) {
	appLabel := "Range"

	verifierTranscript := hagrid.NewTranscript(appLabel, nil)
	verifier, err := paillierrange.NewVerifier(primesBitLength, q, pk, xEncrypted, sid, verifierTranscript, prng)
	if err != nil {
		return err
	}
	proverTranscript := hagrid.NewTranscript(appLabel, nil)
	prover, err := paillierrange.NewProver(primesBitLength, q, sk, x, r, sid, proverTranscript, prng)
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
	proverBytes, _ := proverTranscript.ExtractBytes(label, base.ComputationalSecurity)
	verifierBytes, _ := verifierTranscript.ExtractBytes(label, base.ComputationalSecurity)
	if !bytes.Equal(proverBytes, verifierBytes) {
		return errs.NewFailed("transcript record different data")
	}

	return nil
}
