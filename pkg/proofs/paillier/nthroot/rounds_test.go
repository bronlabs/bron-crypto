package nthroot_test

import (
	"bytes"
	crand "crypto/rand"
	"io"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/paillier/nthroot"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

func doProof(x, y, bigN *saferith.Nat, prng io.Reader) (err error) {
	sessionId := []byte("nthRootSession")
	appLabel := "NthRoot"
	proverTranscript := hagrid.NewTranscript(appLabel, nil)
	prover, err := nthroot.NewProver(bigN, x, y, sessionId, proverTranscript, prng)
	if err != nil {
		return err
	}
	verifierTranscript := hagrid.NewTranscript(appLabel, nil)
	verifier, err := nthroot.NewVerifier(bigN, x, sessionId, verifierTranscript, prng)
	if err != nil {
		return err
	}

	r1, err := prover.Round1()
	if err != nil {
		return err
	}
	r2, err := verifier.Round2(r1)
	if err != nil {
		return err
	}
	r3, err := prover.Round3(r2)
	if err != nil {
		return err
	}

	err = verifier.Round4(r3)
	if err != nil {
		return err
	}

	label := "gimme, gimme"
	proverBytes, _ := proverTranscript.ExtractBytes(label, 128)
	verifierBytes, _ := verifierTranscript.ExtractBytes(label, 128)
	if !bytes.Equal(proverBytes, verifierBytes) {
		return errs.NewFailed("transcript record different data")
	}

	return nil
}

func Test_HappyPath(t *testing.T) {
	prng := crand.Reader
	pInt, err := crand.Prime(prng, 128)
	require.NoError(t, err)
	p := new(saferith.Nat).SetBig(pInt, 128)
	qInt, err := crand.Prime(prng, 128)
	require.NoError(t, err)
	q := new(saferith.Nat).SetBig(qInt, 128)
	bigN := new(saferith.Nat).Mul(p, q, 256)
	bigNSquared := saferith.ModulusFromNat(new(saferith.Nat).Mul(bigN, bigN, 512))

	yInt, err := crand.Int(prng, bigN.Big())
	require.NoError(t, err)
	y := new(saferith.Nat).SetBig(yInt, 256)
	x := new(saferith.Nat).Exp(y, bigN, bigNSquared)

	err = doProof(x, y, bigN, prng)
	require.NoError(t, err)
}

func Test_InvalidRoot(t *testing.T) {
	prng := crand.Reader
	pInt, err := crand.Prime(prng, 128)
	require.NoError(t, err)
	p := new(saferith.Nat).SetBig(pInt, 128)
	qInt, err := crand.Prime(prng, 128)
	require.NoError(t, err)
	q := new(saferith.Nat).SetBig(qInt, 128)
	bigN := new(saferith.Nat).Mul(p, q, 256)
	bigNSquared := saferith.ModulusFromNat(new(saferith.Nat).Mul(bigN, bigN, 512))

	y1Int, err := crand.Int(prng, bigN.Big())
	require.NoError(t, err)
	y1 := new(saferith.Nat).SetBig(y1Int, 256)
	x1 := new(saferith.Nat).Exp(y1, bigN, bigNSquared)

	y2Int, err := crand.Int(prng, bigN.Big())
	require.NoError(t, err)
	y2 := new(saferith.Nat).SetBig(y2Int, 256)
	x2 := new(saferith.Nat).Exp(y2, bigN, bigNSquared)

	err = doProof(x1, y2, bigN, prng)
	require.Error(t, err)
	require.True(t, errs.IsVerification(err))

	err = doProof(x2, y1, bigN, prng)
	require.Error(t, err)
	require.True(t, errs.IsVerification(err))
}
