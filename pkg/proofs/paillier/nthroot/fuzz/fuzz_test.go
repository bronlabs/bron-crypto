package fuzz

import (
	"bytes"
	crand "crypto/rand"
	"math/rand"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton/pkg/base/errs"
	"github.com/copperexchange/krypton/pkg/proofs/paillier/nthroot"
	"github.com/copperexchange/krypton/pkg/transcripts/hagrid"
)

func Fuzz_Test(f *testing.F) {
	f.Add([]byte("sid"), int64(0))
	f.Fuzz(func(t *testing.T, sid []byte, randomSeed int64) {
		prng := rand.New(rand.NewSource(randomSeed))

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

		appLabel := "NthRoot"
		proverTranscript := hagrid.NewTranscript(appLabel, nil)
		prover, err := nthroot.NewProver(bigN, x, y, sid, proverTranscript, prng)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip()
		}
		verifierTranscript := hagrid.NewTranscript(appLabel, nil)
		verifier, err := nthroot.NewVerifier(bigN, x, sid, verifierTranscript, prng)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip()
		}

		r1, err := prover.Round1()
		require.NoError(t, err)
		r2, err := verifier.Round2(r1)
		require.NoError(t, err)
		r3, err := prover.Round3(r2)
		require.NoError(t, err)

		err = verifier.Round4(r3)
		require.NoError(t, err)

		label := "gimme, gimme"
		proverBytes, _ := proverTranscript.ExtractBytes(label, 128)
		verifierBytes, _ := verifierTranscript.ExtractBytes(label, 128)
		if !bytes.Equal(proverBytes, verifierBytes) {
			t.Fail()
		}
	})
}
