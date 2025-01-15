package paillierrange_test

import (
	"bytes"
	crand "crypto/rand"
	"math/rand"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/krypton-primitives/pkg/base"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/encryptions/paillier"
	paillierrange "github.com/bronlabs/krypton-primitives/pkg/proofs/paillier/range"
	"github.com/bronlabs/krypton-primitives/pkg/transcripts/hagrid"
)

func Fuzz_Test(f *testing.F) {
	f.Add([]byte("sid"), int64(0), uint64(3_000_000))
	f.Fuzz(func(t *testing.T, sid []byte, randomSeed int64, qNum uint64) {
		prng := rand.New(rand.NewSource(randomSeed))

		pk, sk, err := paillier.KeyGen(base.ComputationalSecurity, crand.Reader)
		require.NoError(t, err)
		q := new(saferith.Nat).SetUint64(qNum)
		l := new(saferith.Nat).Div(q, saferith.ModulusFromUint64(3), base.ComputationalSecurity)
		xInt, err := crand.Int(prng, l.Big())
		require.NoError(t, err)
		x := new(saferith.Nat).Add(l, new(saferith.Nat).SetBig(xInt, 256), 256)

		xEncrypted, r, err := pk.Encrypt(x, prng)
		require.NoError(t, err)

		appLabel := "Range"

		verifierTranscript := hagrid.NewTranscript(appLabel, nil)
		verifier, err := paillierrange.NewVerifier(base.ComputationalSecurity, q, pk, xEncrypted, sid, verifierTranscript, prng)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip(err.Error())
		}
		proverTranscript := hagrid.NewTranscript(appLabel, nil)
		prover, err := paillierrange.NewProver(base.ComputationalSecurity, q, sk, x, r, sid, proverTranscript, prng)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip(err.Error())
		}

		r1, err := verifier.Round1()
		require.NoError(t, err)
		r2, err := prover.Round2(r1)
		require.NoError(t, err)
		r3, err := verifier.Round3(r2)
		require.NoError(t, err)
		r4, err := prover.Round4(r3)
		require.NoError(t, err)
		err = verifier.Round5(r4)
		require.NoError(t, err)

		label := "gimme, gimme"
		proverBytes, _ := proverTranscript.ExtractBytes(label, base.ComputationalSecurity)
		verifierBytes, _ := verifierTranscript.ExtractBytes(label, base.ComputationalSecurity)
		if !bytes.Equal(proverBytes, verifierBytes) {
			t.Fail()
		}
	})
}
