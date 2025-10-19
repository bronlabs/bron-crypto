package pailliern_test

import (
	crand "crypto/rand"
	"fmt"
	"math/big"
	"slices"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/paillier/pailliern"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
)

func Test_pIsCorrect(t *testing.T) {
	t.Parallel()

	pCheck := numct.NatOne()
	for i := uint64(2); i < pailliern.Alpha; i++ {
		if isPrime(i) {
			// TODO: either remove capacity or fix the type of announced len
			pCheck.MulCap(pCheck, numct.NewNat(i), int(pailliern.P.AnnouncedLen()))
		}
	}

	eq := pCheck.Equal(pailliern.P)
	require.Equal(t, ct.True, eq)
}

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	label := "NizkPaillierNTranscriptLabel"
	sessionId := "NizkPaillierNTestSessionId"

	proverTranscript := hagrid.NewTranscript(label)
	verifierTranscript := hagrid.NewTranscript(label)

	scheme := paillier.NewScheme()

	for i := 0; i < 32; i++ {
		sid, err := network.NewSID([]byte(fmt.Sprintf("%s_%d", sessionId, i)))
		require.NoError(t, err)

		pInt, err := crand.Prime(prng, 512)
		require.NoError(t, err)
		pNat := numct.NewNatFromSaferith(new(saferith.Nat).SetBig(pInt, 512))
		qInt, err := crand.Prime(prng, 512)
		require.NoError(t, err)
		qNat := numct.NewNatFromSaferith(new(saferith.Nat).SetBig(qInt, 512))

		p, err := num.NPlus().FromNatCT(pNat)
		require.NoError(t, err)
		q, err := num.NPlus().FromNatCT(qNat)
		require.NoError(t, err)

		group, err := znstar.NewPaillierGroup(p, q)
		require.NoError(t, err)

		sk, err := paillier.NewPrivateKey(group)
		require.NoError(t, err)

		senc, err := scheme.SelfEncrypter(sk)
		require.NoError(t, err)

		prover, err := pailliern.NewProver(sid, senc, proverTranscript)
		require.NoError(t, err)

		proof, _, err := prover.Prove()
		require.NoError(t, err)
		require.NotNil(t, proof)

		err = pailliern.Verify(sid, verifierTranscript, sk.PublicKey(), proof)
		require.NoError(t, err)
	}

	proverBytes, err := proverTranscript.ExtractBytes("test", 16)
	require.NoError(t, err)
	verifierBytes, err := verifierTranscript.ExtractBytes("test", 16)
	require.NoError(t, err)

	require.True(t, slices.Equal(proverBytes, verifierBytes))
}

func isPrime(x uint64) bool {
	return big.NewInt(int64(x)).ProbablyPrime(32)
}
