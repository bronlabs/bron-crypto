package pailliern_test

// import (
// 	crand "crypto/rand"
// 	"fmt"
// 	"math/big"
// 	"slices"
// 	"testing"

// 	"github.com/cronokirby/saferith"
// 	"github.com/stretchr/testify/require"

// 	saferithUtils "github.com/bronlabs/bron-crypto/pkg/base/utils/saferith"
// 	"github.com/bronlabs/bron-crypto/pkg/indcpa/paillier"
// 	"github.com/bronlabs/bron-crypto/pkg/proofs/paillier/pailliern"
// 	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
// )

// func Test_pIsCorrect(t *testing.T) {
// 	t.Parallel()

// 	pCheck := saferithUtils.NatOne
// 	for i := 2; i < pailliern.Alpha; i++ {
// 		if isPrime(i) {
// 			pCheck = new(saferith.Nat).Mul(pCheck, new(saferith.Nat).SetUint64(uint64(i)), pailliern.P.AnnouncedLen())
// 		}
// 	}

// 	eq := pCheck.Eq(pailliern.P)
// 	require.Equal(t, eq, saferith.Choice(1))
// }

// func Test_HappyPath(t *testing.T) {
// 	t.Parallel()

// 	prng := crand.Reader
// 	label := "NizkPaillierNTranscriptLabel"
// 	sessionId := "NizkPaillierNTestSessionId"

// 	proverTranscript := hagrid.NewTranscript(label, nil)
// 	verifierTranscript := hagrid.NewTranscript(label, nil)

// 	for i := 0; i < 32; i++ {
// 		sid := fmt.Sprintf("%s_%d", sessionId, i)

// 		pInt, err := crand.Prime(prng, 512)
// 		require.NoError(t, err)
// 		p := new(saferith.Nat).SetBig(pInt, 512)
// 		qInt, err := crand.Prime(prng, 512)
// 		require.NoError(t, err)
// 		q := new(saferith.Nat).SetBig(qInt, 512)

// 		sk, err := paillier.NewSecretKey(p, q)
// 		require.NoError(t, err)

// 		prover, err := pailliern.NewProver([]byte(sid), proverTranscript)
// 		require.NoError(t, err)

// 		proof, _, err := prover.Prove(sk)
// 		require.NoError(t, err)
// 		require.NotNil(t, proof)

// 		err = pailliern.Verify([]byte(sid), verifierTranscript, &sk.PublicKey, proof)
// 		require.NoError(t, err)
// 	}

// 	proverBytes, err := proverTranscript.ExtractBytes("test", 16)
// 	require.NoError(t, err)
// 	verifierBytes, err := verifierTranscript.ExtractBytes("test", 16)
// 	require.NoError(t, err)

// 	require.True(t, slices.Equal(proverBytes, verifierBytes))
// }

// func isPrime(x int) bool {
// 	return big.NewInt(int64(x)).ProbablyPrime(32)
// }
