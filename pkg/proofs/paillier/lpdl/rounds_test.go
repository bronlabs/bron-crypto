package lpdl_test

// import (
// 	"bytes"
// 	crand "crypto/rand"
// 	"io"
// 	"testing"

// 	"github.com/cronokirby/saferith"
// 	"github.com/stretchr/testify/require"

// 	"github.com/bronlabs/bron-crypto/pkg/base/curves"
// 	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
// 	"github.com/bronlabs/bron-crypto/pkg/base/errs"
// 	"github.com/bronlabs/bron-crypto/pkg/indcpa/paillier"
// 	"github.com/bronlabs/bron-crypto/pkg/proofs/paillier/lpdl"
// 	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
// )

// func Test_HappyPath(t *testing.T) {
// 	t.Parallel()
// 	if testing.Short() {
// 		t.Skip("Skipping test in short mode")
// 	}

// 	pk, sk, err := paillier.KeyGen(2048, crand.Reader)
// 	require.NoError(t, err)
// 	prng := crand.Reader
// 	curve := p256.NewCurve()
// 	q := curve.SubGroupOrder()

// 	xNat, err := randomIntInRange(q.Nat(), prng)
// 	require.NoError(t, err)

// 	x := curve.Scalar().SetNat(xNat)

// 	bigQ := curve.ScalarBaseMult(x)
// 	xEncrypted, r, err := pk.Encrypt(new(saferith.Int).SetNat(xNat), prng)
// 	require.NoError(t, err)

// 	sid := []byte("sessionId")
// 	err = doProof(x, bigQ, xEncrypted, r, pk, sk, sid, prng)
// 	require.NoError(t, err)
// }

// // xEncrypted is not a dlog of Q
// func Test_FailVerificationOnFalseClaim(t *testing.T) {
// 	t.Parallel()
// 	if testing.Short() {
// 		t.Skip("Skipping test in short mode")
// 	}

// 	pk, sk, err := paillier.KeyGen(1024, crand.Reader)
// 	require.NoError(t, err)
// 	prng := crand.Reader
// 	curve := p256.NewCurve()
// 	q := curve.SubGroupOrder()

// 	x1Nat, err := randomIntInRange(q.Nat(), prng)
// 	require.NoError(t, err)
// 	x1 := curve.Scalar().SetNat(x1Nat)

// 	x2Nat, err := randomIntInRange(q.Nat(), prng)
// 	require.NoError(t, err)
// 	x2 := curve.Scalar().SetNat(x2Nat)

// 	bigQ2 := curve.ScalarBaseMult(x2)
// 	x1Encrypted, r, err := pk.Encrypt(new(saferith.Int).SetNat(x1Nat), prng)
// 	require.NoError(t, err)

// 	sid := []byte("sessionId")
// 	err = doProof(x1, bigQ2, x1Encrypted, r, pk, sk, sid, prng)
// 	require.Error(t, err)
// }

// // xEncrypted is not encryption of x
// func Test_FailVerificationOnIncorrectDlog(t *testing.T) {
// 	t.Parallel()
// 	if testing.Short() {
// 		t.Skip("Skipping test in short mode")
// 	}

// 	pk, sk, err := paillier.KeyGen(1024, crand.Reader)
// 	require.NoError(t, err)
// 	prng := crand.Reader
// 	curve := p256.NewCurve()
// 	q := curve.SubGroupOrder()

// 	xNat, err := randomIntInRange(q.Nat(), prng)
// 	require.NoError(t, err)
// 	x := curve.Scalar().SetNat(xNat)
// 	require.NoError(t, err)
// 	bigQ := curve.ScalarBaseMult(x)

// 	x2Int, err := curve.ScalarField().Random(prng)
// 	require.NoError(t, err)
// 	x2IntNat := x2Int.Nat()
// 	x2Encrypted, r, err := pk.Encrypt(new(saferith.Int).SetNat(x2IntNat), prng)
// 	require.NoError(t, err)

// 	sid := []byte("sessionId")
// 	err = doProof(x, bigQ, x2Encrypted, r, pk, sk, sid, prng)
// 	require.Error(t, err)
// }

// func randomIntInRange(q *saferith.Nat, prng io.Reader) (*saferith.Nat, error) {
// 	l := new(saferith.Nat).Div(q, saferith.ModulusFromUint64(3), 2048)
// 	xInt, err := crand.Int(prng, l.Big())
// 	if err != nil {
// 		return nil, errs.WrapRandomSample(err, "cannot sample integer")
// 	}
// 	x := new(saferith.Nat).SetBig(xInt, 2048)
// 	return new(saferith.Nat).Add(l, x, 2048), nil
// }

// func doProof(x curves.Scalar, bigQ curves.Point, xEncrypted *paillier.CipherText, r *saferith.Nat, pk *paillier.PublicKey, sk *paillier.SecretKey, sessionId []byte, prng io.Reader) (err error) {
// 	transcriptLabel := "LPDL"

// 	verifierTranscript := hagrid.NewTranscript(transcriptLabel, nil)
// 	verifier, err := lpdl.NewVerifier(pk, bigQ, xEncrypted, sessionId, verifierTranscript, prng)
// 	if err != nil {
// 		return err
// 	}

// 	proverTranscript := hagrid.NewTranscript(transcriptLabel, nil)
// 	prover, err := lpdl.NewProver(sk, x, r, sessionId, proverTranscript, prng)
// 	if err != nil {
// 		return err
// 	}

// 	r1, err := verifier.Round1()
// 	if err != nil {
// 		return err
// 	}

// 	r2, err := prover.Round2(r1)
// 	if err != nil {
// 		return err
// 	}

// 	r3, err := verifier.Round3(r2)
// 	if err != nil {
// 		return err
// 	}

// 	r4, err := prover.Round4(r3)
// 	if err != nil {
// 		return err
// 	}

// 	err = verifier.Round5(r4)
// 	if err != nil {
// 		return err
// 	}

// 	label := "gimme, gimme"
// 	proverBytes, err := proverTranscript.ExtractBytes(label, 128)
// 	if err != nil {
// 		return err
// 	}
// 	verifierBytes, err := verifierTranscript.ExtractBytes(label, 128)
// 	if err != nil {
// 		return err
// 	}
// 	if !bytes.Equal(proverBytes, verifierBytes) {
// 		return errs.NewFailed("transcript record different data")
// 	}

// 	return nil
// }
