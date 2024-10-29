package intpedersen_comm_test

import (
	crand "crypto/rand"
	"io"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	intpedersen_comm "github.com/copperexchange/krypton-primitives/pkg/commitments/intpedersen"
)

func Test_ValidCommitment(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	ck := randomCk(t, prng)
	m := randomMessage(t, prng)

	c, r, err := ck.Commit(m, prng)
	require.NoError(t, err)

	err = ck.Verify(c, m, r)
	require.NoError(t, err)

}

func Test_InvalidCommitment(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	ck := randomCk(t, prng)
	m := randomMessage(t, prng)
	invalidCk := randomCk(t, prng)
	invalidM := randomMessage(t, prng)

	c, r, err := ck.Commit(m, prng)
	require.NoError(t, err)

	err = ck.Verify(c, m, r)
	require.NoError(t, err)

	invalidC, invalidR, err := invalidCk.Commit(invalidM, prng)
	require.NoError(t, err)

	err = invalidCk.Verify(c, m, r)
	require.Error(t, err)
	err = ck.Verify(invalidC, m, r)
	require.Error(t, err)
	err = ck.Verify(c, invalidM, r)
	require.Error(t, err)

	err = ck.Verify(c, m, invalidR)
	require.Error(t, err)
	err = ck.Verify(c, invalidM, invalidR)
	require.Error(t, err)
}

func Test_InvalidMessageOutOfBound(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	ck := randomCk(t, prng)
	m := randomMessageOutOfBound(t, prng)

	c, r, err := ck.Commit(m, prng)
	require.NoError(t, err)

	err = ck.Verify(c, m, r)
	require.Error(t, err)
}

func Test_HomomorphicAdd(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	ck := randomCk(t, prng)
	m1 := randomMessage(t, prng)
	m2 := randomMessage(t, prng)
	m := new(saferith.Int).Add(m1, m2, -1)

	c1, r1, err := ck.Commit(m1, prng)
	require.NoError(t, err)
	c2, r2, err := ck.Commit(m2, prng)
	require.NoError(t, err)

	c, err := ck.CommitmentAdd(c1, c2)
	require.NoError(t, err)
	r, err := ck.WitnessAdd(r1, r2)
	require.NoError(t, err)

	err = ck.Verify(c, m, r)
	require.NoError(t, err)

}

func Test_HomomorphicAddMessage(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	ck := randomCk(t, prng)
	m1 := randomMessage(t, prng)
	m2 := randomMessage(t, prng)
	m := new(saferith.Int).Add(m1, m2, -1)

	c1, r, err := ck.Commit(m1, prng)
	require.NoError(t, err)

	c, err := ck.CommitmentAddMessage(c1, m2)
	require.NoError(t, err)

	err = ck.Verify(c, m, r)
	require.NoError(t, err)
}

func Test_HomomorphicSub(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	ck := randomCk(t, prng)
	m1 := randomMessage(t, prng)
	m2 := randomMessage(t, prng)
	m := new(saferith.Int).Add(m1, m2.Clone().Neg(1), -1)

	c1, r1, err := ck.Commit(m1, prng)
	require.NoError(t, err)
	c2, r2, err := ck.Commit(m2, prng)
	require.NoError(t, err)

	c, err := ck.CommitmentSub(c1, c2)
	require.NoError(t, err)
	r, err := ck.WitnessSub(r1, r2)
	require.NoError(t, err)

	err = ck.Verify(c, m, r)
	require.NoError(t, err)

}

func Test_HomomorphicSubMessage(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	ck := randomCk(t, prng)
	m1 := randomMessage(t, prng)
	m2 := randomMessage(t, prng)
	m := new(saferith.Int).Add(m1, m2.Clone().Neg(1), -1)

	c1, r, err := ck.Commit(m1, prng)
	require.NoError(t, err)

	c, err := ck.CommitmentSubMessage(c1, m2)
	require.NoError(t, err)

	err = ck.Verify(c, m, r)
	require.NoError(t, err)

}

func Test_HomomorphicMul(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	ck := randomCk(t, prng)
	m1 := randomMessage(t, prng)
	m2 := randomMessage(t, prng)
	m := new(saferith.Int).Mul(m1, m2, -1)

	c1, r1, err := ck.Commit(m1, prng)
	require.NoError(t, err)

	c, err := ck.CommitmentMul(c1, m2)
	require.NoError(t, err)
	r, err := ck.WitnessMul(r1, m2)
	require.NoError(t, err)

	err = ck.Verify(c, m, r)
	require.NoError(t, err)

}

func Test_HomomorphicNeg(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	ck := randomCk(t, prng)
	m1 := randomMessage(t, prng)
	m := m1.Clone().Neg(1)

	c1, r1, err := ck.Commit(m1, prng)
	require.NoError(t, err)

	c, err := ck.CommitmentNeg(c1)
	require.NoError(t, err)
	r, err := ck.WitnessNeg(r1)
	require.NoError(t, err)

	err = ck.Verify(c, m, r)
	require.NoError(t, err)
}

// 1536-bit MODP Group from RFC3526
var p, _ = saferith.ModulusFromHex(
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
		"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
		"83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
		"670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF")

func randomCk(tb testing.TB, prng io.Reader) *intpedersen_comm.CommittingKey {
	tb.Helper()

	gBig, err := crand.Int(prng, p.Big())
	require.NoError(tb, err)

	g := new(saferith.Nat).SetBig(gBig, p.BitLen())
	g.ModMul(g, g, p) // make sure it's QR

	hBig, err := crand.Int(prng, p.Big())
	require.NoError(tb, err)

	h := new(saferith.Nat).SetBig(hBig, p.BitLen())
	h.ModMul(h, h, p) // make sure it's QR (as it is g)
	return intpedersen_comm.NewCommittingKey(g, h, p)
}

func randomMessage(tb testing.TB, prng io.Reader) *intpedersen_comm.Message {
	tb.Helper()

	var mBytes [256/8 + 1]byte // extra byte for sign
	_, err := io.ReadFull(prng, mBytes[:])
	require.NoError(tb, err)

	m := new(saferith.Int)
	err = m.UnmarshalBinary(mBytes[:])
	require.NoError(tb, err)

	return m
}

func randomMessageOutOfBound(tb testing.TB, prng io.Reader) *intpedersen_comm.Message {
	tb.Helper()

	var mBytes [2048/8 + 1]byte // extra byte for sign
	_, err := io.ReadFull(prng, mBytes[:])
	require.NoError(tb, err)

	m := new(saferith.Int)
	err = m.UnmarshalBinary(mBytes[:])
	require.NoError(tb, err)

	return m
}
