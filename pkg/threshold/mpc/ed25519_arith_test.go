package mpc_test

import (
	crand "crypto/rand"
	"encoding/binary"
	"io"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/network"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/mpc"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/binrep3"
	"github.com/stretchr/testify/require"
)

type TestEd25519AddOutput struct {
	XSeed [4]*mpc.Value64
	X     [4]*mpc.Value64
	YSeed [4]*mpc.Value64
	Y     [4]*mpc.Value64
	Z     [4]*mpc.Value64
}

var _ network.Runner[*TestEd25519AddOutput] = (*TestEd25519AddRunner)(nil)

type TestEd25519AddRunner struct {
	sid    network.SID
	id     sharing.ID
	quorum network.Quorum
	prng   io.Reader
}

func NewTestEd25519AddRunner(sid network.SID, id sharing.ID, quorum network.Quorum, prng io.Reader) *TestEd25519AddRunner {
	return &TestEd25519AddRunner{sid, id, quorum, prng}
}

func (r *TestEd25519AddRunner) Run(rt *network.Router) (*TestEd25519AddOutput, error) {
	arith, err := mpc.NewArithmetic(rt, r.sid, "aaa", r.id, r.quorum, r.prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create arithmetic")
	}

	xSeed := [4]*mpc.Value64{
		arith.RandomSecret(),
		arith.RandomSecret(),
		arith.RandomSecret(),
		arith.RandomSecret(),
	}
	ySeed := [4]*mpc.Value64{
		arith.RandomSecret(),
		arith.RandomSecret(),
		arith.RandomSecret(),
		arith.RandomSecret(),
	}

	ed25519Arith := mpc.NewEd25519Arithmetic(arith)
	x := ed25519Arith.U256ReduceToScalar(xSeed)
	y := ed25519Arith.U256ReduceToScalar(ySeed)
	z := ed25519Arith.ScalarAdd(x, y)

	return &TestEd25519AddOutput{xSeed, x, ySeed, y, z}, nil
}

func TestEd25519Arithmetic_ScalarAdd(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	quorum := sharing.NewOrdinalShareholderSet(3)
	quorumList := quorum.List()

	for range 128 {
		var sid network.SID
		_, err := io.ReadFull(prng, sid[:])
		require.NoError(t, err)

		runners := map[sharing.ID]network.Runner[*TestEd25519AddOutput]{
			quorumList[0]: NewTestEd25519AddRunner(sid, quorumList[0], quorum, prng),
			quorumList[1]: NewTestEd25519AddRunner(sid, quorumList[1], quorum, prng),
			quorumList[2]: NewTestEd25519AddRunner(sid, quorumList[2], quorum, prng),
		}
		result := ntu.TestExecuteRunners(t, runners)

		dealer, err := binrep3.NewScheme(quorum)
		require.NoError(t, err)

		var xWideBytes, yWideBytes, xBytes, yBytes, zBytes []byte
		for i := range 4 {
			v, err := dealer.Reconstruct(result[quorumList[0]].XSeed[3-i].Secret(), result[quorumList[1]].XSeed[3-i].Secret(), result[quorumList[2]].XSeed[3-i].Secret())
			require.NoError(t, err)
			xWideBytes = binary.BigEndian.AppendUint64(xWideBytes, v)

			v, err = dealer.Reconstruct(result[quorumList[0]].YSeed[3-i].Secret(), result[quorumList[1]].YSeed[3-i].Secret(), result[quorumList[2]].YSeed[3-i].Secret())
			require.NoError(t, err)
			yWideBytes = binary.BigEndian.AppendUint64(yWideBytes, v)

			v, err = dealer.Reconstruct(result[quorumList[0]].X[3-i].Secret(), result[quorumList[1]].X[3-i].Secret(), result[quorumList[2]].X[3-i].Secret())
			require.NoError(t, err)
			xBytes = binary.BigEndian.AppendUint64(xBytes, v)

			v, err = dealer.Reconstruct(result[quorumList[0]].Y[3-i].Secret(), result[quorumList[1]].Y[3-i].Secret(), result[quorumList[2]].Y[3-i].Secret())
			require.NoError(t, err)
			yBytes = binary.BigEndian.AppendUint64(yBytes, v)

			v, err = dealer.Reconstruct(result[quorumList[0]].Z[3-i].Secret(), result[quorumList[1]].Z[3-i].Secret(), result[quorumList[2]].Z[3-i].Secret())
			require.NoError(t, err)
			zBytes = binary.BigEndian.AppendUint64(zBytes, v)
		}

		x, err := edwards25519.NewScalarField().FromWideBytes(xWideBytes)
		require.NoError(t, err)
		require.Equal(t, xBytes, x.Bytes())

		y, err := edwards25519.NewScalarField().FromWideBytes(yWideBytes)
		require.NoError(t, err)
		require.Equal(t, yBytes, y.Bytes())

		z := x.Add(y)
		require.Equal(t, zBytes, z.Bytes())
	}
}
