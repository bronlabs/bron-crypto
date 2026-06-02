package zkmodule

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/proofs"
	"github.com/bronlabs/bron-crypto/pkg/proofs/dlog/schnorr"
)

type (
	testCommitment = *schnorr.Commitment[*k256.Point, *k256.Scalar]
	testResponse   = *schnorr.Response[*k256.Scalar]
)

// validProof builds a genuine proof so its fields can seed the malformed DTOs
// below; reusing real (a, e, z) values isolates each test to the single field
// it nullifies.
func validProof(tb testing.TB) *Proof[testCommitment, testResponse] {
	tb.Helper()

	prng := pcg.NewRandomised()
	curve := k256.NewCurve()

	protocol, err := schnorr.NewProtocol(curve.Generator(), prng)
	require.NoError(tb, err)

	witnessValue, err := curve.ScalarField().Random(prng)
	require.NoError(tb, err)
	witness := schnorr.NewWitness(witnessValue)
	statement := schnorr.NewStatement(curve.ScalarBaseMul(witnessValue))

	quorum := hashset.NewComparable[sharing.ID](1, 2).Freeze()
	ctxs := session_testutils.MakeRandomContexts(tb, quorum, prng)
	var ctx *session.Context = ctxs[1]

	commitment, state, err := Commit(protocol, statement, witness)
	require.NoError(tb, err)
	proof, err := Prove(ctx, protocol, statement, witness, commitment, state)
	require.NoError(tb, err)
	return proof
}

// TestUnmarshalCBOR_RejectsMalformed checks the deserialisation trust boundary:
// a proof that decodes structurally but is missing a cryptographic component
// (commitment, challenge, or response) must be rejected with ErrInvalidArgument
// rather than silently produce an unverifiable Proof.
func TestUnmarshalCBOR_RejectsMalformed(t *testing.T) {
	t.Parallel()

	good := validProof(t)

	t.Run("nil commitment", func(t *testing.T) {
		t.Parallel()
		data, err := serde.MarshalCBOR(&proofDTO[testCommitment, testResponse]{A: nil, E: good.e, Z: good.z})
		require.NoError(t, err)

		var p Proof[testCommitment, testResponse]
		err = p.UnmarshalCBOR(data)
		require.True(t, errs.Is(err, proofs.ErrInvalidArgument))
	})

	t.Run("empty challenge", func(t *testing.T) {
		t.Parallel()
		data, err := serde.MarshalCBOR(&proofDTO[testCommitment, testResponse]{A: good.a, E: nil, Z: good.z})
		require.NoError(t, err)

		var p Proof[testCommitment, testResponse]
		err = p.UnmarshalCBOR(data)
		require.True(t, errs.Is(err, proofs.ErrInvalidArgument))
	})

	t.Run("nil response", func(t *testing.T) {
		t.Parallel()
		data, err := serde.MarshalCBOR(&proofDTO[testCommitment, testResponse]{A: good.a, E: good.e, Z: nil})
		require.NoError(t, err)

		var p Proof[testCommitment, testResponse]
		err = p.UnmarshalCBOR(data)
		require.True(t, errs.Is(err, proofs.ErrInvalidArgument))
	})

	t.Run("garbage bytes", func(t *testing.T) {
		t.Parallel()
		var p Proof[testCommitment, testResponse]
		err := p.UnmarshalCBOR([]byte{0xff, 0x00, 0x13, 0x37})
		require.Error(t, err)
	})

	t.Run("well-formed round trip", func(t *testing.T) {
		t.Parallel()
		data, err := serde.MarshalCBOR(&proofDTO[testCommitment, testResponse]{A: good.a, E: good.e, Z: good.z})
		require.NoError(t, err)

		var p Proof[testCommitment, testResponse]
		require.NoError(t, p.UnmarshalCBOR(data))
		require.Equal(t, good.a.Bytes(), p.a.Bytes())
		require.Equal(t, good.e, p.e)
		require.Equal(t, good.z.Bytes(), p.z.Bytes())
	})
}
