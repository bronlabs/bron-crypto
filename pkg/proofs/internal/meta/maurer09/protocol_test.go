package maurer09_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/proofs"
	"github.com/bronlabs/bron-crypto/pkg/proofs/internal/meta/maurer09"
)

func TestCommitmentUnmarshalCBOR(t *testing.T) {
	t.Parallel()

	valid := &maurer09.Commitment[*k256.Point]{A: k256.NewCurve().Generator()}
	data, err := serde.MarshalCBOR(valid)
	require.NoError(t, err)

	decoded, err := serde.UnmarshalCBOR[*maurer09.Commitment[*k256.Point]](data)
	require.NoError(t, err)
	require.True(t, valid.A.Equal(decoded.A))

	assertRejectsMalformedCommitment(t, []byte{0xf6})
	assertRejectsMalformedCommitment(t, []byte{0xf7})
	assertRejectsMalformedCommitment(t, []byte{0xa0})

	data, err = serde.MarshalCBOR(map[string]any{"a": nil})
	require.NoError(t, err)
	assertRejectsMalformedCommitment(t, data)
}

func TestResponseUnmarshalCBOR(t *testing.T) {
	t.Parallel()

	valid := &maurer09.Response[*k256.Scalar]{Z: k256.NewScalarField().One()}
	data, err := serde.MarshalCBOR(valid)
	require.NoError(t, err)

	decoded, err := serde.UnmarshalCBOR[*maurer09.Response[*k256.Scalar]](data)
	require.NoError(t, err)
	require.True(t, valid.Z.Equal(decoded.Z))

	assertRejectsMalformedResponse(t, []byte{0xf6})
	assertRejectsMalformedResponse(t, []byte{0xf7})
	assertRejectsMalformedResponse(t, []byte{0xa0})

	data, err = serde.MarshalCBOR(map[string]any{"z": nil})
	require.NoError(t, err)
	assertRejectsMalformedResponse(t, data)
}

func assertRejectsMalformedCommitment(t *testing.T, data []byte) {
	t.Helper()

	var commitment maurer09.Commitment[*k256.Point]
	err := commitment.UnmarshalCBOR(data)
	require.True(t, errs.Is(err, proofs.ErrInvalidArgument), "unexpected error: %+v", err)
}

func assertRejectsMalformedResponse(t *testing.T, data []byte) {
	t.Helper()

	var response maurer09.Response[*k256.Scalar]
	err := response.UnmarshalCBOR(data)
	require.True(t, errs.Is(err, proofs.ErrInvalidArgument), "unexpected error: %+v", err)
}
