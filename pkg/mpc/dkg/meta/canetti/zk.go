package canetti

import (
	"crypto/sha3"
	"io"
	"slices"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

const zkDomainSeparator = "BRON_CRYPTO_DKG_CANETTI_ZK"

type ZKResponse[A sigma.Commitment, Z sigma.Response] struct {
	A A
	E sigma.ChallengeBytes
	Z Z
}

func zkCom[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response](protocol sigma.Protocol[X, W, A, S, Z], statement X, witness W) (commitment A, state S, err error) {
	var nilA A
	var nilS S
	if protocol == nil {
		return nilA, nilS, ErrInvalidArgument.WithMessage("protocol is nil")
	}

	a, s, err := protocol.ComputeProverCommitment(statement, witness)
	if err != nil {
		return nilA, nilS, errs.Wrap(err).WithMessage("cannot commit")
	}
	return a, s, nil
}

func zkProve[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response](protocol sigma.Protocol[X, W, A, S, Z], statement X, witness W, commitment A, state S, aux base.BytesLike) (*ZKResponse[A, Z], error) {
	h := sha3.NewCSHAKE256(nil, []byte(zkDomainSeparator))
	auxBytes := aux.Bytes()
	xBytes := statement.Bytes()
	aBytes := commitment.Bytes()
	_, err := h.Write(sliceutils.AppendLengthPrefixedSlices(auxBytes, xBytes, aBytes))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot write to hasher")
	}
	e := make([]byte, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(h, e)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot sample challenge")
	}

	z, err := protocol.ComputeProverResponse(statement, witness, commitment, state, e)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot prove")
	}

	psi := &ZKResponse[A, Z]{
		A: commitment,
		E: e,
		Z: z,
	}
	return psi, nil
}

func zkVrfy[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response](protocol sigma.Protocol[X, W, A, S, Z], statement X, aux base.BytesLike, response *ZKResponse[A, Z]) error {
	h := sha3.NewCSHAKE256(nil, []byte(zkDomainSeparator))
	auxBytes := aux.Bytes()
	xBytes := statement.Bytes()
	aBytes := response.A.Bytes()
	_, err := h.Write(sliceutils.AppendLengthPrefixedSlices(auxBytes, xBytes, aBytes))
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot write to hasher")
	}
	ePrime := make([]byte, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(h, ePrime)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot sample challenge")
	}
	if !slices.Equal(ePrime, response.E) {
		return ErrVerificationFailed.WithMessage("invalid proof")
	}
	if err := protocol.Verify(statement, response.A, ePrime, response.Z); err != nil {
		return ErrVerificationFailed.WithMessage("invalid proof")
	}

	return nil
}
