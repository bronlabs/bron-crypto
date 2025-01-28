package commitments

import "github.com/bronlabs/krypton-primitives/pkg/base/errs"

type Opening[M Message, W Witness] struct {
	message M
	witness W
}

func NewOpening[M Message, W Witness](message M, witness W) *Opening[M, W] {
	return &Opening[M, W]{
		message: message,
		witness: witness,
	}
}

func (o *Opening[M, W]) Message() M {
	return o.message
}

func (o *Opening[M, W]) Witness() W {
	return o.witness
}

func OpeningAdd[C Commitment, M Message, W Witness, S Scalar, CK HomomorphicCommittingKey[C, M, W, S]](ck CK, lhs, rhs *Opening[M, W]) (*Opening[M, W], error) {
	m, err := ck.MessageAdd(lhs.Message(), rhs.Message())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot add messages")
	}
	r, err := ck.WitnessAdd(lhs.Witness(), rhs.Witness())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot add witnesses")
	}

	return NewOpening[M, W](m, r), nil
}

func OpeningAddMessage[C Commitment, M Message, W Witness, S Scalar, CK HomomorphicCommittingKey[C, M, W, S]](ck CK, lhs *Opening[M, W], rhs M) (*Opening[M, W], error) {
	m, err := ck.MessageAdd(lhs.Message(), rhs)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot add messages")
	}

	return NewOpening[M, W](m, lhs.Witness()), nil
}

func OpeningSub[C Commitment, M Message, W Witness, S Scalar, CK HomomorphicCommittingKey[C, M, W, S]](ck CK, lhs, rhs *Opening[M, W]) (*Opening[M, W], error) {
	m, err := ck.MessageSub(lhs.Message(), rhs.Message())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot add messages")
	}
	r, err := ck.WitnessSub(lhs.Witness(), rhs.Witness())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot add witnesses")
	}

	return NewOpening[M, W](m, r), nil
}

func OpeningSubMessage[C Commitment, M Message, W Witness, S Scalar, CK HomomorphicCommittingKey[C, M, W, S]](ck CK, lhs *Opening[M, W], rhs M) (*Opening[M, W], error) {
	m, err := ck.MessageSub(lhs.Message(), rhs)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot add messages")
	}

	return NewOpening[M, W](m, lhs.Witness()), nil
}

func OpeningMul[C Commitment, M Message, W Witness, S Scalar, CK HomomorphicCommittingKey[C, M, W, S]](ck CK, lhs *Opening[M, W], rhs S) (*Opening[M, W], error) {
	m, err := ck.MessageMul(lhs.Message(), rhs)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot add messages")
	}
	r, err := ck.WitnessMul(lhs.Witness(), rhs)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot add witnesses")
	}

	return NewOpening[M, W](m, r), nil
}

func OpeningNeg[C Commitment, M Message, W Witness, S Scalar, CK HomomorphicCommittingKey[C, M, W, S]](ck CK, x *Opening[M, W]) (*Opening[M, W], error) {
	m, err := ck.MessageNeg(x.Message())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot add messages")
	}
	r, err := ck.WitnessNeg(x.Witness())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot add witnesses")
	}

	return NewOpening[M, W](m, r), nil
}

func Verify[C Commitment, M Message, W Witness, CK CommittingKey[C, M, W]](committingKey CK, commitment C, opening *Opening[M, W]) error {
	err := committingKey.Verify(commitment, opening.Message(), opening.Witness())
	if err != nil {
		return errs.WrapVerification(err, "invalid commitment")
	}

	return nil
}
