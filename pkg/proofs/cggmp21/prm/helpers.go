package prm

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
)

func validateStatement(statement *Statement) error {
	if statement == nil || statement.CommitmentKey == nil {
		return ErrInvalidArgument.WithMessage("commitment key must not be nil")
	}
	s := statement.CommitmentKey.S()
	t := statement.CommitmentKey.T()
	if s == nil || t == nil {
		return ErrInvalidArgument.WithMessage("s and t must not be nil")
	}
	group := s.Group()
	if !group.Contains(t) {
		return ErrValidationFailed.WithMessage("s and t must belong to the same RSA group")
	}
	if s.Equal(t) {
		return ErrValidationFailed.WithMessage("s and t must be distinct")
	}
	if s.IsOne() || t.IsOne() {
		return ErrValidationFailed.WithMessage("s and t must not be the identity")
	}
	if !s.IsTorsionFree() || !t.IsTorsionFree() {
		return ErrValidationFailed.WithMessage("s and t must be torsion-free")
	}
	if !s.Value().Decrement().Nat().Coprime(s.Modulus().Nat()) {
		return ErrValidationFailed.WithMessage("s cannot be a generator of QR(N)")
	}
	if !t.Value().Decrement().Nat().Coprime(t.Modulus().Nat()) {
		return ErrValidationFailed.WithMessage("t cannot be a generator of QR(N)")
	}
	return nil
}

func validateWitness(statement *Statement, witness *Witness) error {
	if witness == nil || witness.TrapdoorKey == nil {
		return ErrInvalidArgument.WithMessage("trapdoor key must not be nil")
	}
	if witness.TrapdoorKey.Group() == nil {
		return ErrInvalidArgument.WithMessage("trapdoor group must not be nil")
	}
	if witness.TrapdoorKey.Lambda() == nil {
		return ErrInvalidArgument.WithMessage("lambda must not be nil")
	}
	if witness.TrapdoorKey.S() == nil || witness.TrapdoorKey.T() == nil {
		return ErrInvalidArgument.WithMessage("trapdoor public parameters must not be nil")
	}
	if !witness.TrapdoorKey.S().Equal(statement.CommitmentKey.S()) ||
		!witness.TrapdoorKey.T().Equal(statement.CommitmentKey.T()) {

		return ErrValidationFailed.WithMessage("trapdoor key does not match statement")
	}
	if !witness.TrapdoorKey.Group().Modulus().Equal(statement.CommitmentKey.Group().Modulus()) {
		return ErrValidationFailed.WithMessage("trapdoor group does not match statement")
	}

	t, err := statement.CommitmentKey.T().LearnOrder(witness.TrapdoorKey.Group())
	if err != nil {
		return errs.Wrap(err).WithMessage("could not learn order of t")
	}
	expectedS := t.Exp(witness.TrapdoorKey.Lambda().Nat()).ForgetOrder()
	if !expectedS.Equal(statement.CommitmentKey.S()) {
		return ErrValidationFailed.WithMessage("lambda does not open s relative to t")
	}
	return nil
}

func validateCommitment(statement *Statement, commitment *Commitment) error {
	if commitment == nil {
		return ErrInvalidArgument.WithMessage("commitment must not be nil")
	}
	group := statement.CommitmentKey.Group()
	for _, a := range &commitment.A {
		if a == nil {
			return ErrInvalidArgument.WithMessage("commitment element must not be nil")
		}
		if !group.Contains(a) {
			return ErrValidationFailed.WithMessage("commitment element is not in the statement group")
		}
	}
	return nil
}

func phiFromGroup(group *znstar.RSAGroupKnownOrder) (*num.NatPlus, error) {
	if group == nil {
		return nil, ErrInvalidArgument.WithMessage("group must not be nil")
	}
	phi, err := num.NPlus().FromNatCT(group.Arithmetic().Phi.Nat())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not convert phi(N)")
	}
	return phi, nil
}

func symmetricModulusRange(modulus *num.NatPlus) (low, high *num.Int) {
	half := modulus.Rsh(1).Lift()
	return half.Neg(), half.Increment()
}
