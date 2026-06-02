package prm

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/commitments/intcom"
	"github.com/bronlabs/bron-crypto/pkg/proofs"
)

func validateCommitmentKey(commitmentKey *intcom.CommitmentKey) error {
	if commitmentKey == nil {
		return proofs.ErrInvalidArgument.WithMessage("commitment key must not be nil")
	}
	s := commitmentKey.S()
	t := commitmentKey.T()
	if s == nil || t == nil {
		return proofs.ErrInvalidArgument.WithMessage("s and t must not be nil")
	}
	group := s.Group()
	if group == nil || t.Group() == nil {
		return proofs.ErrInvalidArgument.WithMessage("s and t groups must not be nil")
	}
	if !group.Contains(t) {
		return proofs.ErrValidationFailed.WithMessage("s and t must belong to the same RSA group")
	}
	if s.Equal(t) {
		return proofs.ErrValidationFailed.WithMessage("s and t must be distinct")
	}
	if s.IsOne() || t.IsOne() {
		return proofs.ErrValidationFailed.WithMessage("s and t must not be the identity")
	}
	if !s.IsTorsionFree() || !t.IsTorsionFree() {
		return proofs.ErrValidationFailed.WithMessage("s and t must be torsion-free")
	}
	if !s.Value().Decrement().Nat().Coprime(s.Modulus().Nat()) {
		return proofs.ErrValidationFailed.WithMessage("s cannot be a generator of QR(N)")
	}
	if !t.Value().Decrement().Nat().Coprime(t.Modulus().Nat()) {
		return proofs.ErrValidationFailed.WithMessage("t cannot be a generator of QR(N)")
	}
	return nil
}

func validateWitness(statement *Statement, witness *Witness) error {
	if !witness.trapdoorKey.S().Equal(statement.commitmentKey.S()) ||
		!witness.trapdoorKey.T().Equal(statement.commitmentKey.T()) {

		return proofs.ErrValidationFailed.WithMessage("trapdoor key does not match statement")
	}
	if !witness.trapdoorKey.Group().Modulus().Equal(statement.commitmentKey.Group().Modulus()) {
		return proofs.ErrValidationFailed.WithMessage("trapdoor group does not match statement")
	}

	t, err := statement.commitmentKey.T().LearnOrder(witness.trapdoorKey.Group())
	if err != nil {
		return errs.Wrap(err).WithMessage("could not learn order of t")
	}
	expectedS := t.Exp(witness.trapdoorKey.Lambda().Nat()).ForgetOrder()
	if !expectedS.Equal(statement.commitmentKey.S()) {
		return proofs.ErrValidationFailed.WithMessage("lambda does not open s relative to t")
	}
	return nil
}

func validateCommitment(statement *Statement, commitment *Commitment) error {
	group := statement.commitmentKey.Group()
	for _, a := range &commitment.a {
		if !group.Contains(a) {
			return proofs.ErrValidationFailed.WithMessage("commitment element is not in the statement group")
		}
	}
	return nil
}

func phiFromGroup(group *znstar.RSAGroupKnownOrder) (*num.NatPlus, error) {
	if group == nil {
		return nil, proofs.ErrInvalidArgument.WithMessage("group must not be nil")
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
