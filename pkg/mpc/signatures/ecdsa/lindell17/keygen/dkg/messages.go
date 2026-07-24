package dkg

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/commitments/hashcom"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/proofs/paillier/lp"
	"github.com/bronlabs/bron-crypto/pkg/proofs/paillier/lpdl"
	paillierrange "github.com/bronlabs/bron-crypto/pkg/proofs/paillier/range"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
)

// Round1Broadcast carries the first-round commitment to the ordered set of
// decomposed raw MSP-share component points.
type Round1Broadcast[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	BigQCommitment hashcom.Commitment
}

// Validate checks the round-1 message at the deserialisation boundary.
func (m *Round1Broadcast[P, B, S]) Validate(_ *Participant[P, B, S], _ sharing.ID) error {
	if m == nil {
		return ErrValidation.WithMessage("Round1Broadcast message is nil")
	}
	if m.BigQCommitment == (hashcom.Commitment{}) {
		return ErrValidation.WithMessage("BigQ commitment is empty")
	}
	return nil
}

// ComponentDecomposition contains the two range-bounded halves of one raw MSP
// share component and proofs of their discrete logarithms. Row is the absolute
// row identifier in the public MSP.
type ComponentDecomposition[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	Row                  int
	BigQPrime            P
	BigQPrimeProof       compiler.NIZKPoKProof
	BigQDoublePrime      P
	BigQDoublePrimeProof compiler.NIZKPoKProof
}

// Round2Broadcast opens the round-1 commitment and proves knowledge of the
// discrete logarithm of every raw-share component decomposition half.
type Round2Broadcast[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	BigQOpening hashcom.Witness
	Components  []*ComponentDecomposition[P, B, S]
}

// Validate checks the exact sorted MSP row set and the shape of every point.
// Explicit absolute row identifiers prevent component reordering. The selected
// non-interactive verifier validates each proof when the round is processed.
func (m *Round2Broadcast[P, B, S]) Validate(participant *Participant[P, B, S], sender sharing.ID) error {
	if m == nil {
		return ErrValidation.WithMessage("Round2Broadcast message is nil")
	}
	if m.BigQOpening == (hashcom.Witness{}) {
		return ErrValidation.WithMessage("BigQ opening is empty")
	}
	expectedRows := participant.shareRows(sender)
	if len(m.Components) != len(expectedRows) {
		return ErrValidation.WithMessage("component decomposition count does not match MSP row count %d", len(expectedRows))
	}
	for i, row := range expectedRows {
		component := m.Components[i]
		if component == nil || component.Row != row {
			return ErrValidation.WithMessage("component decomposition %d has the wrong MSP row identifier", i)
		}
		if utils.IsNil(component.BigQPrime) || component.BigQPrime.IsOpIdentity() || !component.BigQPrime.IsTorsionFree() {
			return ErrValidation.WithMessage("invalid BigQ' for MSP row %d", row)
		}
		if utils.IsNil(component.BigQDoublePrime) || component.BigQDoublePrime.IsOpIdentity() || !component.BigQDoublePrime.IsTorsionFree() {
			return ErrValidation.WithMessage("invalid BigQ'' for MSP row %d", row)
		}
	}
	return nil
}

// ComponentCiphertexts contains the Paillier encryptions of both decomposition
// halves of one raw MSP share component.
type ComponentCiphertexts struct {
	Row             int
	CKeyPrime       *paillier.Ciphertext
	CKeyDoublePrime *paillier.Ciphertext
}

// Round3Broadcast carries one Paillier public key and raw-share component
// ciphertext halves under that key.
type Round3Broadcast[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	Components        []*ComponentCiphertexts
	PaillierPublicKey *paillier.PublicKey
}

// Validate checks the Paillier modulus and exact sorted MSP row set.
func (m *Round3Broadcast[P, B, S]) Validate(participant *Participant[P, B, S], sender sharing.ID) error {
	if m == nil || m.PaillierPublicKey == nil {
		return ErrValidation.WithMessage("missing fields in Round3Broadcast message")
	}
	expectedRows := participant.shareRows(sender)
	if len(m.Components) != len(expectedRows) {
		return ErrValidation.WithMessage("component ciphertext count does not match MSP row count %d", len(expectedRows))
	}
	if m.PaillierPublicKey.Group().N().TrueLen() != participant.paillierKeyLen {
		return ErrValidation.WithMessage("invalid Paillier public key size in Round3Broadcast message")
	}
	for i, row := range expectedRows {
		component := m.Components[i]
		if component == nil || component.Row != row {
			return ErrValidation.WithMessage("component ciphertext %d has the wrong MSP row identifier", i)
		}
		if component.CKeyPrime == nil || !m.PaillierPublicKey.CiphertextGroup().Contains(component.CKeyPrime.Value()) {
			return ErrValidation.WithMessage("CKey' for MSP row %d is not a valid ciphertext", row)
		}
		if component.CKeyDoublePrime == nil || !m.PaillierPublicKey.CiphertextGroup().Contains(component.CKeyDoublePrime.Value()) {
			return ErrValidation.WithMessage("CKey'' for MSP row %d is not a valid ciphertext", row)
		}
	}
	return nil
}

// ComponentLPDLRound1Output carries first-round LPDL messages for one MSP row.
type ComponentLPDLRound1Output[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	Row                         int
	LpdlPrimeRound1Output       *lpdl.Round1Output[P, B, S]
	LpdlDoublePrimeRound1Output *lpdl.Round1Output[P, B, S]
}

// Round4P2P carries one first-round LP message and first-round LPDL messages
// for every component of the prover's raw MSP share.
type Round4P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	LpRound1Output *lp.Round1Output
	Components     []*ComponentLPDLRound1Output[P, B, S]
}

// Validate checks all round-4 proof messages against the local prover states.
func (m *Round4P2P[P, B, S]) Validate(participant *Participant[P, B, S], sender sharing.ID) error {
	if m == nil || m.LpRound1Output == nil {
		return ErrValidation.WithMessage("missing fields in Round4P2P message")
	}
	lpProver := participant.state.lpProvers[sender]
	primeProvers := participant.state.lpdlPrimeProvers[sender]
	doublePrimeProvers := participant.state.lpdlDoublePrimeProvers[sender]
	expectedRows := participant.shareRows(participant.SharingID())
	if lpProver == nil || len(primeProvers) != len(expectedRows) || len(doublePrimeProvers) != len(expectedRows) || len(m.Components) != len(expectedRows) {
		return ErrValidation.WithMessage("missing proof state for sender %d", sender)
	}
	if err := m.LpRound1Output.Validate(lpProver, sender); err != nil {
		return errs.Wrap(err).WithMessage("invalid LP round-1 output")
	}
	if err := validateLPRound1Output(m.LpRound1Output, participant.state.myPaillierPk); err != nil {
		return errs.Wrap(err).WithMessage("invalid nested LP round-1 output")
	}
	for i, row := range expectedRows {
		component := m.Components[i]
		if component == nil || component.Row != row || component.LpdlPrimeRound1Output == nil || component.LpdlDoublePrimeRound1Output == nil || primeProvers[i] == nil || doublePrimeProvers[i] == nil {
			return ErrValidation.WithMessage("invalid LPDL round-1 component for MSP row %d", row)
		}
		if err := component.LpdlPrimeRound1Output.Validate(primeProvers[i], sender); err != nil {
			return errs.Wrap(err).WithMessage("invalid prime LPDL round-1 output for MSP row %d", row)
		}
		if err := validateLPDLRound1Output(component.LpdlPrimeRound1Output.CPrime, participant.state.myPaillierPk); err != nil {
			return errs.Wrap(err).WithMessage("invalid nested prime LPDL round-1 output for MSP row %d", row)
		}
		if err := component.LpdlDoublePrimeRound1Output.Validate(doublePrimeProvers[i], sender); err != nil {
			return errs.Wrap(err).WithMessage("invalid double-prime LPDL round-1 output for MSP row %d", row)
		}
		if err := validateLPDLRound1Output(component.LpdlDoublePrimeRound1Output.CPrime, participant.state.myPaillierPk); err != nil {
			return errs.Wrap(err).WithMessage("invalid nested double-prime LPDL round-1 output for MSP row %d", row)
		}
	}
	return nil
}

// ComponentLPDLRound2Output carries second-round LPDL messages for one MSP row.
type ComponentLPDLRound2Output[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	Row                         int
	LpdlPrimeRound2Output       *lpdl.Round2Output[P, B, S]
	LpdlDoublePrimeRound2Output *lpdl.Round2Output[P, B, S]
}

// Round5P2P carries the second LP and component-wise LPDL messages.
type Round5P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	LpRound2Output *lp.Round2Output
	Components     []*ComponentLPDLRound2Output[P, B, S]
}

// Validate checks all round-5 proof messages against the local verifier states.
//
//nolint:dupl // false positive
func (m *Round5P2P[P, B, S]) Validate(participant *Participant[P, B, S], sender sharing.ID) error {
	if m == nil || m.LpRound2Output == nil {
		return ErrValidation.WithMessage("missing fields in Round5P2P message")
	}
	lpVerifier := participant.state.lpVerifiers[sender]
	primeVerifiers := participant.state.lpdlPrimeVerifiers[sender]
	doublePrimeVerifiers := participant.state.lpdlDoublePrimeVerifiers[sender]
	expectedRows := participant.shareRows(sender)
	if lpVerifier == nil || len(primeVerifiers) != len(expectedRows) || len(doublePrimeVerifiers) != len(expectedRows) || len(m.Components) != len(expectedRows) {
		return ErrValidation.WithMessage("missing proof state for sender %d", sender)
	}
	if err := m.LpRound2Output.Validate(lpVerifier, sender); err != nil {
		return errs.Wrap(err).WithMessage("invalid LP round-2 output")
	}
	publicKey := participant.state.theirPaillierPublicKeys[sender]
	for i, row := range expectedRows {
		component := m.Components[i]
		if component == nil || component.Row != row || component.LpdlPrimeRound2Output == nil || component.LpdlDoublePrimeRound2Output == nil || primeVerifiers[i] == nil || doublePrimeVerifiers[i] == nil {
			return ErrValidation.WithMessage("invalid LPDL round-2 component for MSP row %d", row)
		}
		if err := component.LpdlPrimeRound2Output.Validate(primeVerifiers[i], sender); err != nil {
			return errs.Wrap(err).WithMessage("invalid prime LPDL round-2 output for MSP row %d", row)
		}
		if err := validateRangeCommitment(component.LpdlPrimeRound2Output.RangeProverOutput, publicKey); err != nil {
			return errs.Wrap(err).WithMessage("invalid nested prime LPDL round-2 output for MSP row %d", row)
		}
		if err := component.LpdlDoublePrimeRound2Output.Validate(doublePrimeVerifiers[i], sender); err != nil {
			return errs.Wrap(err).WithMessage("invalid double-prime LPDL round-2 output for MSP row %d", row)
		}
		if err := validateRangeCommitment(component.LpdlDoublePrimeRound2Output.RangeProverOutput, publicKey); err != nil {
			return errs.Wrap(err).WithMessage("invalid nested double-prime LPDL round-2 output for MSP row %d", row)
		}
	}
	return nil
}

// ComponentLPDLRound3Output carries third-round LPDL messages for one MSP row.
type ComponentLPDLRound3Output[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	Row                         int
	LpdlPrimeRound3Output       *lpdl.Round3Output[P, B, S]
	LpdlDoublePrimeRound3Output *lpdl.Round3Output[P, B, S]
}

// Round6P2P carries the third LP and component-wise LPDL messages.
type Round6P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	LpRound3Output *lp.Round3Output
	Components     []*ComponentLPDLRound3Output[P, B, S]
}

// Validate checks all round-6 proof messages against the local prover states.
func (m *Round6P2P[P, B, S]) Validate(participant *Participant[P, B, S], sender sharing.ID) error {
	if m == nil || m.LpRound3Output == nil {
		return ErrValidation.WithMessage("missing fields in Round6P2P message")
	}
	lpProver := participant.state.lpProvers[sender]
	primeProvers := participant.state.lpdlPrimeProvers[sender]
	doublePrimeProvers := participant.state.lpdlDoublePrimeProvers[sender]
	expectedRows := participant.shareRows(participant.SharingID())
	if lpProver == nil || len(primeProvers) != len(expectedRows) || len(doublePrimeProvers) != len(expectedRows) || len(m.Components) != len(expectedRows) {
		return ErrValidation.WithMessage("missing proof state for sender %d", sender)
	}
	if err := m.LpRound3Output.Validate(lpProver, sender); err != nil {
		return errs.Wrap(err).WithMessage("invalid LP round-3 output")
	}
	if err := validateLPRound3Output(m.LpRound3Output, participant.state.myPaillierPk); err != nil {
		return errs.Wrap(err).WithMessage("invalid nested LP round-3 output")
	}
	for i, row := range expectedRows {
		component := m.Components[i]
		if component == nil || component.Row != row || component.LpdlPrimeRound3Output == nil || component.LpdlDoublePrimeRound3Output == nil || primeProvers[i] == nil || doublePrimeProvers[i] == nil {
			return ErrValidation.WithMessage("invalid LPDL round-3 component for MSP row %d", row)
		}
		if err := component.LpdlPrimeRound3Output.Validate(primeProvers[i], sender); err != nil {
			return errs.Wrap(err).WithMessage("invalid prime LPDL round-3 output for MSP row %d", row)
		}
		if err := component.LpdlDoublePrimeRound3Output.Validate(doublePrimeProvers[i], sender); err != nil {
			return errs.Wrap(err).WithMessage("invalid double-prime LPDL round-3 output for MSP row %d", row)
		}
	}
	return nil
}

// ComponentLPDLRound4Output carries final LPDL responses for one MSP row.
type ComponentLPDLRound4Output[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	Row                         int
	LpdlPrimeRound4Output       *lpdl.Round4Output[P, B, S]
	LpdlDoublePrimeRound4Output *lpdl.Round4Output[P, B, S]
}

// Round7P2P carries the final LP and component-wise LPDL responses.
type Round7P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	LpRound4Output *lp.Round4Output
	Components     []*ComponentLPDLRound4Output[P, B, S]
}

// Validate checks all round-7 proof messages against the local verifier states.
//
//nolint:dupl // false positive
func (m *Round7P2P[P, B, S]) Validate(participant *Participant[P, B, S], sender sharing.ID) error {
	if m == nil || m.LpRound4Output == nil {
		return ErrValidation.WithMessage("missing fields in Round7P2P message")
	}
	lpVerifier := participant.state.lpVerifiers[sender]
	primeVerifiers := participant.state.lpdlPrimeVerifiers[sender]
	doublePrimeVerifiers := participant.state.lpdlDoublePrimeVerifiers[sender]
	expectedRows := participant.shareRows(sender)
	if lpVerifier == nil || len(primeVerifiers) != len(expectedRows) || len(doublePrimeVerifiers) != len(expectedRows) || len(m.Components) != len(expectedRows) {
		return ErrValidation.WithMessage("missing proof state for sender %d", sender)
	}
	if err := m.LpRound4Output.Validate(lpVerifier, sender); err != nil {
		return errs.Wrap(err).WithMessage("invalid LP round-4 output")
	}
	publicKey := participant.state.theirPaillierPublicKeys[sender]
	for i, row := range expectedRows {
		component := m.Components[i]
		if component == nil || component.Row != row || component.LpdlPrimeRound4Output == nil || component.LpdlDoublePrimeRound4Output == nil || primeVerifiers[i] == nil || doublePrimeVerifiers[i] == nil {
			return ErrValidation.WithMessage("invalid LPDL round-4 component for MSP row %d", row)
		}
		if err := component.LpdlPrimeRound4Output.Validate(primeVerifiers[i], sender); err != nil {
			return errs.Wrap(err).WithMessage("invalid prime LPDL round-4 output for MSP row %d", row)
		}
		if err := validateRangeResponse(component.LpdlPrimeRound4Output.RangeProverOutput, publicKey); err != nil {
			return errs.Wrap(err).WithMessage("invalid nested prime LPDL round-4 output for MSP row %d", row)
		}
		if err := component.LpdlDoublePrimeRound4Output.Validate(doublePrimeVerifiers[i], sender); err != nil {
			return errs.Wrap(err).WithMessage("invalid double-prime LPDL round-4 output for MSP row %d", row)
		}
		if err := validateRangeResponse(component.LpdlDoublePrimeRound4Output.RangeProverOutput, publicKey); err != nil {
			return errs.Wrap(err).WithMessage("invalid nested double-prime LPDL round-4 output for MSP row %d", row)
		}
	}
	return nil
}

func validateLPRound1Output(m *lp.Round1Output, publicKey *paillier.PublicKey) error {
	if publicKey == nil {
		return ErrValidation.WithMessage("missing local Paillier public key")
	}
	for i, statement := range m.X {
		if statement.X == nil || statement.X.Value() == nil || statement.X.Value().Value() == nil ||
			!publicKey.CiphertextGroup().Contains(statement.X) {

			return ErrValidation.WithMessage("LP statement %d is not in the local Paillier group", i)
		}
	}
	for i, commitment := range m.NthRootsProverOutput {
		if commitment.A == nil || commitment.A.Value() == nil || commitment.A.Value().Value() == nil ||
			!publicKey.CiphertextGroup().Contains(commitment.A) {

			return ErrValidation.WithMessage("LP commitment %d is not in the local Paillier group", i)
		}
	}
	return nil
}

func validateLPRound3Output(m *lp.Round3Output, publicKey *paillier.PublicKey) error {
	if publicKey == nil {
		return ErrValidation.WithMessage("missing local Paillier public key")
	}
	for i, response := range m.NthRootsProverOutput {
		if response.Z == nil || response.Z.Value() == nil || response.Z.Value().Value() == nil ||
			!publicKey.CiphertextGroup().Contains(response.Z) {

			return ErrValidation.WithMessage("LP response %d is not in the local Paillier group", i)
		}
	}
	return nil
}

func validateLPDLRound1Output(ciphertext *paillier.Ciphertext, publicKey *paillier.PublicKey) error {
	if publicKey == nil {
		return ErrValidation.WithMessage("missing local Paillier public key")
	}
	if ciphertext.Value() == nil || ciphertext.Value().Value() == nil || !publicKey.CiphertextGroup().Contains(ciphertext.Value()) {
		return ErrValidation.WithMessage("LPDL ciphertext is not in the local Paillier group")
	}
	return nil
}

func validateRangeCommitment(commitment *paillierrange.Commitment, publicKey *paillier.PublicKey) error {
	if publicKey == nil {
		return ErrValidation.WithMessage("missing peer Paillier public key")
	}
	expected := int(base.ComputationalSecurityBits)
	if len(commitment.C1) != expected || len(commitment.C2) != expected {
		return ErrValidation.WithMessage("range commitment lengths must both be %d", expected)
	}
	for i := range expected {
		if !validPaillierCiphertext(commitment.C1[i], publicKey) {
			return ErrValidation.WithMessage("range commitment C1[%d] is not in the peer Paillier group", i)
		}
		if !validPaillierCiphertext(commitment.C2[i], publicKey) {
			return ErrValidation.WithMessage("range commitment C2[%d] is not in the peer Paillier group", i)
		}
	}
	return nil
}

func validateRangeResponse(response *paillierrange.Response, publicKey *paillier.PublicKey) error {
	if publicKey == nil {
		return ErrValidation.WithMessage("missing peer Paillier public key")
	}
	expected := int(base.ComputationalSecurityBits)
	if len(response.W1) != len(response.R1) || len(response.W1) != len(response.W2) || len(response.W1) != len(response.R2) ||
		len(response.Wj) != len(response.Rj) || len(response.Wj) != len(response.J) || len(response.W1)+len(response.Wj) != expected {

		return ErrValidation.WithMessage("inconsistent range response map lengths")
	}

	plaintextGroup := publicKey.PlaintextGroup()
	nonceGroup := publicKey.NonceGroup()
	validPlaintext := func(value *paillier.Plaintext) bool {
		return value != nil && value.Value() != nil && value.Value().Value() != nil && plaintextGroup.Contains(value.Value())
	}
	validNonce := func(value *paillier.Nonce) bool {
		return value != nil && value.Value() != nil && value.Value().Value() != nil && nonceGroup.Contains(value.Value())
	}

	for i := range uint(expected) {
		w1, hasW1 := response.W1[i]
		r1, hasR1 := response.R1[i]
		w2, hasW2 := response.W2[i]
		r2, hasR2 := response.R2[i]
		wj, hasWj := response.Wj[i]
		rj, hasRj := response.Rj[i]
		j, hasJ := response.J[i]

		switch {
		case hasW1 && hasR1 && hasW2 && hasR2 && !hasWj && !hasRj && !hasJ:
			if !validPlaintext(w1) || !validNonce(r1) || !validPlaintext(w2) || !validNonce(r2) {
				return ErrValidation.WithMessage("range response opening %d contains an invalid value", i)
			}
		case !hasW1 && !hasR1 && !hasW2 && !hasR2 && hasWj && hasRj && hasJ:
			if !validPlaintext(wj) || !validNonce(rj) || (j != 1 && j != 2) {
				return ErrValidation.WithMessage("range response combined opening %d contains an invalid value", i)
			}
		default:
			return ErrValidation.WithMessage("range response maps disagree at index %d", i)
		}
	}
	return nil
}

func validPaillierCiphertext(ciphertext *paillier.Ciphertext, publicKey *paillier.PublicKey) bool {
	return ciphertext != nil && ciphertext.Value() != nil && ciphertext.Value().Value() != nil &&
		publicKey.CiphertextGroup().Contains(ciphertext.Value())
}
