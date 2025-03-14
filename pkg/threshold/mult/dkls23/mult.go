package dkls23

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
)

// These should really be parameters, but we are declaring them as constants for readability of struct field types.
const (
	// Commputational security parameter (a.k.a. lambda_c).
	Lambda      = base.ComputationalSecurity
	LambdaBytes = Lambda / 8

	// Statistical security parameter (a.k.a. lambda_s).
	S      = base.ComputationalSecurity
	SBytes = S / 8

	// Group order bit-size (=|q| for group Zq).
	QBitLen      = base.FieldBytes * 8
	QBitLenBytes = base.FieldBytes

	// Scalar batch size.
	L = 2

	// Expansion ratio, set to ceil(kappa / lambda_c) = 2.
	Rho = (QBitLen + Lambda - 1) / Lambda

	// Number of OTe messages needed for the OTe functionality.
	LOTe = L + Rho

	// number of random choice bits per element in each batch.
	Xi      = QBitLen + 2*S
	XiBytes = Xi / 8

	// OTe batch size.
	Eta      = Xi * L
	EtaBytes = Eta / 8
)

type (
	RvoleAliceInput = [L]curves.Scalar
	OutputShares    = [L]curves.Scalar
)
