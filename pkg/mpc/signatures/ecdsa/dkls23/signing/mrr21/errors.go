package signing_mrr21

import "github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/dkls23/signing"

var (
	// ErrInvalidArgument aliases signing.ErrInvalidArgument: a constructor or
	// round received an argument that violates its documented contract.
	ErrInvalidArgument = signing.ErrInvalidArgument
	// ErrValidation aliases signing.ErrValidation: an incoming message failed
	// validation.
	ErrValidation = signing.ErrValidation
	// ErrRound aliases signing.ErrRound: a round was invoked out of order.
	ErrRound = signing.ErrRound
)
