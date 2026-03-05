package gjkr07

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	pedersenVSS "github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/meta/pedersen"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
)

// Round1Broadcast carries the dealer’s Pedersen VSS verification vector.
type Round1Broadcast[
	LFTDF interface {
		algebra.Operand[LFTDF]
		sharing.DealerFunc[LFTS, LFTSV, AC]
	}, LFTS sharing.LinearShare[LFTS, LFTSV],
	LFTSV algebra.PrimeGroupElement[LFTSV, SV],
	SV algebra.PrimeFieldElement[SV],
	AC accessstructures.Monotone,
] struct {
	PedersenVerificationVector LFTDF `cbor:"verificationVector"`
}

// Round2Unicast carries the dealer’s Pedersen share to a specific party.
type Round2Unicast[US sharing.LinearShare[US, USV], USV algebra.PrimeFieldElement[USV]] struct {
	Share *pedersenVSS.Share[US, USV] `cbor:"share"`
}

// Round2Broadcast carries the Feldman VSS verification vector and proof of well-formedness.
type Round2Broadcast[
	LFTDF interface {
		algebra.Operand[LFTDF]
		sharing.DealerFunc[LFTS, LFTSV, AC]
	}, LFTS sharing.LinearShare[LFTS, LFTSV],
	LFTSV algebra.PrimeGroupElement[LFTSV, SV],
	SV algebra.PrimeFieldElement[SV],
	AC accessstructures.Monotone,
] struct {
	FeldmanVerificationVector LFTDF                 `cbor:"verificationVector"`
	Proof                     compiler.NIZKPoKProof `cbor:"proof"`
}
