package vsot

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
)

type Round1P2P[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	bigB  P
	proof compiler.NIZKPoKProof
}

type Round2P2P[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	bigA []P
}

type Round3P2P struct {
	xi [][]byte
}

type Round4P2P struct {
	rhoPrime [][]byte
}

type Round5P2P struct {
	rho0Digest [][]byte
	rho1Digest [][]byte
}

type SenderOutput struct {
	M [][2][]byte
}

type ReceiverOutput struct {
	Choices []byte
	M       [][]byte
}
