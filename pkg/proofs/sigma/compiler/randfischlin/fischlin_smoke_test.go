package randfischlin_test

import (
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/randfischlin"
)

func _[X sigma.Statement, W sigma.Witness, A sigma.Statement, S sigma.State, Z sigma.Response]() {
	var (
		_ compiler.NonInteractiveProtocol[X, W] = (*randfischlin.Protocol[X, W, A, S, Z])(nil)
		_ compiler.NIProver[X, W]               = (*randfischlin.Prover[X, W, A, S, Z])(nil)
		_ compiler.NIVerifier[X]                = (*randfischlin.Verifier[X, W, A, S, Z])(nil)
	)
}
