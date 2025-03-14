package dleq

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/curveutils"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/proofs/dleq/chaum"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	compilerUtils "github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler_utils"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

const PROTOCOL = chaum.Name

type Statement = chaum.Statement

func Prove(sessionId []byte, secret curves.Scalar, G1, G2 curves.Point, niCompiler compiler.Name, transcript transcripts.Transcript, prng io.Reader) (proof compiler.NIZKPoKProof, statement *Statement, err error) {
	if err := validateProveInputs(sessionId, secret, G1, G2, niCompiler, prng); err != nil {
		return nil, nil, errs.WrapArgument(err, "invalid arguments")
	}
	X1 := G1.ScalarMul(secret)
	X2 := G2.ScalarMul(secret)
	switch PROTOCOL {
	case chaum.Name:
		statement := &chaum.Statement{
			X1: X1,
			X2: X2,
		}
		sigmaProtocol, err := chaum.NewSigmaProtocol(G1, G2, prng)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "could not construct dleq sigma protocol")
		}
		niSigma, err := compilerUtils.MakeNonInteractive(niCompiler, sigmaProtocol, prng)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "could not convert dleq sigma protocol into non interactive")
		}
		prover, err := niSigma.NewProver(sessionId, transcript)
		if err != nil {
			return nil, nil, errs.NewFailed("cannot create dleq prover")
		}
		proof, err := prover.Prove(statement, secret)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "cannot prove dleq")
		}
		return proof, statement, nil
	default:
		return nil, nil, errs.NewType("default protocol is not supported %s", PROTOCOL)
	}
}

func Verify(sessionId []byte, proof compiler.NIZKPoKProof, statement *Statement, G1, G2 curves.Point, niCompiler compiler.Name, transcript transcripts.Transcript) error {
	if err := validateVerifyInputs(sessionId, statement, G1, G2, niCompiler); err != nil {
		return errs.WrapArgument(err, "invalid arguments")
	}
	switch PROTOCOL {
	case chaum.Name:
		sigmaProtocol, err := chaum.NewSigmaProtocol(G1, G2, nil)
		if err != nil {
			return errs.WrapFailed(err, "could not construct dleq sigma protocol")
		}
		niSigma, err := compilerUtils.MakeNonInteractive(niCompiler, sigmaProtocol, nil)
		if err != nil {
			return errs.WrapFailed(err, "could not convert dleq sigma protocol into non interactive")
		}
		verifier, err := niSigma.NewVerifier(sessionId, transcript)
		if err != nil {
			return errs.WrapFailed(err, "could not construct verifier")
		}
		if err := verifier.Verify(statement, proof); err != nil {
			return errs.WrapVerification(err, "dleq proof failed")
		}
		return nil
	default:
		return errs.NewType("default protocol is not supported %s", PROTOCOL)
	}
}

func validateProveInputs(sessionId []byte, secret curves.Scalar, G1, G2 curves.Point, niCompiler compiler.Name, prng io.Reader) error {
	if len(sessionId) == 0 {
		return errs.NewIsNil("session id")
	}
	if secret == nil {
		return errs.NewIsNil("secret")
	}
	if G1 == nil {
		return errs.NewIsNil("G1")
	}
	if G2 == nil {
		return errs.NewIsNil("G2")
	}
	if G1.Equal(G2) {
		return errs.NewValue("G1 == G2")
	}
	if !compilerUtils.CompilerIsSupported(niCompiler) {
		return errs.NewType("compiler %s is not supported", niCompiler)
	}
	if prng == nil {
		return errs.NewIsNil("prng")
	}
	if curveutils.AllPointsOfSameCurve(G1.Curve(), G1, G2) {
		return errs.NewValue("G1 and G2 have the same curves")
	}
	if !curveutils.AllScalarsOfSameCurve(G1.Curve(), secret) {
		return errs.NewValue("secret is not on the same curve as G1 G2")
	}
	return nil
}

func validateVerifyInputs(sessionId []byte, statement *Statement, G1, G2 curves.Point, niCompiler compiler.Name) error {
	if len(sessionId) == 0 {
		return errs.NewIsNil("session id")
	}
	if G1 == nil {
		return errs.NewIsNil("G1")
	}
	if G2 == nil {
		return errs.NewIsNil("G2")
	}
	if G1.Equal(G2) {
		return errs.NewValue("G1 == G2")
	}
	if statement == nil {
		return errs.NewIsNil("statement")
	}
	if statement.X1 == nil {
		return errs.NewIsNil("X1")
	}
	if statement.X1.Curve().Name() != G1.Curve().Name() {
		return errs.NewValue("X1 group mismatch")
	}
	if statement.X2 == nil {
		return errs.NewIsNil("X2")
	}
	if statement.X2.Curve().Name() != G2.Curve().Name() {
		return errs.NewValue("X2 group mismatch")
	}
	if statement.X1.Equal(statement.X2) {
		return errs.NewValue("X1 == X2")
	}
	if !compilerUtils.CompilerIsSupported(niCompiler) {
		return errs.NewType("compiler %s is not supported", niCompiler)
	}
	return nil
}
