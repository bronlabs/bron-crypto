package dlog

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/curveutils"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/dlog/batch_schnorr"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/dlog/schnorr"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler"
	compilerUtils "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler_utils"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
)

const (
	PROTOCOL       = schnorr.Name
	BATCH_PROTOCOL = batch_schnorr.Name
)

func Prove(sessionId []byte, secret curves.Scalar, basePoint curves.Point, niCompiler compiler.Name, transcript transcripts.Transcript, prng io.Reader) (proof compiler.NIZKPoKProof, statement curves.Point, err error) {
	if err := validateProveInputs(sessionId, false, secret, nil, basePoint, niCompiler, prng); err != nil {
		return nil, nil, errs.WrapArgument(err, "invalid arguments")
	}
	statement = basePoint.ScalarMul(secret)
	switch PROTOCOL {
	case schnorr.Name:
		sigmaProtocol, err := schnorr.NewSigmaProtocol(basePoint, prng)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "could not construct dlog sigma protocol")
		}
		niSigma, err := compilerUtils.MakeNonInteractive(niCompiler, sigmaProtocol, prng)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "could not convert dlog sigma protocol into non interactive")
		}
		prover, err := niSigma.NewProver(sessionId, transcript)
		if err != nil {
			return nil, nil, errs.NewFailed("cannot create dlog prover")
		}
		proof, err := prover.Prove(statement, secret)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "cannot prove dlog")
		}
		return proof, statement, nil
	default:
		return nil, nil, errs.NewType("default protocol is not supported %s", PROTOCOL)
	}
}

func BatchProve(sessionId []byte, secrets []curves.Scalar, basePoint curves.Point, niCompiler compiler.Name, transcript transcripts.Transcript, prng io.Reader) (proof compiler.NIZKPoKProof, statement []curves.Point, err error) {
	if err := validateProveInputs(sessionId, true, nil, secrets, basePoint, niCompiler, prng); err != nil {
		return nil, nil, errs.WrapArgument(err, "invalid arguments")
	}
	statement = make([]curves.Point, len(secrets))
	for i, s := range secrets {
		statement[i] = basePoint.ScalarMul(s)
	}
	switch BATCH_PROTOCOL {
	case batch_schnorr.Name:
		sigmaProtocol, err := batch_schnorr.NewSigmaProtocol(basePoint, prng)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "could not construct batch dlog sigma protocol")
		}
		niSigma, err := compilerUtils.MakeNonInteractive(niCompiler, sigmaProtocol, prng)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "could not convert dlog sigma protocol into non interactive")
		}
		prover, err := niSigma.NewProver(sessionId, transcript)
		if err != nil {
			return nil, nil, errs.NewFailed("cannot create dlog prover")
		}
		proof, err := prover.Prove(statement, secrets)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "cannot prove dlog")
		}
		return proof, statement, nil
	default:
		return nil, nil, errs.NewType("default protocol is not supported %s", BATCH_PROTOCOL)
	}
}

func Verify(sessionId []byte, proof compiler.NIZKPoKProof, statement, basePoint curves.Point, niCompiler compiler.Name, transcript transcripts.Transcript) error {
	if err := validateVerifyInputs(sessionId, false, statement, nil, basePoint, niCompiler); err != nil {
		return errs.WrapArgument(err, "invalid arguments")
	}
	switch PROTOCOL {
	case schnorr.Name:
		sigmaProtocol, err := schnorr.NewSigmaProtocol(basePoint, nil)
		if err != nil {
			return errs.WrapFailed(err, "could not construct dlog sigma protocol")
		}
		niSigma, err := compilerUtils.MakeNonInteractive(niCompiler, sigmaProtocol, nil)
		if err != nil {
			return errs.WrapFailed(err, "could not convert dlog sigma protocol into non interactive")
		}
		verifier, err := niSigma.NewVerifier(sessionId, transcript)
		if err != nil {
			return errs.WrapFailed(err, "could not construct verifier")
		}
		if err := verifier.Verify(statement, proof); err != nil {
			return errs.WrapVerification(err, "dlog proof failed")
		}
		return nil
	default:
		return errs.NewType("default protocol is not supported %s", PROTOCOL)
	}
}

func BatchVerify(sessionId []byte, proof compiler.NIZKPoKProof, statement []curves.Point, basePoint curves.Point, niCompiler compiler.Name, transcript transcripts.Transcript) error {
	if err := validateVerifyInputs(sessionId, true, nil, statement, basePoint, niCompiler); err != nil {
		return errs.WrapArgument(err, "invalid arguments")
	}
	switch BATCH_PROTOCOL {
	case batch_schnorr.Name:
		sigmaProtocol, err := batch_schnorr.NewSigmaProtocol(basePoint, nil)
		if err != nil {
			return errs.WrapFailed(err, "could not construct batch dlog sigma protocol")
		}
		niSigma, err := compilerUtils.MakeNonInteractive(niCompiler, sigmaProtocol, nil)
		if err != nil {
			return errs.WrapFailed(err, "could not convert batch dlog sigma protocol into non interactive")
		}
		verifier, err := niSigma.NewVerifier(sessionId, transcript)
		if err != nil {
			return errs.WrapFailed(err, "could not construct verifier")
		}
		if err := verifier.Verify(statement, proof); err != nil {
			return errs.WrapVerification(err, "dlog proof failed")
		}
		return nil
	default:
		return errs.NewType("default protocol is not supported %s", PROTOCOL)
	}
}

func validateProveInputs(sessionId []byte, batched bool, secret curves.Scalar, secrets []curves.Scalar, basePoint curves.Point, niCompiler compiler.Name, prng io.Reader) error {
	if len(sessionId) == 0 {
		return errs.NewIsNil("session id")
	}
	if !batched && secret == nil {
		return errs.NewIsNil("secret")
	}
	if batched && secrets == nil {
		return errs.NewIsNil("secrets")
	}
	if basePoint == nil {
		return errs.NewIsNil("base point")
	}
	if !compilerUtils.CompilerIsSupported(niCompiler) {
		return errs.NewType("compiler %s is not supported", niCompiler)
	}
	if prng == nil {
		return errs.NewIsNil("prng")
	}
	if !curveutils.AllOfSameCurve(secret.ScalarField().Curve(), secret, basePoint) {
		return errs.NewCurve("secret and base point have different curves")
	}
	if !curveutils.AllScalarsOfSameCurve(secret.ScalarField().Curve(), secrets...) {
		return errs.NewCurve("secrets have different curves")
	}
	return nil
}

func validateVerifyInputs(sessionId []byte, batched bool, statement curves.Point, statements []curves.Point, basePoint curves.Point, niCompiler compiler.Name) error {
	if len(sessionId) == 0 {
		return errs.NewIsNil("session id")
	}
	if !batched && statement == nil {
		return errs.NewIsNil("statement")
	}
	if batched && statements == nil {
		return errs.NewIsNil("statements")
	}
	if basePoint == nil {
		return errs.NewIsNil("base point")
	}
	if !compilerUtils.CompilerIsSupported(niCompiler) {
		return errs.NewType("compiler %s is not supported", niCompiler)
	}
	return nil
}
