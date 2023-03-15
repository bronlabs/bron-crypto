package schnorr

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"

	"github.com/pkg/errors"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves/native"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
)

type Prover struct {
	CipherSuite     *integration.CipherSuite
	BasePoint       curves.Point
	uniqueSessionId []byte
	options         *Options
}

type Options struct {
	TranscriptPrefixes [][]byte
	TranscriptSuffixes [][]byte
}

// Proof contains the (c, s) schnorr proof. `Statement` is the curve point you're proving knowledge of discrete log of,
// with respect to the base point.
type Proof struct {
	C         curves.Scalar
	S         curves.Scalar
	Statement curves.Point
}

// NewProver generates a `Prover` object, ready to generate Schnorr proofs on any given point.
// We allow the option `basePoint == nil`, in which case `basePoint` is auto-assigned to be the "default" generator for the group.
func NewProver(cipherSuite *integration.CipherSuite, basePoint curves.Point, uniqueSessionId []byte, options *Options) (*Prover, error) {
	if err := cipherSuite.Validate(); err != nil {
		return nil, errors.Wrap(err, "ciphersuite is invalid")
	}
	if basePoint == nil {
		basePoint = cipherSuite.Curve.Point.Generator()
	}
	// In a schnorr proof, G is the first item of the transcript. We want to generate a schnorr proof, bind it to a message and have it be
	// verifiable with an Ed25519 Verifier. So we check if options is nil, and then automatically we add G to the transcript prefixes
	if options == nil {
		options = &Options{
			TranscriptPrefixes: [][]byte{basePoint.ToAffineCompressed()},
		}

	}
	return &Prover{
		CipherSuite:     cipherSuite,
		BasePoint:       basePoint,
		uniqueSessionId: uniqueSessionId,
		options:         options,
	}, nil
}

// Prove generates and returns a Schnorr proof, given the scalar witness `x`.
// in the process, it will actually also construct the statement (just one curve mult in this case)
func (p *Prover) Prove(x curves.Scalar) (*Proof, error) {
	var err error
	if p.options == nil {
		return nil, errors.New("options can't be nil")
	}
	result := &Proof{}
	result.Statement = p.BasePoint.Mul(x)
	k := p.CipherSuite.Curve.Scalar.Random(rand.Reader)
	R := p.BasePoint.Mul(k)

	// G will be added by default to the prefixes
	transcriptItems := [][]byte{R.ToAffineCompressed(), result.Statement.ToAffineCompressed(), p.uniqueSessionId}
	if len(p.options.TranscriptPrefixes) > 0 {
		transcriptItems = append(p.options.TranscriptPrefixes, transcriptItems...)
	}
	if len(p.options.TranscriptSuffixes) > 0 {
		transcriptItems = append(transcriptItems, p.options.TranscriptSuffixes...)
	}

	result.C, err = ComputeFiatShamirChallege(p.CipherSuite, transcriptItems)
	if err != nil {
		return nil, errors.Wrap(err, "could not produce fiat shamir challenge scalar")
	}

	result.S = result.C.Mul(x).Add(k)
	return result, nil
}

// Verify verifies the `proof`, given the prover parameters `scalar` and `curve`.
// As for the prover, we allow `basePoint == nil`, in this case, it's auto-assigned to be the group's default generator.
func Verify(cipherSuite *integration.CipherSuite, proof *Proof, basepoint curves.Point, uniqueSessionId []byte, options *Options) error {
	if err := cipherSuite.Validate(); err != nil {
		return errors.Wrap(err, "ciphersuite is invalid")
	}
	if proof == nil {
		return errors.New("proof is nil")
	}

	if basepoint == nil {
		basepoint = cipherSuite.Curve.Point.Generator()
	}

	gs := basepoint.Mul(proof.S)
	xc := proof.Statement.Mul(proof.C.Neg())
	R := gs.Add(xc)
	if options == nil {
		options = &Options{
			TranscriptPrefixes: [][]byte{basepoint.ToAffineCompressed()},
		}
	}
	transcriptItems := [][]byte{R.ToAffineCompressed(), proof.Statement.ToAffineCompressed(), uniqueSessionId}
	if len(options.TranscriptPrefixes) > 0 {
		transcriptItems = append(options.TranscriptPrefixes, transcriptItems...)
	}
	if len(options.TranscriptSuffixes) > 0 {
		transcriptItems = append(transcriptItems, options.TranscriptSuffixes...)
	}

	computedChallenge, err := ComputeFiatShamirChallege(cipherSuite, transcriptItems)
	if err != nil {
		return errors.Wrap(err, "could not compute challenge")
	}

	if subtle.ConstantTimeCompare(proof.C.Bytes(), computedChallenge.Bytes()) != 1 {
		return fmt.Errorf("schnorr verification failed")
	}
	return nil
}

func ComputeFiatShamirChallege(cipherSuite *integration.CipherSuite, xs [][]byte) (curves.Scalar, error) {
	if err := cipherSuite.Validate(); err != nil {
		return nil, errors.Wrap(err, "ciphersuite is invalid")
	}

	H := cipherSuite.Hash()
	for _, x := range xs {
		if _, err := H.Write(x); err != nil {
			return nil, errors.Wrap(err, "could not write to H")
		}
	}

	digest := H.Sum(nil)
	var setBytesFunc func([]byte) (curves.Scalar, error)
	switch len(digest) {
	case native.FieldBytes:
		// if a 256-bit hash function is used with ED25519, then the setBytes function will not reduce it.
		// we can't manually reduce it ourselves because it's not exported from the golang's std. So we will
		// call clamping method which internally does the reduction.
		if cipherSuite.Curve.Name == curves.ED25519().Name {
			scalar := &curves.ScalarEd25519{}
			setBytesFunc = scalar.SetBytesClamping
		} else {
			setBytesFunc = cipherSuite.Curve.Scalar.SetBytes
		}
	case native.WideFieldBytes:
		setBytesFunc = cipherSuite.Curve.Scalar.SetBytesWide
	default:
		return nil, errors.Errorf("digest length %d unsporrted", len(digest))
	}

	challenge, err := setBytesFunc(digest)
	if err != nil {
		return nil, errors.Wrap(err, "could not compute challenge scalar")
	}
	return challenge, nil
}
