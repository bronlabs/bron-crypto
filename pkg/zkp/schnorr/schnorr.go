//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

// Package schnorr implements a Schnorr proof, as described and used in Doerner, et al. https://eprint.iacr.org/2018/499.pdf
// see Functionalities 6. it also implements a "committed" version, as described in Functionality 7.
package schnorr

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"

	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
)

type Commitment = []byte

type Prover struct {
	curve           *curves.Curve
	basePoint       curves.Point
	uniqueSessionId []byte
	parameters      [][]byte
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
func NewProver(curve *curves.Curve, basepoint curves.Point, uniqueSessionId []byte, parameters [][]byte) *Prover {
	if basepoint == nil {
		basepoint = curve.NewGeneratorPoint()
	}
	return &Prover{
		curve:           curve,
		basePoint:       basepoint,
		uniqueSessionId: uniqueSessionId,
		parameters:      parameters,
	}
}

// Prove generates and returns a Schnorr proof, given the scalar witness `x`.
// in the process, it will actually also construct the statement (just one curve mult in this case)
func (p *Prover) Prove(x curves.Scalar) (*Proof, error) {
	// assumes that params, and pub are already populated. populates the fields c and s...
	var err error
	result := &Proof{}
	result.Statement = p.basePoint.Mul(x)
	k := p.curve.Scalar.Random(rand.Reader)
	random := p.basePoint.Mul(k)
	hash := sha3.New256()
	if _, err = hash.Write(p.basePoint.ToAffineCompressed()); err != nil {
		return nil, errors.Wrap(err, "writing basePoint to hash in schnorr prove")
	}
	if _, err = hash.Write(random.ToAffineCompressed()); err != nil {
		return nil, errors.Wrap(err, "writing point K to hash in schnorr prove")
	}
	if _, err = hash.Write(result.Statement.ToAffineCompressed()); err != nil {
		return nil, errors.Wrap(err, "writing statement to hash in schnorr prove")
	}
	if _, err = hash.Write(p.uniqueSessionId); err != nil {
		return nil, errors.Wrap(err, "writing salt to hash in schnorr prove")
	}
	for _, parameter := range p.parameters {
		if _, err := hash.Write(parameter); err != nil {
			return nil, errors.Wrap(err, "writing parameter to the hash in schnorr prove")
		}
	}
	if p.curve.Name == curves.ED25519().Name {
		scalar := &curves.ScalarEd25519{}
		result.C, err = scalar.SetBytesClamping(hash.Sum(nil))
		if err != nil {
			return nil, errors.Wrap(err, "converting hash to challenge scalar failed")
		}
	} else {
		result.C, err = p.curve.Scalar.SetBytes(hash.Sum(nil))
		if err != nil {
			return nil, errors.Wrap(err, "converting hash to challenge scalar failed")
		}
	}
	result.S = result.C.Mul(x).Add(k)
	return result, nil
}

// Verify verifies the `proof`, given the prover parameters `scalar` and `curve`.
// As for the prover, we allow `basePoint == nil`, in this case, it's auto-assigned to be the group's default generator.
func Verify(proof *Proof, curve *curves.Curve, basepoint curves.Point, uniqueSessionId []byte, parameters [][]byte) error {
	if basepoint == nil {
		basepoint = curve.NewGeneratorPoint()
	}
	gs := basepoint.Mul(proof.S)
	xc := proof.Statement.Mul(proof.C.Neg())
	random := gs.Add(xc)
	hash := sha3.New256()
	if _, err := hash.Write(basepoint.ToAffineCompressed()); err != nil {
		return errors.Wrap(err, "writing basePoint to hash in schnorr verify")
	}
	if _, err := hash.Write(random.ToAffineCompressed()); err != nil {
		return errors.Wrap(err, "writing point K to hash in schnorr verify")
	}
	if _, err := hash.Write(proof.Statement.ToAffineCompressed()); err != nil {
		return errors.Wrap(err, "writing statement to hash in schnorr verify")
	}
	if _, err := hash.Write(uniqueSessionId); err != nil {
		return errors.Wrap(err, "writing salt to hash in schnorr verify")
	}
	for _, parameter := range parameters {
		if _, err := hash.Write(parameter); err != nil {
			return errors.Wrap(err, "writing parameter to the hash in schnorr verify")
		}
	}
	var computedChallenge curves.Scalar
	var err error
	if curve.Name == curves.ED25519().Name {
		scalar := &curves.ScalarEd25519{}
		computedChallenge, err = scalar.SetBytesClamping(hash.Sum(nil))
		if err != nil {
			return errors.Wrap(err, "converting hash to challenge scalar failed")
		}
	} else {
		computedChallenge, err = curve.Scalar.SetBytes(hash.Sum(nil))
		if err != nil {
			return errors.Wrap(err, "converting hash to challenge scalar failed")
		}
	}
	if subtle.ConstantTimeCompare(proof.C.Bytes(), computedChallenge.Bytes()) != 1 {
		return fmt.Errorf("schnorr verification failed")
	}
	return nil
}

// ProveCommit generates _and_ commits to a schnorr proof which is later revealed; see Functionality 7.
// returns the Proof and Commitment.
func (p *Prover) ProveCommit(x curves.Scalar) (*Proof, Commitment, error) {
	proof, err := p.Prove(x)
	if err != nil {
		return nil, nil, err
	}
	hash := sha3.New256()
	if _, err = hash.Write(proof.C.Bytes()); err != nil {
		return nil, nil, err
	}
	if _, err = hash.Write(proof.S.Bytes()); err != nil {
		return nil, nil, err
	}
	return proof, hash.Sum(nil), nil
}

// DecommitVerify receives a `Proof` and a `Commitment`; it first checks that the proof actually opens the commitment;
// then it verifies the proof. returns and error if either on eof thse fail.
func DecommitVerify(proof *Proof, commitment Commitment, curve *curves.Curve, basepoint curves.Point, uniqueSessionId []byte) error {
	hash := sha3.New256()
	if _, err := hash.Write(proof.C.Bytes()); err != nil {
		return err
	}
	if _, err := hash.Write(proof.S.Bytes()); err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(hash.Sum(nil), commitment) != 1 {
		return fmt.Errorf("initial hash decommitment failed")
	}
	return Verify(proof, curve, basepoint, uniqueSessionId, nil)
}
