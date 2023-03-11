package aggregation

import (
	"fmt"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/sharing"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost"
	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"
)

type SignatureAggregator struct {
	CohortConfig          *integration.CohortConfig
	PublicKey             curves.Point
	MyIdentityKey         integration.IdentityKey
	PresentParties        []int
	ShamirIdToIdentityKey map[int]integration.IdentityKey
	PublicKeyShares       *frost.PublicKeyShares

	parameters *SignatureAggregatorParameters
}

type SignatureAggregatorParameters struct {
	Message []byte
	Z_i     curves.Scalar
	R       curves.Point
	D_alpha []curves.Point
	E_alpha []curves.Point
}

func NewSignatureAggregator(identityKey integration.IdentityKey, cohortConfig *integration.CohortConfig, publicKey curves.Point, publicKeyShares *frost.PublicKeyShares, presentParties []int, shamirIdToIdentityKey map[int]integration.IdentityKey, parameters *SignatureAggregatorParameters) (*SignatureAggregator, error) {
	if err := cohortConfig.Validate(); err != nil {
		return nil, errors.Wrap(err, "cohort config is invalid")
	}
	declaredAsSA := false
	for _, someSignatureAggregatorIdentityKey := range cohortConfig.SignatureAggregators {
		if someSignatureAggregatorIdentityKey.PublicKey().Equal(identityKey.PublicKey()) {
			declaredAsSA = true
		}
	}
	if !declaredAsSA {
		return nil, errors.New("provided identity key is not declared as a signature aggregator within the cohort config")
	}
	if presentParties == nil || len(presentParties) == 0 {
		return nil, errors.New("must provide the list of the shamir ids of present parties")
	}
	for _, shamirId := range presentParties {
		if !(0 < shamirId || shamirId <= cohortConfig.TotalParties) {
			return nil, errors.Errorf("present party shamir id %d is invalid")
		}
	}
	if len(shamirIdToIdentityKey) != cohortConfig.TotalParties {
		return nil, errors.New("don't have enough mapping for shamir to identity keys as we have parties")
	}
	if publicKey.IsIdentity() {
		return nil, errors.New("public key can't be at infinity")
	}
	if !publicKey.IsOnCurve() {
		return nil, errors.New("public key is not on curve")
	}
	if publicKeyShares == nil {
		return nil, errors.New("publicKeyShares is nil")
	}
	if !publicKey.Equal(publicKeyShares.PublicKey) {
		return nil, errors.New("provided public key is not a match with the one provided in the public key shares")
	}
	return &SignatureAggregator{
		CohortConfig:          cohortConfig,
		PublicKey:             publicKey,
		PublicKeyShares:       publicKeyShares,
		MyIdentityKey:         identityKey,
		PresentParties:        presentParties,
		ShamirIdToIdentityKey: shamirIdToIdentityKey,
		parameters:            parameters,
	}, nil
}

func (sa *SignatureAggregator) Aggregate(partialSignatures map[integration.IdentityKey]*frost.PartialSignature, message []byte, R curves.Point, D_alpha, E_alpha map[integration.IdentityKey]curves.Point) (*frost.Signature, error) {
	if len(D_alpha) != len(sa.PresentParties) {
		return nil, errors.New("length of D_alpha is not equal to S")
	}
	if len(E_alpha) != len(sa.PresentParties) {
		return nil, errors.New("length of D_alpha is not equal to S")
	}
	if R == nil {
		R = sa.CohortConfig.Curve.Point.Identity()
	}
	// This is for TS-SUF-4 in case aggregator was the one computing the R
	if R.IsIdentity() {
		for _, j := range sa.PresentParties {
			currentPartyIdentityKey, exists := sa.ShamirIdToIdentityKey[j]
			if !exists {
				return nil, errors.New("could not find the identity key of current party")
			}
			hasher := sha3.New256()
			if _, err := hasher.Write([]byte(fmt.Sprintf("%d", j))); err != nil {
				return nil, errors.Wrap(err, "could not write present participant into hasher")
			}
			if _, err := hasher.Write(message); err != nil {
				return nil, errors.Wrap(err, "could not write message into hasher")
			}
			for _, D := range D_alpha {
				if _, err := hasher.Write(D.ToAffineCompressed()); err != nil {
					return nil, errors.Wrap(err, "could not write an element of D_alpha into hasher")
				}
			}
			for _, E := range D_alpha {
				if _, err := hasher.Write(E.ToAffineCompressed()); err != nil {
					return nil, errors.Wrap(err, "could not write an element of E_alpha into hasher")
				}
			}

			r_j := sa.CohortConfig.Curve.Scalar.Zero()
			var err error
			if sa.CohortConfig.Curve.Name == curves.ED25519().Name {
				scalar := &curves.ScalarEd25519{}
				r_j, err = scalar.SetBytesClamping(hasher.Sum(nil))
				if err != nil {
					return nil, errors.Wrap(err, "converting hash to r_j failed")
				}
			} else {
				r_j, err = sa.CohortConfig.Curve.Scalar.SetBytes(hasher.Sum(nil))
				if err != nil {
					return nil, errors.Wrap(err, "converting hash to r_j failed")
				}
			}

			D_j, exists := D_alpha[currentPartyIdentityKey]
			if !exists {
				return nil, errors.Errorf("could not find D_j for j=%d")
			}
			E_j, exists := E_alpha[currentPartyIdentityKey]
			if !exists {
				return nil, errors.Errorf("could not find E_j for j=%d")
			}

			R_j := D_j.Add(E_j.Mul(r_j))
			R = R.Add(R_j)
		}
		if R.IsIdentity() {
			return nil, errors.New("R is at infinity")
		}
	}

	// Identifiable Abort is possible
	if sa.PublicKeyShares != nil {
		shamirConfig, err := sharing.NewShamir(uint32(sa.CohortConfig.Threshold), uint32(sa.CohortConfig.TotalParties), sa.CohortConfig.Curve)
		if err != nil {
			return nil, errors.Wrap(err, "could not initialize shamir config")
		}
		sUint32 := make([]uint32, len(sa.PresentParties))
		for i, presentPartyShamirId := range sa.PresentParties {
			sUint32[i] = uint32(presentPartyShamirId)
		}
		lagrangeCoefficients, err := shamirConfig.LagrangeCoeffs(sUint32)
		if err != nil {
			return nil, errors.Wrap(err, "could not compute lagrange coefficients")
		}
		for _, j := range sa.PresentParties {
			currentPartyIdentityKey, exists := sa.ShamirIdToIdentityKey[j]
			if !exists {
				return nil, errors.New("could not find the identity key of current party")
			}
			challengeHasher := sa.CohortConfig.Hash()
			if _, err := challengeHasher.Write(R.ToAffineCompressed()); err != nil {
				return nil, errors.Wrap(err, "could not write R to challenge hasher")
			}
			if _, err := challengeHasher.Write(sa.PublicKey.ToAffineCompressed()); err != nil {
				return nil, errors.Wrap(err, "could not write public key to challenge hasher")
			}
			if _, err := challengeHasher.Write(message); err != nil {
				return nil, errors.Wrap(err, "could not write the message to challenge hasher")
			}
			Y_j, exists := sa.PublicKeyShares.SharesMap[currentPartyIdentityKey]
			if !exists {
				return nil, errors.Errorf("could not find public key share of shamir id %d", j)
			}
			lambda_j, exists := lagrangeCoefficients[uint32(j)]
			if !exists {
				return nil, errors.Errorf("could not find lagrange coefficient of shamir id %d", j)
			}

			z_j, exists := partialSignatures[currentPartyIdentityKey]
			if !exists {
				return nil, errors.Errorf("could not find partial signature from shamir id %d", j)
			}

		}
	}

}
