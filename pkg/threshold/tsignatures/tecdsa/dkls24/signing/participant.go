package signing

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/przs/sample"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24/mult"
)

type Participant struct {
	types.BaseParticipant[types.ThresholdSignatureProtocol]

	types.ThresholdSignatureParticipant

	Shard         *dkls24.Shard
	SharingConfig types.SharingConfig
}

// Multiplication contains corresponding participant objects for pairwise multiplication subProtocols.
type Multiplication struct {
	Alice *mult.Alice
	Bob   *mult.Bob

	_ ds.Incomparable
}

type SubProtocols struct {
	// use to get the secret key mask (zeta_i)
	ZeroShareSampling *sample.Participant
	// pairwise multiplication protocol i.e. each party acts as alice and bob against every party
	Multiplication ds.Map[types.IdentityKey, *Multiplication]

	_ ds.Incomparable
}

type SignerState struct {
	Phi_i                          curves.Scalar
	Sk_i                           curves.Scalar
	R_i                            curves.Scalar
	Zeta_i                         curves.Scalar
	BigR_i                         curves.Point
	Pk_i                           curves.Point
	Cu_i                           map[types.SharingID]curves.Scalar
	Cv_i                           map[types.SharingID]curves.Scalar
	Du_i                           map[types.SharingID]curves.Scalar
	Dv_i                           map[types.SharingID]curves.Scalar
	Psi_i                          map[types.SharingID]curves.Scalar
	Chi_i                          map[types.SharingID]curves.Scalar
	InstanceKeyWitness             map[types.SharingID]commitments.Witness
	ReceivedInstanceKeyCommitments map[types.SharingID]commitments.Commitment
	ReceivedBigR_i                 ds.Map[types.IdentityKey, curves.Point]
	Protocols                      *SubProtocols

	_ ds.Incomparable
}
