package commitment

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/groups"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
)

type Type types.Type

type Message any
type Witness any
type Opening[W Witness] interface {
	Witness() W
}
type Commitment any

type Committer[W Witness, M Message, C Commitment] interface {
	types.Participant[Type]
	Commit(message M, prng types.PRNG) (C, W, error)
	CommitWithWitness(message M, W W) (C, error)
}

type Verifier[W Witness, O Opening[W], M Message, C Commitment] interface {
	types.Participant[Type]
	Verify(commitment C, message M, opening O) error
}

type Scheme[W Witness, O Opening[W], M Message, C Commitment] interface {
	types.Scheme[Type]
	Committer() Committer[W, M, C]
	Verifier() Verifier[W, O, M, C]
}

// ******** Homomorphic

type Homomorphic[TV groups.GroupElement[TV]] types.Transparent[TV]
type AdditivelyHomomorphic[TV groups.GroupElement[TV]] Homomorphic[TV]
type MultiplicativelyHomomorphic[TV groups.GroupElement[TV]] Homomorphic[TV]

type HomomorphicScheme[
	W interface {
		Witness
		Homomorphic[WT]
	}, WT groups.GroupElement[WT],
	O Opening[W],
	M interface {
		Message
		Homomorphic[MT]
	}, MT groups.GroupElement[MT],
	C interface {
		Commitment
		Homomorphic[CT]
	}, CT groups.GroupElement[CT],
] Scheme[W, O, M, C]
