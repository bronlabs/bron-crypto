package commitment

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
)

type Type types.Type

type Message types.SchemeElement[Type]
type Witness types.SchemeElement[Type]
type Commitment types.SchemeElement[Type]

type Committer[W Witness, M Message, C Commitment] interface {
	types.Participant[Scheme[W, M, C], Type]
	Commit(message M, prng types.PRNG) (C, W, error)
	CommitWithWitness(message M, W Witness) (C, error)
}

type Verifier[W Witness, M Message, C Commitment] interface {
	types.Participant[Scheme[W, M, C], Type]
	Verify(commitment C, message M, witness W) error
}

type Scheme[W Witness, M Message, C Commitment] interface {
	types.Scheme[Type]
	Committer() Committer[W, M, C]
	Verifier() Verifier[W, M, C]
}

type HomomorphicMessage[M interface {
	Message
	algebra.AbelianGroupElement[M, S]
}, S algebra.IntLike[S]] interface {
	Message
	algebra.AbelianGroupElement[M, S]
}

type HomomorphicWitness[W interface {
	Witness
	algebra.AbelianGroupElement[W, S]
}, S algebra.IntLike[S]] interface {
	Witness
	algebra.AbelianGroupElement[W, S]
}

type HomomorphicCommitment[C interface {
	Commitment
	algebra.AbelianGroupElement[C, S]
}, S algebra.IntLike[S]] interface {
	Commitment
	algebra.AbelianGroupElement[C, S]
}

type HomomorphicScheme[W HomomorphicWitness[W, S], M HomomorphicMessage[M, S], C HomomorphicCommitment[C, S], S algebra.IntLike[S]] Scheme[W, M, C]
