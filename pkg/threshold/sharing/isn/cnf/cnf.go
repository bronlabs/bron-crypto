package cnf

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/bitset"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/isn"
	"github.com/bronlabs/errs-go/errs"
)

// CNFName is the human-readable name for the CNF variant of ISN.
const CNFName sharing.Name = "CNF secret sharing scheme"

// CNFScheme implements the Ito-Saito-Nishizeki secret sharing scheme with
// a CNF (Conjunctive Normal Form) access structure. The access structure
// is specified by maximal unqualified sets (clauses). Each share is a vector
// with one component per maximal unqualified set.
type CNFScheme[E algebra.GroupElement[E]] struct {
	g  algebra.FiniteGroup[E]
	ac sharing.CNFAccessStructure
}

// NewCNFScheme creates a new CNF ISN scheme over the given finite group
// with the specified access structure.
//
// Parameters:
//   - g: The finite group over which secrets and shares are defined
//   - ac: The CNF access structure specifying maximal unqualified sets
//
// Returns the initialised scheme.
func NewCNFScheme[E algebra.GroupElement[E]](
	g algebra.FiniteGroup[E],
	ac sharing.CNFAccessStructure,
) *CNFScheme[E] {
	return &CNFScheme[E]{
		g:  g,
		ac: ac,
	}
}

// Name returns the scheme's identifier.
func (*CNFScheme[E]) Name() sharing.Name {
	return CNFName
}

// AccessStructure returns the CNF access structure (maximal unqualified sets).
func (c *CNFScheme[E]) AccessStructure() sharing.CNFAccessStructure {
	return c.ac
}

// DealRandom samples a uniformly random secret from the group and splits it
// into shares according to the CNF access structure.
//
// Parameters:
//   - prng: A cryptographically secure random number generator
//
// Returns the dealer output containing all shares, or an error if sampling
// or dealing fails.
func (c *CNFScheme[E]) DealRandom(prng io.Reader) (*DealerOutput[E], error) {
	secretValue, err := c.g.Random(prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not sample random secret")
	}
	secret := isn.NewSecret(secretValue)
	shares, err := c.Deal(secret, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not deal shares for random secret")
	}
	return shares, nil
}

// Deal splits the given secret into shares according to the CNF access structure.
//
// The algorithm creates an ℓ-out-of-ℓ additive sharing of the secret into
// pieces r1,...,rℓ (where ℓ is the number of maximal unqualified sets). Each
// party p receives a share vector with ℓ components, where component j is rj
// if p is not in maximal unqualified set Tj, or the group identity element
// if p is in Tj.
//
// Parameters:
//   - secret: The secret to be shared
//   - prng: A cryptographically secure random number generator
//
// Returns the dealer output containing all shares, or an error if dealing fails.
func (c *CNFScheme[E]) Deal(secret *isn.Secret[E], prng io.Reader) (*DealerOutput[E], error) {
	if prng == nil {
		return nil, isn.ErrIsNil.WithMessage("prng is nil")
	}
	if secret == nil {
		return nil, isn.ErrIsNil.WithMessage("secret is nil")
	}
	l := len(c.ac) // number of maximal unqualified sets / clauses
	if l == 0 {
		return nil, isn.ErrFailed.WithMessage("access structure has no maximal unqualified sets")
	}

	shares := make(map[sharing.ID]*Share[E])

	// step 1: initialise each shareholder's share with an empty map
	for p := range c.ac.Shareholders().Iter() {
		shares[p] = &Share[E]{
			id: p,
			v:  make(map[bitset.ImmutableBitSet[sharing.ID]]E),
		}
	}

	// step 2: create an ℓ-out-of-ℓ additive sharing of s into pieces r1..rℓ
	rs, err := isn.SumToSecret(secret, prng, l)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create additive sharing of secret")
	}

	// step 3: distribute: party p gets piece rj (with key Tj) iff p ∉ Tj
	for j, Tj := range c.ac {
		// step 3.1: assign piece rj to all parties not in Tj
		for p := range c.ac.Shareholders().Iter() {
			// step 3.1.1: if p is not in Tj, store rj in sparse map
			if !Tj.Contains(p) {
				// step 3.1.1.1
				shares[p].v[Tj] = rs[j]
			}
		}
	}

	// step 4: return shares
	return &DealerOutput[E]{
		shares: hashmap.NewComparableFromNativeLike(shares).Freeze(),
	}, nil
}

// Reconstruct recovers the secret from an authorized set of shares.
//
// The algorithm verifies that the provided shares form an authorized coalition.
// For each maximal unqualified set Tj, it finds a party in the coalition that
// is not in Tj and extracts piece rj from that party's share. The secret is
// reconstructed by summing all pieces r1 + r2 + ... + rℓ.
//
// Parameters:
//   - shares: Variable number of shares from different shareholders
//
// Returns the reconstructed secret, or an error if the shares are unauthorised,
// incomplete, or invalid.
func (c *CNFScheme[E]) Reconstruct(shares ...*Share[E]) (*isn.Secret[E], error) {
	ids, err := sharing.CollectIDs(shares...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not collect IDs from shares")
	}
	// step 1
	if !c.ac.IsAuthorized(ids...) {
		return nil, isn.ErrUnauthorized.WithMessage("not authorized to reconstruct secret with IDs %v", ids)
	}

	idSet := bitset.NewImmutableBitSet(ids...)
	sharesMap := make(map[sharing.ID]*Share[E])
	for _, sh := range shares {
		if sh == nil {
			return nil, isn.ErrFailed.WithMessage("nil share provided")
		}
		sharesMap[sh.ID()] = sh
	}

	// step 2 & 3: for each maximal unqualified set, find a party outside it and collect pieces
	sHat := c.g.OpIdentity()
	for _, Tj := range c.ac {
		rj := c.g.OpIdentity() // default to identity if piece is missing (should not happen for authorized coalition)
		// Find any party in the coalition that is not in Tj
		for pid := range idSet.Iter() {
			if Tj.Contains(pid) {
				continue
			}
			sh, ok := sharesMap[pid]
			if !ok || sh == nil {
				return nil, isn.ErrFailed.WithMessage("missing share for ID %d", pid)
			}
			val, exists := sh.v[Tj]
			if !exists {
				return nil, isn.ErrFailed.WithMessage("share for ID %d does not contain piece for maximal unqualified set %v", pid, Tj.List())
			}
			rj = val
			break
		}
		if rj.IsOpIdentity() {
			return nil, isn.ErrFailed.WithMessage("could not find a party outside maximal unqualified set %v", Tj.List())
		}
		sHat = sHat.Op(rj)
	}
	return isn.NewSecret(sHat), nil
}
