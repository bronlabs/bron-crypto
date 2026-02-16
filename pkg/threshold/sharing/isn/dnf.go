package isn

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/bitset"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/errs-go/errs"
)

// DNFName is the human-readable name for the DNF variant of ISN.
const DNFName sharing.Name = "DNF secret sharing scheme"

// DNFScheme implements the Ito-Saito-Nishizeki secret sharing scheme with
// a DNF (Disjunctive Normal Form) access structure. The access structure
// is specified by minimal qualified sets (clauses). Each share is a vector
// with one component per minimal qualified set.
type DNFScheme[E algebra.GroupElement[E]] struct {
	g  algebra.FiniteGroup[E]
	ac sharing.DNFAccessStructure
}

// NewDNFScheme creates a new DNF ISN scheme over the given finite group
// with the specified access structure.
//
// Parameters:
//   - g: The finite group over which secrets and shares are defined
//   - ac: The DNF access structure specifying minimal qualified sets
//
// Returns the initialised scheme.
func NewDNFScheme[E algebra.GroupElement[E]](
	g algebra.FiniteGroup[E],
	ac sharing.DNFAccessStructure,
) *DNFScheme[E] {
	return &DNFScheme[E]{
		g:  g,
		ac: ac,
	}
}

// Name returns the scheme's identifier.
func (*DNFScheme[E]) Name() sharing.Name {
	return DNFName
}

// AccessStructure returns the DNF access structure (minimal qualified sets).
func (d *DNFScheme[E]) AccessStructure() sharing.DNFAccessStructure {
	return d.ac
}

// DealRandom samples a uniformly random secret from the group and splits it
// into shares according to the DNF access structure.
//
// Parameters:
//   - prng: A cryptographically secure random number generator
//
// Returns the dealer output containing all shares, or an error if sampling
// or dealing fails.
func (d *DNFScheme[E]) DealRandom(prng io.Reader) (*DealerOutput[E], error) {
	secretValue, err := d.g.Random(prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not sample random secret")
	}
	secret := NewSecret(secretValue)
	shares, err := d.Deal(secret, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not deal shares for random secret")
	}
	return shares, nil
}

// Deal splits the given secret into shares according to the DNF access structure.
//
// For each minimal qualified set Bk, the algorithm creates an |Bk|-out-of-|Bk|
// additive sharing of the secret among the parties in Bk. Each party receives
// a share vector with m components (where m is the number of minimal qualified
// sets). Component k is the party's piece for clause Bk if the party is in Bk,
// or the group identity element otherwise.
//
// Parameters:
//   - secret: The secret to be shared
//   - prng: A cryptographically secure random number generator
//
// Returns the dealer output containing all shares, or an error if dealing fails.
func (d *DNFScheme[E]) Deal(secret *Secret[E], prng io.Reader) (*DealerOutput[E], error) {
	if prng == nil {
		return nil, ErrIsNil.WithMessage("prng is nil")
	}
	if secret == nil {
		return nil, ErrIsNil.WithMessage("secret is nil")
	}
	shares := make(map[sharing.ID]*Share[E])
	// step 1: initialize each shareholder's share with an empty map
	for p := range d.ac.Shareholders().Iter() {
		shares[p] = &Share[E]{
			id: p,
			v:  make(map[bitset.ImmutableBitSet[sharing.ID]]E),
		}
	}

	// step 2: for each minimal qualified set, create an additive sharing
	for _, Bk := range d.ac {
		// step 2.1
		parties := Bk.List()
		l := len(parties)
		// step 2.2
		if l < 1 {
			return nil, ErrFailed.WithMessage("access structure has an empty minimal qualified set")
		}

		// Create an ℓ-out-of-ℓ additive sharing of s over the parties in Bk
		// step 2.3, 2.4
		rs, err := SumToSecret(secret, prng, l)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not create additive sharing of secret")
		}
		// step 2.5: assign each party's piece to the sparse map
		for j := range l {
			// step 2.5.1: use Bk as the map key
			shares[parties[j]].v[Bk] = rs[j]
		}
	}
	// step 3
	return &DealerOutput[E]{
		shares: hashmap.NewComparableFromNativeLike(shares).Freeze(),
	}, nil
}

// Reconstruct recovers the secret from an authorized set of shares.
//
// The algorithm verifies that the provided shares form an authorized coalition,
// finds a minimal qualified set Bk contained in the coalition, and reconstructs
// the secret by summing the k-th components of all shares in Bk.
//
// Parameters:
//   - shares: Variable number of shares from different shareholders
//
// Returns the reconstructed secret, or an error if the shares are unauthorised,
// incomplete, or invalid.
func (d *DNFScheme[E]) Reconstruct(shares ...*Share[E]) (*Secret[E], error) {
	ids, err := sharing.CollectIDs(shares...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not collect IDs from shares")
	}
	// step 1
	if !d.ac.IsAuthorized(ids...) {
		return nil, ErrUnauthorized.WithMessage("not authorized to reconstruct secret with IDs %v", ids)
	}
	// step 2: find a minimal qualified set Bk contained in the provided coalition
	var qualifiedSet bitset.ImmutableBitSet[sharing.ID]
	found := false
	idSet := bitset.NewImmutableBitSet(ids...)
	for _, Bi := range d.ac {
		if Bi.IsSubSet(idSet) {
			qualifiedSet = Bi
			found = true
			break
		}
	}
	if !found {
		return nil, ErrFailed.WithMessage("could not find a minimal qualified set contained in the provided shares")
	}

	// step 3: reconstruct from the qualified set's components
	sharesMap := make(map[sharing.ID]*Share[E])
	for _, sh := range shares {
		if sh == nil {
			return nil, ErrFailed.WithMessage("nil share provided")
		}
		sharesMap[sh.ID()] = sh
	}

	sHat := d.g.OpIdentity()
	for pid := range qualifiedSet.Iter() {
		pShare, exists := sharesMap[pid]
		if !exists || pShare == nil {
			return nil, ErrFailed.WithMessage("missing share for ID %d", pid)
		}
		// Retrieve value from sparse map; if missing, it's implicitly identity
		val, exists := pShare.v[qualifiedSet]
		if exists {
			sHat = sHat.Op(val)
		}
		// If not exists, val is identity, so Op(identity) doesn't change sHat
	}
	return &Secret[E]{v: sHat}, nil
}
