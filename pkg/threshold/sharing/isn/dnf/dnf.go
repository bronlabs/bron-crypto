package dnf

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/bitset"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/isn"
	"github.com/bronlabs/errs-go/errs"
)

// Name is the human-readable name for the DNF variant of ISN.
const Name sharing.Name = "DNF secret sharing scheme"

// Scheme implements the Ito-Saito-Nishizeki secret sharing scheme with
// a DNF (Disjunctive Normal Form) access structure. The access structure
// is specified by minimal qualified sets (clauses). Each share is a vector
// with one component per minimal qualified set.
type Scheme[E algebra.GroupElement[E]] struct {
	g       algebra.Group[E]
	ac      sharing.DNFAccessStructure
	sampler *isn.Sampler[E]
}

// NewFiniteScheme creates a new DNF ISN scheme over the given group
// with the specified access structure.
//
// Parameters:
//   - g: The group over which secrets and shares are defined
//   - ac: The DNF access structure specifying minimal qualified sets
//
// Returns the initialised scheme.
func NewFiniteScheme[E algebra.GroupElement[E]](
	g algebra.FiniteGroup[E],
	ac sharing.DNFAccessStructure,
) (*Scheme[E], error) {
	sampler, err := isn.NewFiniteGroupElementSampler(g)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create sampler")
	}
	return &Scheme[E]{
		g:       g,
		sampler: sampler,
		ac:      ac,
	}, nil
}

// Name returns the scheme's identifier.
func (*Scheme[E]) Name() sharing.Name {
	return Name
}

// AccessStructure returns the DNF access structure (minimal qualified sets).
func (d *Scheme[E]) AccessStructure() sharing.DNFAccessStructure {
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
func (d *Scheme[E]) DealRandom(prng io.Reader) (*DealerOutput[E], error) {
	secretValue, err := d.sampler.Secret(prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not sample random secret")
	}
	secret := isn.NewSecret(secretValue)
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
func (d *Scheme[E]) Deal(secret *isn.Secret[E], prng io.Reader) (*DealerOutput[E], error) {
	if prng == nil {
		return nil, isn.ErrIsNil.WithMessage("prng is nil")
	}
	if secret == nil {
		return nil, isn.ErrIsNil.WithMessage("secret is nil")
	}
	shares := make(map[sharing.ID]*Share[E])
	// step 1: initialise each shareholder's share with an empty map
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
			return nil, isn.ErrFailed.WithMessage("access structure has an empty minimal qualified set")
		}

		// Create an ℓ-out-of-ℓ additive sharing of s over the parties in Bk
		// step 2.3, 2.4
		rs, err := isn.SumToSecret(secret, d.sampler.Share, prng, l)
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
func (d *Scheme[E]) Reconstruct(shares ...*Share[E]) (*isn.Secret[E], error) {
	ids, err := sharing.CollectIDs(shares...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not collect IDs from shares")
	}
	// step 1
	if !d.ac.IsAuthorized(ids...) {
		return nil, isn.ErrUnauthorized.WithMessage("not authorized to reconstruct secret with IDs %v", ids)
	}
	// step 2: find a minimal qualified set Bk contained in the provided coalition
	var qualifiedSet bitset.ImmutableBitSet[sharing.ID]
	idSet := bitset.NewImmutableBitSet(ids...)
	for _, Bi := range d.ac {
		if Bi.IsSubSet(idSet) {
			qualifiedSet = Bi
			break
		}
	}
	if qualifiedSet == 0 {
		return nil, isn.ErrFailed.WithMessage("could not find a minimal qualified set contained in the provided shares")
	}

	// step 3: reconstruct from the qualified set's components
	sharesMap := make(map[sharing.ID]*Share[E])
	for _, sh := range shares {
		if sh == nil {
			return nil, isn.ErrFailed.WithMessage("nil share provided")
		}
		sharesMap[sh.ID()] = sh
	}

	sHat := d.g.OpIdentity()
	for pid := range qualifiedSet.Iter() {
		pShare, exists := sharesMap[pid]
		if !exists || pShare == nil {
			return nil, isn.ErrFailed.WithMessage("missing share for ID %d", pid)
		}
		// Retrieve value from sparse map; if missing, it's implicitly identity
		val, exists := pShare.v[qualifiedSet]
		if exists {
			sHat = sHat.Op(val)
		}
		// If not exists, val is identity, so Op(identity) doesn't change sHat
	}
	return isn.NewSecret(sHat), nil
}
