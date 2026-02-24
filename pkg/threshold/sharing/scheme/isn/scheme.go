package isn

import (
	"io"
	"maps"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/bitset"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/iterutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/scheme/additive"
	"github.com/bronlabs/errs-go/errs"
)

// Scheme implements the Ito-Saito-Nishizeki secret sharing scheme with
// a monotone access structure represented via maximal unqualified sets.
// Each share is a vector with one component per maximal unqualified set.
type Scheme[E algebra.GroupElement[E]] struct {
	g       algebra.Group[E]
	sampler *sampler[E]
	ac      sharing.MonotoneAccessStructure
}

// NewFiniteScheme creates a new ISN scheme over the given finite group
// with the specified access structure.
//
// Parameters:
//   - g: The finite group over which secrets and shares are defined
//   - ac: The monotone access structure specifying maximal unqualified sets
//
// Returns the initialised scheme.
func NewFiniteScheme[E algebra.GroupElement[E]](
	g algebra.FiniteGroup[E],
	ac sharing.MonotoneAccessStructure,
) (*Scheme[E], error) {
	if ac == nil {
		return nil, sharing.ErrIsNil.WithMessage("access structure is nil")
	}

	sampler, err := newFiniteGroupElementSampler(g)
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

// AccessStructure returns the scheme access structure.
func (c *Scheme[E]) AccessStructure() sharing.MonotoneAccessStructure {
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
func (c *Scheme[E]) DealRandom(prng io.Reader) (*DealerOutput[E], *Secret[E], error) {
	do, secret, _, err := c.DealRandomAndRevealDealerFunc(prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not deal random shares")
	}
	return do, secret, nil
}

// DealRandomAndRevealDealerFunc samples a uniformly random secret from the group,
// splits it into shares according to the CNF access structure, and reveals the
// dealer function. This is part of the LSSS interface.
//
// Parameters:
//   - prng: A cryptographically secure random number generator
//
// Returns:
//   - The dealer output containing all shares
//   - The randomly generated secret
//   - The dealer function mapping shareholder IDs to shares
//   - An error if sampling or dealing fails
func (c *Scheme[E]) DealRandomAndRevealDealerFunc(prng io.Reader) (*DealerOutput[E], *Secret[E], DealerFunc[E], error) {
	secretValue, err := c.sampler.Secret(prng)
	if err != nil {
		return nil, nil, nil, errs.Wrap(err).WithMessage("could not sample random secret")
	}
	secret := NewSecret(secretValue)
	shares, dealerFunc, err := c.DealAndRevealDealerFunc(secret, prng)
	if err != nil {
		return nil, nil, nil, errs.Wrap(err).WithMessage("could not deal shares for random secret")
	}
	return shares, secret, dealerFunc, nil
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
func (c *Scheme[E]) Deal(secret *Secret[E], prng io.Reader) (*DealerOutput[E], error) {
	do, _, err := c.DealAndRevealDealerFunc(secret, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not deal shares")
	}
	return do, nil
}

// DealAndRevealDealerFunc splits the given secret into shares according to the
// CNF access structure and reveals the dealer function. This is part of the
// LSSS interface and enables protocols that require knowledge of the complete
// share distribution.
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
// Returns:
//   - The dealer output containing all shares
//   - The dealer function mapping shareholder IDs to shares
//   - An error if dealing fails
func (c *Scheme[E]) DealAndRevealDealerFunc(secret *Secret[E], prng io.Reader) (*DealerOutput[E], DealerFunc[E], error) {
	if prng == nil {
		return nil, nil, sharing.ErrIsNil.WithMessage("prng is nil")
	}
	if secret == nil {
		return nil, nil, sharing.ErrIsNil.WithMessage("secret is nil")
	}
	clauses := c.clauses()
	l := len(clauses) // number of maximal unqualified sets / clauses
	if l == 0 {
		return nil, nil, sharing.ErrFailed.WithMessage("access structure has no maximal unqualified sets")
	}

	// step 2: create an ℓ-out-of-ℓ additive sharing of s into pieces r1..rℓ
	rs, err := additive.SumToSecret(secret.Value(), c.sampler.Share, prng, l)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not create additive sharing of secret")
	}
	dealerFunc := make(DealerFunc[E])
	for i, clause := range clauses {
		dealerFunc[clause] = rs[i]
	}

	// step 3: distribute: party p gets piece rj (with key Tj) iff p ∉ Tj
	shares := hashmap.NewComparable[sharing.ID, *Share[E]]()
	for id := range c.ac.Shareholders().Iter() {
		shares.Put(id, dealerFunc.ShareOf(id))
	}

	// step 4: return shares
	output := &DealerOutput[E]{shares: shares.Freeze()}
	return output, dealerFunc, nil
}

// Reconstruct recovers the secret from an authorized set of shares.
//
// The algorithm verifies that the provided shares form an authorized coalition
// and shares are consistent.
// For each maximal unqualified set it finds parties in the coalition that
// are not in the set and extracts pieces from that parties' shares checking
// if they are the same. The secret is
// reconstructed by summing all pieces r1 + r2 + ... + rℓ.
//
// Parameters:
//   - shares: Variable number of shares from different shareholders
//
// Returns the reconstructed secret, or an error if the shares are unauthorised,
// incomplete, invalid, or inconsistent.
func (c *Scheme[E]) Reconstruct(shares ...*Share[E]) (*Secret[E], error) {
	ids, err := sharing.CollectIDs(shares...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not collect IDs from shares")
	}
	if !c.ac.IsQualified(ids...) {
		return nil, sharing.ErrUnauthorized.WithMessage("not authorized to reconstruct secret with IDs %v", ids)
	}

	clauses := c.clauses()
	chunks := make(map[bitset.ImmutableBitSet[sharing.ID]]E)
	for _, share := range shares {
		if share == nil {
			return nil, sharing.ErrFailed.WithMessage("nil share provided")
		}

		for _, maxUnqualifiedSet := range clauses {
			if maxUnqualifiedSet.Contains(share.id) {
				continue
			}

			chunk, ok := share.v[maxUnqualifiedSet]
			if !ok || utils.IsNil(chunk) {
				return nil, sharing.ErrFailed.WithMessage("share for ID %d does not contain piece for maximal unqualified set %v", share.id, maxUnqualifiedSet.List())
			}
			if refChunk, contains := chunks[maxUnqualifiedSet]; contains {
				if !refChunk.Equal(chunk) {
					return nil, sharing.ErrFailed.WithMessage("inconsistent shares")
				}
			} else {
				chunks[maxUnqualifiedSet] = chunk
			}
		}
	}

	return NewSecret(iterutils.Reduce(maps.Values(chunks), c.g.OpIdentity(), E.Op)), nil
}

// ShareToAdditiveShare converts this Shamir share to an additive share by multiplying
// by the appropriate Lagrange coefficient. The resulting additive shares can
// be summed to reconstruct the secret.
func (*Scheme[E]) ShareToAdditiveShare(s *Share[E], quorum *sharing.UnanimityAccessStructure) (*additive.Share[E], error) {
	return s.ToAdditive(quorum)
}

func (c *Scheme[E]) clauses() []bitset.ImmutableBitSet[sharing.ID] {
	clausesCount := 0
	for range c.ac.MaximalUnqualifiedSetsIter() {
		clausesCount++
	}

	clauses := make([]bitset.ImmutableBitSet[sharing.ID], 0, clausesCount)
	for set := range c.ac.MaximalUnqualifiedSetsIter() {
		clauses = append(clauses, bitset.NewImmutableBitSet(set.List()...))
	}
	return clauses
}

// sampler provides functions to sample secrets and shares for ISN schemes. It abstracts the randomness source and allows for flexible sampling strategies.
type sampler[E algebra.GroupElement[E]] struct {
	secrets func(io.Reader) (E, error)
	shares  func(io.Reader) (E, error)
}

// newFiniteGroupElementSampler creates a new sampler for secrets and shares based on the random sampling function of a finite group. It returns an error if the provided group is nil.
func newFiniteGroupElementSampler[E algebra.GroupElement[E]](g algebra.FiniteGroup[E]) (*sampler[E], error) {
	if g == nil {
		return nil, sharing.ErrIsNil.WithMessage("group is nil")
	}
	return &sampler[E]{
		secrets: g.Random,
		shares:  g.Random,
	}, nil
}

func (s *sampler[E]) Secret(prng io.Reader) (E, error) {
	return s.secrets(prng)
}

func (s *sampler[E]) Share(prng io.Reader) (E, error) {
	return s.shares(prng)
}
