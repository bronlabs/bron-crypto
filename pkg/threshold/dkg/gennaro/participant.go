package gennaro

import (
	"fmt"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	pedcom "github.com/bronlabs/bron-crypto/pkg/commitments/pedersen"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/pedersen"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/shamir"
	ts "github.com/bronlabs/bron-crypto/pkg/transcripts"
)

type (
	ScalarField[S Scalar[S]]               = algebra.PrimeField[S]
	Scalar[S algebra.PrimeFieldElement[S]] = algebra.PrimeFieldElement[S]

	Group[E GroupElement[E, S], S Scalar[S]]                     = algebra.PrimeGroup[E, S]
	GroupElement[E algebra.PrimeGroupElement[E, S], S Scalar[S]] = algebra.PrimeGroupElement[E, S]

	DKGOutput[
		E GroupElement[E, S], S Scalar[S],
	] struct {
		DKGPublicOutput[E, S]

		share *feldman.Share[S]
	}

	DKGPublicOutput[
		E GroupElement[E, S], S Scalar[S],
	] struct {
		publicKeyValue         E
		partialPublicKeyValues ds.Map[sharing.ID, E]
		fv                     feldman.VerificationVector[E, S]
		accessStructure        *shamir.AccessStructure
	}
)

const (
	transcriptLabel = "BRON_CRYPTO_DKG_GENNARO-"
)

type Participant[E GroupElement[E, S], S Scalar[S]] struct {
	sid   network.SID
	ac    *shamir.AccessStructure
	id    sharing.ID
	tape  ts.Transcript
	prng  io.Reader
	state *State[E, S]
	round network.Round
}

func (p *Participant[E, S]) SharingID() sharing.ID {
	return p.id
}

func (p *Participant[E, S]) AccessStructure() *shamir.AccessStructure {
	return p.ac
}

type State[E GroupElement[E, S], S Scalar[S]] struct {
	key         *pedcom.Key[E, S]
	pedersenVSS *pedersen.Scheme[E, S]
	feldmanVSS  *feldman.Scheme[E, S]

	receivedPedersenVerificationVectors ds.MutableMap[sharing.ID, pedersen.VerificationVector[E, S]]
	receivedFeldmanVerificationVectors  ds.MutableMap[sharing.ID, feldman.VerificationVector[E, S]]

	localPedersenDealerOutput      *pedersen.DealerOutput[E, S]
	pedersenDealerFunc             *pedersen.DealerFunc[S]
	localFeldmanVerificationVector feldman.VerificationVector[E, S]
	localSecret                    *pedersen.Secret[S]
	localShare                     *pedersen.Share[S]
}

func NewParticipant[E GroupElement[E, S], S Scalar[S]](
	sid network.SID,
	group Group[E, S],
	myID sharing.ID,
	ac *shamir.AccessStructure,
	tape ts.Transcript,
	prng io.Reader,
) (*Participant[E, S], error) {
	if group == nil {
		return nil, errs.NewIsNil("group")
	}
	if tape == nil {
		return nil, errs.NewIsNil("tape")
	}
	if prng == nil {
		return nil, errs.NewIsNil("prng")
	}
	if ac == nil {
		return nil, errs.NewIsNil("access structure")
	}
	if !ac.Shareholders().Contains(myID) {
		return nil, errs.NewArgument("myID is not a shareholder in the access structure")
	}
	dst := fmt.Sprintf("%s-%d-%s", transcriptLabel, sid, group.Name())
	tape.AppendDomainSeparator(dst)

	h, err := ts.Extract(tape, "second generator of pedersen key", group)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to extract second generator for pedersen key")
	}
	key, err := pedcom.NewCommitmentKey(group.Generator(), h)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create pedersen key")
	}
	pedersenVSS, err := pedersen.NewScheme(key, ac.Threshold(), ac.Shareholders())
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create pedersen VSS scheme")
	}
	feldmanVSS, err := feldman.NewScheme(key.G(), ac.Threshold(), ac.Shareholders())
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create feldman VSS scheme")
	}
	return &Participant[E, S]{
		sid:  sid,
		tape: tape,
		prng: prng,
		id:   myID,
		ac:   ac,
		state: &State[E, S]{
			key:                                 key,
			pedersenVSS:                         pedersenVSS,
			feldmanVSS:                          feldmanVSS,
			receivedPedersenVerificationVectors: hashmap.NewComparable[sharing.ID, pedersen.VerificationVector[E, S]](),
			receivedFeldmanVerificationVectors:  hashmap.NewComparable[sharing.ID, feldman.VerificationVector[E, S]](),
		},
		round: 1,
	}, nil
}

func NewDKGOutput[E GroupElement[E, S], S Scalar[S]](
	share *feldman.Share[S],
	vector feldman.VerificationVector[E, S],
	accessStructure *shamir.AccessStructure,
) (*DKGOutput[E, S], error) {
	if share == nil {
		return nil, errs.NewIsNil("share")
	}
	if vector == nil {
		return nil, errs.NewIsNil("verification vector")
	}
	if accessStructure == nil {
		return nil, errs.NewIsNil("accessStructure")
	}
	sf, ok := share.Value().Structure().(ScalarField[S])
	if !ok {
		return nil, errs.NewType("share value structure is not a scalar field")
	}
	publicKeyValue := vector.Eval(sf.Zero())
	partialPublicKeys, err := ComputePartialPublicKey(sf, share, vector, accessStructure)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to compute partial public keys from share")
	}
	return &DKGOutput[E, S]{
		share: share,
		DKGPublicOutput: DKGPublicOutput[E, S]{
			publicKeyValue:         publicKeyValue,
			partialPublicKeyValues: partialPublicKeys,
			fv:                     vector,
			accessStructure:        accessStructure,
		},
	}, nil
}

func (o *DKGOutput[E, S]) Share() *feldman.Share[S] {
	if o == nil {
		return nil
	}
	return o.share
}

func (o *DKGOutput[E, S]) PublicMaterial() *DKGPublicOutput[E, S] {
	if o == nil {
		return nil
	}
	return &DKGPublicOutput[E, S]{
		publicKeyValue:         o.publicKeyValue,
		partialPublicKeyValues: o.partialPublicKeyValues,
		fv:                     o.fv,
		accessStructure:        o.accessStructure,
	}
}

func (o *DKGPublicOutput[E, S]) PublicKeyValue() E {
	return o.publicKeyValue
}

func (o *DKGPublicOutput[E, S]) PartialPublicKeyValues() ds.Map[sharing.ID, E] {
	if o == nil {
		return nil
	}
	return o.partialPublicKeyValues
}

func (o *DKGPublicOutput[E, S]) AccessStructure() *shamir.AccessStructure {
	if o == nil {
		return nil
	}
	return o.accessStructure
}

func (o *DKGPublicOutput[E, S]) VerificationVector() feldman.VerificationVector[E, S] {
	if o == nil {
		return nil
	}
	return o.fv
}
