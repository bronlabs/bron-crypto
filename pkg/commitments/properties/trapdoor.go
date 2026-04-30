package properties

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"pgregory.net/rapid"
)

type (
	TrapdoorKeyGenerator[K commitments.TrapdoorKey[K, M, W, C], M commitments.Message, W commitments.Witness, C commitments.Commitment[C]]                                 = rapid.Generator[K]
	HomomorphicTrapdoorKeyGenerator[K commitments.HomomorphicTrapdoorKey[K, M, W, C, S], M commitments.Message, W commitments.Witness, C commitments.Commitment[C], S any] = rapid.Generator[K]
	GroupHomomorphicTrapdoorKeyGenerator[
		K commitments.GroupHomomorphicTrapdoorKey[K, M, MG, MV, W, WG, WV, C, CG, CV, S],
		M interface {
			commitments.Message
			base.Transparent[MV]
		}, MG algebra.Group[MV], MV algebra.GroupElement[MV],
		W interface {
			commitments.Witness
			base.Transparent[WV]
		}, WG algebra.Group[WV], WV algebra.GroupElement[WV],
		C interface {
			commitments.Commitment[C]
			base.Transparent[CV]
		}, CG algebra.FiniteGroup[CV], CV algebra.GroupElement[CV],
		S any,
	] = rapid.Generator[K]
)
