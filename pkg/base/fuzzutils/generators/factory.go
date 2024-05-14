package generators

import randv2 "math/rand/v2"

type GeneratorFactory[T any] interface {
	New(prng randv2.Source) Generator[T]
}
