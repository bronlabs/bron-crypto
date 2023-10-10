# Threshold BLS (GLOW)

This package implements threshold BLS using [GLOW20](https://eprint.iacr.org/2020/096.pdf). The output signature is verifiable with [official spec](https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html).


The protocol only works for the following scheme:

- **Short public keys, long signatures**: Signatures are longer and slower to create, verify, and aggregate but public keys are small and fast to aggregate. Used when signing and verification operations not computed as often or for minimizing storage or bandwidth for public keys.

The output signature can be incorporated in a multisignature protocol requiring the `basic` rogue key prevention scheme.


## Remark

This protocol should only be used where such speed optimization is actually needed.

Also, we have used the non UC-secure dleq proof implementation for this protocol, since relative aggregation performance is the objective. For almost all use-cases, the randomized Fischlin variant of Chaum-Pedersen proof must be used.

## Benchmark

The aggregation phase of this protocol is around **3 times faster** than our more general Boldyreva02 implementation in the same scheme. It is faster because it uses Chaum-Pedersen DLEQ proof with Fiat-Shamir instead of verifying individual POPs which require pairings.

For GLOW:
```
Benchmark_Combine-10                  14          72459464 ns/op
```

For Boldyreva02[G1, G2]:

```
Benchmark_Combine/short_keys-10                5         216142500 ns/op
```

## Remark

Since aggregation speed is the objective of this protocol, we have used the version of Chaum-Pedersen proof that's made non-interactive with Fiat-Shamir. In case such optimization is needed, use Boldyreva02.
