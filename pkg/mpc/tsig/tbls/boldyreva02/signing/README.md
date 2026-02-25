# signing

Threshold BLS signing protocol for Boldyreva scheme.

## Overview

This package implements the signing and aggregation phases of the Boldyreva threshold BLS protocol. Each cosigner produces a partial signature independently, and an aggregator combines them into a full threshold signature.

## Types

- `Cosigner` - A signing participant that holds a shard and produces partial signatures
- `Aggregator` - Combines partial signatures into a threshold signature

## Protocol Flow

1. Create cosigners with `NewShortKeyCosigner` or `NewLongKeyCosigner`
2. Each cosigner calls `ProducePartialSignature(message)` to generate their partial signature
3. Collect partial signatures from a threshold number of cosigners
4. Create an aggregator with `NewShortKeyAggregator` or `NewLongKeyAggregator`
5. Call `Aggregate(partialSigs, message)` to produce the final signature
