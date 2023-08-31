# Keygen-CLI

A tool to generate threshold private key shards, public key and print them to stdout.

## Build

Run the following command to build the keygen-cli binary:

```bash
go build internal/keygen/keygen-cli.go
```

## Run

Example:
```bash
./keygen-cli
```
should output:
```bash
2023/08/31 21:19:47 Running with the following parameters:
scheme: ecdsa
protocol: DKLs23
threshold: 2
participants: 3

2023/08/31 21:19:47 Public key: 03d736a4f01fced5d89ac1d9c62c18bdbd0243e11c5ab433c4fba8d6311ab62a69
2023/08/31 21:19:47 Private key shard #1: 3fc7f5359c11b3d5257dfb8144f6a2fa3debeb2e94ec8107aebe45c51f8d5871
2023/08/31 21:19:47 Private key shard #2: 3a1928bebed593a48d21c8c93cce8508116746db2948e072644c2a2929a62d58
2023/08/31 21:19:47 Private key shard #3: 346a5c47e1997373f4c5961134a66715e4e2a287bda53fdd19da0e8d33bf023f
```

You can also specify the parameters as flags:
```bash
./keygen-cli -s ecdsa -p DKLs23 -t 2 -n 3
```

run help command to sho all available flags:
```bash
./keygen-cli -h

A command line tool to generate threshold private key shards, public key and print them to stdout.
Use flags to specify signature scheme, protocol, threshold and number of participants.
For example: ./keygen-cli -s ecdsa -p DKLs23 -t 2 -n 3

Usage:
  keygen-cli [flags]

Flags:
  -h, --help               help for keygen-cli
  -n, --participants int   number of participants (default 3)
  -p, --protocol string    protocol used for key generation (default "DKLs23")
  -s, --scheme string      signature scheme (default "ecdsa")
  -t, --threshold int      threshold for key generation (default 2)
```
