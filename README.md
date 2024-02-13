## Getting Started

### Rust Setup

First, Install rust using the [rustup](https://rustup.rs/) toolchain installer,
then run:

```bash
rustup show
```

### Single Key Delay Encryption - Aggregator

To test our test_aggregate_circuit test code, run

```sh
cargo test test_aggregate_circuit
```

## Bench

To run all benches, run

````bash
cargo bench
````

To run a specific bench, run

```bash
cargo bench --bench $name
````

For example, to run a bench `aggregate` defined in "benches" folder

```bash
cargo bench --bench aggregate
```
