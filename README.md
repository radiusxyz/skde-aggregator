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


The "data" folder is auto-generated according to running the bench file.

Note that, the parameter size depends on the $k$ which has to set bigger than or equal to the minimum degree requirement for creating polynomial. In general, the $k$ is set by subtracting 1 from the number of rows in the table to represent the circuit.



## Result 

- Spec (MacBook pro 16 - 2021)
    - CPU: Apple M1 Pro
    - Memory: 16GB
    - Storage: SSD 1T
$\quad$
- Notation
    - $k$: degree of the poly.
    - $n$: number of sequencers
    - $|\pi |$: proof size
    - $| pk |$: prover key size
    - $| vk |$: verifier key size


### performance of SKDE circuit

| $k$  |   $n$   | proving time | verifying time |  $\|\pi \|$ |  $\|pk\|$ | $\|vk\|$ |
| :--: | :-----: | :----------: | :------------: | :---------: | :-------: | :------: |
|  17  |  2 -  3 |       9.23 s |        4.91 ms |        48KB |   729.9MB |     67KB |
|  18  |  4 -  5 |      18.81 s |        5.32 ms |        48KB |    1.46GB |    133KB |
|  19  |  6 - 10 |      40.56 s |        5.41 ms |        48KB |    2.92GB |    264KB |
|  20  | 11 - 20 |      79.09 s |        5.60 ms |        48KB |    5.48GB |    526KB |

