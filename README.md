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
    <!-- - $| g |$: bit-size of the base in $g^T$
    - $| T |$: bit-size of the exponent in $g^T$ -->
    - $|\pi |$: proof size
    - $| pk |$: prover key size
    - $| vk |$: verifier key size


### performance of SKDE circuit

| $k$ |   $n$  | proving time | verifying time | $\|\pi \|$ | $\|pk\|$ | $\|vk\|$ |
| :-: | :----: | :----------: | :------------: | :--------: | :------: | :------: |
|  17 |      3 |      45.12 s |       30.00 ms |       138K |   901.8M |       7K |
|  18 |      4 |     103.49 s |       49.80 ms |       166K |    2.24G |       8K |
|  18 |      7 |     159.50 s |       50.80 ms |       251K |    3.55G |      13K |
|  19 |      8 |     497.82 s s |     58.23 ms |       279K |    7.97G |      15K |
|  19 |     13 |      s |      ms |       K |     M |     K |
|  20 |     14 |      s |      ms |       K |     M |     K |
|  20 |     26 |      s |      ms |       K |     M |     K |


<!-- ### performance of modulo power circuit

| $k$ | advice |  fixed | $\|g \|$ | $\|T\|$ | proving time | verifying time | $\|\pi \|$ | $\|pk\|$ | $\|vk\|$ |
| :-: | :----: | :----: | :------: | :-----: | :----------: | :------------: | :--------: | :------: | :------: |
|  15 |  17822 |  17822 | 2048-bit |   2-bit |     1.9365 s |      3.6873 ms |       286K |     138M |     9.3K |
|  15 |  25803 |  25803 | 2048-bit |   3-bit |     2.0866 s |      3.8051 ms |       286K |     138M |     9.3K |
|  16 |  33784 |  33784 | 2048-bit |   4-bit |     3.4051 s |      3.4529 ms |       281K |     276M |      17K |
|  16 |  41766 |  41766 | 2048-bit |   5-bit |     3.5665 s |      3.5643 ms |       281K |     276M |      17K |
|  16 |  49747 |  49747 | 2048-bit |   6-bit |     3.5869 s |      3.4665 ms |       281K |     276M |      17K |
|  16 |  57728 |  57728 | 2048-bit |   7-bit |     3.7930 s |      3.5109 ms |       281K |     276M |      17K |
|  17 |  65709 |  65709 | 2048-bit |   8-bit |     6.2824 s |      3.4320 ms |       281K |     276M |      17K |
|  17 | 121578 | 121578 | 2048-bit |  15-bit |     7.0485 s |      3.4704 ms |       281K |     552M |      33K |
|  17 | 129559 | 129559 | 2048-bit |  16-bit |     7.1383 s |      3.6634 ms |       281K |     552M |      33K |
|  18 | 137541 | 137541 | 2048-bit |  17-bit |     11.897 s |      3.4222 ms |       281K |     1.1G |      65K |
|  18 | 249278 | 249278 | 2048-bit |  31-bit |     13.601 s |      3.5342 ms |       281K |     1.1G |      65K |
|  18 | 257259 | 257259 | 2048-bit |  32-bit |     13.724 s |      3.4590 ms |       281K |     1.1G |      65K |
|  19 | 265241 | 265241 | 2048-bit |  33-bit |     23.828 s |      3.4100 ms |       281K |     2.2G |     129K | -->
