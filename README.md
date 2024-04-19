<h1 align="center"> Non-Transferable One Time Anonymous Tokens </h1>

<p align="center">
   <a href="https://github.com/bufferhe4d/ntat/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
</p>

**Note: This is an academic prototype and is not ready to be used in production.**

The results of this benchmark is used to Produce Table 4 of our paper.

### Requirements:
- Rust 1.70.0

Please run the following to match the version.

```
rustup default 1.70.0
```

To run the benchmarks:
```
cargo bench
```

### How Table 4 is constructed:
Table 4 has four constructions, namely: NTAT, NTAT w/Pairing, U-Prove and CHAC.

For each construction, the benchmarks output the Client and Server Running Times Separately. They are further decomposed into each interaction.

Example:
Client Issuance running time of NTAT in Table 4 is derived by summing the output of the benchmarks named: "NTAT: Client Query" and "NTAT: Client Finalize Query"

### File Organization:
Each construction has 3 files: client, server and util, followed by the construction name.