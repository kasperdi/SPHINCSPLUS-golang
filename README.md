# SPHINCSPLUS-golang

This repository contains an implementation of the SPHINCS<sup>+</sup> signature framework as described in https://sphincs.org/data/sphincs+-round3-specification.pdf.

Test vectors for WOTS<sup>+</sup>, FORS, and SPHINCS<sup>+</sup> can be found in their respective folders. The tests themselves can be found in the Go test files, while the expected signatures can then be found in the expected_signature folders. The test vectors cover the 24 named variants described in the specification that are instantiated using either SHA-256 or SHAKE256. The test that checks if the output matches the expected signature is called testSignFixed, and it is a subtest that is run for each of the named variants.
