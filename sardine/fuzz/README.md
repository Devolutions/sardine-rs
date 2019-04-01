The fuzzers use cargo-fuzz. The setup instructions can be found in https://fuzz.rs/book/cargo-fuzz/setup.html.

To list the fuzzers, use:

`cargo +nightly fuzz list`

To run a fuzzer, use "fuzz run":

`cargo +nightly fuzz run fuzz_basic_auth`