# zkOracles Protocol

## Specification
To read the specification of zkOracles locally, you should first run the following instructions.
> cargo install mdbook

> cargo install mdbook-katex

Then go to the `doc` directory, and run the following instruction.
> mdbook serve --open

## Run Demo
You could run a demo in two terminals as follows. The inputs of two parties are hardcore in the code [here](twopc/examples/demo.rs).

In one terminal, run
> cargo run --example demo -- --is-server 1

In another terminal, run
> cargo run --example demo -- --is-server 0

