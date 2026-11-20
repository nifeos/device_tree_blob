# Fuzz targets of `device_tree_blob`

The targets use cargo-fuzz and need a nightly toolchain. From the repository root:

```sh
cargo install --locked cargo-fuzz
cargo +nightly fuzz list
cargo +nightly fuzz build
```

The weekly workflow does not run them. To run one by hand, give libFuzzer a scratch directory first, so that what it finds does not land among the committed inputs:

```sh
mkdir -p "$TMPDIR/work"
cargo +nightly fuzz run <target> "$TMPDIR/work" corpus/<target>
```

Each `corpus/<target>` directory holds the inputs a run starts from. A crash input is not committed: it becomes a regression test in the crate, beside the code it broke.

`corpus/device_tree_blob_walk` also holds copies of the inputs in `tests/fixtures`.

## `device_tree_blob_walk`

The walkers are where the parser's state lives: a depth counter, two 16-entry per-depth cell-count
stacks, and a slot for the node being walked. Each is indexed by a number the blob controls. A
walker is an unbounded loop over a symbolic blob, which is where bounded model checking stops, so the
Kani harnesses deliberately stay with the leaf readers.

A blob that parses is not a blob that is safe to walk, and the kernel calls every accessor on the
same blob during boot. So the target calls them all. The count grows with the parser; the rule is
that the target tracks the parser's public surface.
