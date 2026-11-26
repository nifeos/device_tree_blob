# Changelog

Dates are UTC. One line per release, what changed and why, so a reader of the diff has the
sentence beside it.

## Unreleased

- First version.
- A lookup reads a property name from inside the strings block alone, as the specification and
  libfdt read one. The header must place the block (`size_dt_strings` bytes) inside the blob. A
  name offset at or past the block's end is `Truncated`. A name with no terminating zero byte
  inside the block is `BadValue`.
- `from_bytes` walks the reservation block and the whole structure block once and refuses a blob
  that is not one tree, so every lookup answers an accepted blob the same way. A lookup then fails
  only on the shape of a value it reads or a full output slice.
- A lookup by name takes the whole name or the name before its unit address. `b"serial"` no
  longer names `serial-bus`, and an empty name names no node. A caller that passed `b"x@"` passes
  `b"x"`.
- `node_properties` refuses a full output slice with `TooManyRegions`, as the region lookups do.
- `root`, `nodes` and `find_node` hand out a `Node`, which walks its `children` and `properties`
  and reads one `property`, so a caller can visit the whole tree.
- `Region` is `#[non_exhaustive]`, gains `Region::new`, `Default`, `PartialOrd`, `Ord` and `Hash`,
  and `DeviceTreeBlob` is `Copy`, with a `Debug` that prints the layout and not the bytes.
- `from_pointer` states in full what its caller promises: the bytes are readable and nothing
  writes them for as long as the tree lives.
- Each walk reads a property name only when a lookup compares it, which takes about 30 percent off
  a lookup that finds nothing on the fixtures.
- Every public function has an example and says which errors it returns.
- The package ships the source, the tests and their fixtures, and the documents, without the
  repository's tooling.

## BUGS

- The template's lag check guards the CI pin, not this file; a change that matters to a user of
  the crate belongs in a release line here.
