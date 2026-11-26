# Changelog

Dates are UTC. One line per release, what changed and why, so a reader of the diff has the
sentence beside it.

## Unreleased

- First version.
- A property name is looked up inside the strings block alone, as the specification and libfdt
  read one: the header must place the block (`size_dt_strings` bytes) inside the blob, a name
  offset at or past the block's end is `Truncated`, and a name with no terminating zero byte
  inside the block is `BadValue`.

## BUGS

- The template's lag check guards the CI pin, not this file; a change that matters to a user of
  the crate belongs in a release line here.
