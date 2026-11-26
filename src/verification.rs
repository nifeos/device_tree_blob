use super::*;

/// Enough bytes to place a `be64` read at a few different offsets.
const N: usize = 12;

/// Falsification: replayable `falsifications/verification.be32_is_total.patch`
/// **`be32` is total: no offset panics.** For any bytes and any offset, `be32` returns `Ok` or
/// `Err(Truncated)`, never panicking, even at `usize::MAX` where the old `at + 4` would have
/// wrapped. This is the hardening proved.
#[kani::proof]
fn be32_is_total() {
    let bytes: [u8; N] = kani::any();
    let at: usize = kani::any();
    let _ = be32(&bytes, at);
}

/// Falsification: replayable `falsifications/verification.be64_is_total.patch`
/// **`be64` is total: no offset panics.** As `be32`, for the 8-byte read.
#[kani::proof]
fn be64_is_total() {
    let bytes: [u8; N] = kani::any();
    let at: usize = kani::any();
    let _ = be64(&bytes, at);
}

/// Falsification: replayable `falsifications/verification.be32_reads_big_endian_when_in_bounds.patch`
/// **An in-bounds `be32` reads four big-endian bytes.** When it returns `Ok`, the value is
/// exactly `bytes[at..at+4]` most-significant-byte first, so the endianness conversion the whole
/// crate depends on is correct, for every input.
#[kani::proof]
fn be32_reads_big_endian_when_in_bounds() {
    let bytes: [u8; N] = kani::any();
    let at: usize = kani::any();
    if let Ok(v) = be32(&bytes, at) {
        let expected = ((bytes[at] as u32) << 24)
            | ((bytes[at + 1] as u32) << 16)
            | ((bytes[at + 2] as u32) << 8)
            | (bytes[at + 3] as u32);
        assert_eq!(v, expected);
    }
}

/// Falsification: replayable `falsifications/verification.align4_rounds_up_to_a_multiple_of_four.patch`
/// **`align4` rounds up to a multiple of four.** For any length, `align4(n)` is either `None`
/// (only when rounding up would wrap) or a multiple of 4 that is at least `n` and less than
/// `n + 4`.
#[kani::proof]
fn align4_rounds_up_to_a_multiple_of_four() {
    let n: usize = kani::any();
    match align4(n) {
        Some(a) => {
            assert!(a.is_multiple_of(4));
            assert!(a >= n);
            assert!(a - n < 4);
        }
        None => assert!(n > usize::MAX - 3),
    }
}

/// Falsification: replayable `falsifications/verification.skip_padded_never_wraps.patch`
/// **Stepping over padded data is total.** For any position and length, `skip_padded` returns
/// a position at least as far along or refuses; it never panics or wraps.
#[kani::proof]
fn skip_padded_never_wraps() {
    let at: usize = kani::any();
    let n: usize = kani::any();
    if let Ok(next) = skip_padded(at, n) {
        assert!(next >= at);
        assert!(next - at >= n);
    }
}

/// Falsification: replayable `falsifications/verification.cells_refuses_a_value_wider_than_64_bits.patch`
/// **`cells` refuses a value wider than 64 bits.** For any value of up to five cells, an `Ok`
/// means every cell above the low two is zero and the answer is the low two, most significant
/// first; a nonzero cell above them is refused rather than shifted out.
#[kani::proof]
#[kani::unwind(14)]
fn cells_refuses_a_value_wider_than_64_bits() {
    let bytes: [u8; 20] = kani::any();
    let count: usize = kani::any();
    kani::assume(count <= 5);
    let value = &bytes[..count * 4];
    let low = count.saturating_sub(2) * 4;
    match cells(value) {
        Ok(number) => {
            assert!(value[..low].iter().all(|&byte| byte == 0));
            let mut expected = 0u64;
            for &byte in &value[low..] {
                expected = (expected << 8) | byte as u64;
            }
            assert_eq!(number, expected);
        }
        Err(error) => {
            assert_eq!(error, Error::BadValue);
            assert!(value[..low].iter().any(|&byte| byte != 0));
        }
    }
}

/// Falsification: replayable `falsifications/verification.decode_regions_stays_inside_its_output.patch`
/// **`decode_regions` never panics and never writes past `out`.** For any `reg` value of up to
/// 24 bytes, any cell counts and a two-slot `out`, it returns a count no larger than `out`, or
/// refuses.
#[kani::proof]
#[kani::unwind(8)]
fn decode_regions_stays_inside_its_output() {
    let bytes: [u8; 24] = kani::any();
    let length: usize = kani::any();
    kani::assume(length <= bytes.len());
    let mut out = [Region {
        start: 0,
        size_bytes: 0,
    }; 2];
    if let Ok(found) = decode_regions(&bytes[..length], kani::any(), kani::any(), &mut out) {
        assert!(found <= out.len());
    }
}

/// Falsification: replayable `falsifications/verification.the_header_checks_are_total.patch`
/// **The header checks are total.** For any buffer of up to 48 bytes (a header and a little more),
/// the header checks of `from_bytes` return a tree or an error and never panic, and a tree they
/// return lies inside the buffer. The walks `from_bytes` adds are loops over the token step the
/// next harness proves; the model checker runs out of memory on them whole, so the fuzz target
/// runs them whole instead.
#[kani::proof]
fn the_header_checks_are_total() {
    let bytes: [u8; 48] = kani::any();
    let length: usize = kani::any();
    kani::assume(length <= bytes.len());
    if let Ok(tree) = DeviceTreeBlob::from_header(&bytes[..length]) {
        assert!(tree.total_size() <= length);
        assert!(tree.structure.len() <= tree.total_size());
    }
}

/// Falsification: replayable `falsifications/verification.a_token_step_is_total_and_moves_forward.patch`
/// **One step of the token walk is total, moves forward, and keeps the depth in bounds.** Over
/// any 56-byte blob whose header `from_bytes` accepts and whose structure and strings blocks
/// start after the header, whatever those blocks hold, three steps each return a token, the end
/// or an error without panicking; each token
/// moves the cursor forward, so no walk can stall, and the depth never passes `MAXIMUM_DEPTH`.
/// Starting both blocks after the header bounds every name scan at 16 bytes, which is what
/// keeps the unwinding small; the bytes of the blocks themselves are unconstrained.
#[kani::proof]
#[kani::unwind(17)]
fn a_token_step_is_total_and_moves_forward() {
    let bytes: [u8; 56] = kani::any();
    let Ok(tree) = DeviceTreeBlob::from_header(&bytes) else {
        return;
    };
    kani::assume(tree.structure_offset == HEADER_BYTES && tree.strings_offset >= HEADER_BYTES);
    let mut tokens = tree.tokens();
    for _ in 0..3 {
        let before = tokens.at;
        match tokens.step() {
            Ok(Some((depth, _))) => {
                assert!(tokens.at > before);
                assert!(depth <= MAXIMUM_DEPTH);
                assert!(tokens.depth <= MAXIMUM_DEPTH);
            }
            Ok(None) | Err(_) => return,
        }
    }
}
