//! Property names and the strings block that holds them.
//!
//! The specification places every property name inside the strings block, `size_dt_strings` bytes
//! from `off_dt_strings`, and libfdt's `fdt_get_string` reads one only there. These blobs put a
//! name offset, or a name's end, outside that block, and check the parser refuses each one.

use device_tree_blob::{DeviceTreeBlob, Error};

/// The header word `size_dt_strings`, at byte 32.
const STRINGS_SIZE_FIELD_OFFSET_BYTES: usize = 32;

/// A device tree assembled from parts: a 40-byte header, an empty reservation block, the structure
/// block, then the strings block. Every property here gives its name offset as is, so a test can
/// point one anywhere, and the strings block holds whatever bytes the test puts in it.
struct Blob {
    strings: Vec<u8>,
    structure: Vec<u8>,
}

impl Blob {
    fn new(strings: &[u8]) -> Blob {
        Blob {
            strings: strings.to_vec(),
            structure: Vec::new(),
        }
    }

    fn token(&mut self, t: u32) -> &mut Self {
        self.structure.extend_from_slice(&t.to_be_bytes());
        self
    }

    /// `FDT_BEGIN_NODE` plus the node's name, zero byte-terminated and padded to four bytes.
    fn begin_node(&mut self, name: &[u8]) -> &mut Self {
        self.token(1);
        self.structure.extend_from_slice(name);
        self.structure.push(0);
        while !self.structure.len().is_multiple_of(4) {
            self.structure.push(0);
        }
        self
    }

    fn end_node(&mut self) -> &mut Self {
        self.token(2)
    }

    /// `FDT_PROP`: a length, the name offset given, then the value padded to four bytes.
    fn prop_at(&mut self, name_offset: u32, value: &[u8]) -> &mut Self {
        self.token(3);
        self.structure
            .extend_from_slice(&(value.len() as u32).to_be_bytes());
        self.structure.extend_from_slice(&name_offset.to_be_bytes());
        self.structure.extend_from_slice(value);
        while !self.structure.len().is_multiple_of(4) {
            self.structure.push(0);
        }
        self
    }

    fn finish(&mut self) -> Vec<u8> {
        self.token(9); // FDT_END
        let reservations_offset = 40;
        let structure_offset = reservations_offset + 16;
        let strings_offset = structure_offset + self.structure.len();
        let total = strings_offset + self.strings.len();
        let mut b = Vec::with_capacity(total);
        for word in [
            0xd00d_feed,
            total as u32,
            structure_offset as u32,
            strings_offset as u32,
            reservations_offset as u32,
            17, // version
            16, // last_comp_version
            0,  // boot_cpuid_phys
            self.strings.len() as u32,
            self.structure.len() as u32,
        ] {
            b.extend_from_slice(&word.to_be_bytes());
        }
        b.extend_from_slice(&[0u8; 16]);
        b.extend_from_slice(&self.structure);
        b.extend_from_slice(&self.strings);
        b
    }
}

/// `blob` with the big-endian word at `offset` replaced by `value`.
fn patched(blob: &[u8], offset: usize, value: u32) -> Vec<u8> {
    let mut b = blob.to_vec();
    b[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    b
}

/// A root, and a `chosen` node below it holding one property named by `name_offset`.
fn one_property(strings: &[u8], name_offset: u32) -> Vec<u8> {
    let mut b = Blob::new(strings);
    b.begin_node(b"");
    b.begin_node(b"chosen");
    b.prop_at(name_offset, b"value");
    b.end_node();
    b.end_node();
    b.finish()
}

/// **A property name with no terminating zero byte inside the strings block is refused.** The
/// strings block holds `abc` and nothing else, so the name runs to the block's end unterminated.
/// libfdt refuses the same name, and so does this parser, with the error a node name with no
/// terminator inside the structure block gets.
#[test]
fn a_property_name_without_a_terminator_inside_the_strings_block_is_refused() {
    let blob = one_property(b"abc", 0);
    let tree = DeviceTreeBlob::from_bytes(&blob).unwrap();
    assert_eq!(tree.node_property(b"chosen", b"abc"), Err(Error::BadValue));
}

/// **A name offset at or past the end of the strings block is refused**, as libfdt's
/// `fdt_get_string` refuses one at or past `size_dt_strings`. The offset of the block's last byte
/// is still read.
#[test]
fn a_property_name_offset_past_the_strings_block_is_refused() {
    let at = |name_offset: u32| {
        let blob = one_property(b"ab\0", name_offset);
        let tree = DeviceTreeBlob::from_bytes(&blob).unwrap();
        tree.node_property(b"chosen", b"b")
            .map(|value| value.is_some())
    };
    assert_eq!(at(1), Ok(true), "the name at offset 1 is `b`");
    assert_eq!(at(2), Ok(false), "the last byte is the empty name");
    assert_eq!(at(3), Err(Error::Truncated), "one past the block");
    assert_eq!(at(u32::MAX), Err(Error::Truncated), "far past the block");
}

/// **The search for a property name's terminator stops at the end of the strings block.** The
/// block is declared one byte long (`x`), and the blob carries more nonzero bytes and a zero after
/// it. A search bounded by the blob's end instead would read the name as `x` and those bytes, and
/// would read them again for every property that points there, so a walk over many such properties
/// would cost their count times the length of the run. Each lookup is now refused at the first
/// property. The header must also place the whole strings block inside the blob.
#[test]
fn the_property_name_search_stops_at_the_end_of_the_strings_block() {
    const PROPERTIES: usize = 100;
    const RUN_BYTES: usize = 10_000;
    let mut strings = vec![b'x'];
    strings.extend_from_slice(&[b'y'; RUN_BYTES]);
    strings.push(0);
    let mut b = Blob::new(&strings);
    b.begin_node(b"");
    b.begin_node(b"chosen");
    for _ in 0..PROPERTIES {
        b.prop_at(0, b"");
    }
    b.end_node();
    b.end_node();
    let whole = b.finish();
    let strings_offset = whole.len() - (RUN_BYTES + 2);

    // As built, the block holds the whole run and its zero, and every name is read in full.
    let tree = DeviceTreeBlob::from_bytes(&whole).unwrap();
    assert_eq!(tree.node_property(b"chosen", b"absent"), Ok(None));

    let short = patched(&whole, STRINGS_SIZE_FIELD_OFFSET_BYTES, 1);
    let tree = DeviceTreeBlob::from_bytes(&short).unwrap();
    assert_eq!(
        tree.node_property(b"chosen", b"absent"),
        Err(Error::BadValue)
    );
    assert_eq!(tree.node_property(b"chosen", b"x"), Err(Error::BadValue));

    // The strings block reaching exactly to the blob's end is accepted; one byte further is not,
    // nor is a size that wraps.
    let exact = (whole.len() - strings_offset) as u32;
    assert!(
        DeviceTreeBlob::from_bytes(&patched(&whole, STRINGS_SIZE_FIELD_OFFSET_BYTES, exact))
            .is_ok()
    );
    assert_eq!(
        DeviceTreeBlob::from_bytes(&patched(&whole, STRINGS_SIZE_FIELD_OFFSET_BYTES, exact + 1))
            .err(),
        Some(Error::Truncated)
    );
    assert_eq!(
        DeviceTreeBlob::from_bytes(&patched(&whole, STRINGS_SIZE_FIELD_OFFSET_BYTES, u32::MAX))
            .err(),
        Some(Error::Truncated)
    );
}
