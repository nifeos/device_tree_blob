//! A minimal flattened device tree (FDT) parser: bytes in, regions and property values out.
//!
//! The blob is the machine describing itself (where RAM, the serial port and the interrupt
//! controller are, how many CPUs exist), handed over by firmware: a bootloader, a Unified Extensible Firmware Interface (UEFI) loader or
//! QEMU. Every integer in it is big-endian, so every read goes through `be32` or `be64`. The blob
//! is untrusted input: every offset is checked, every walk is bounded, and a malformed blob is an
//! [`Error`] rather than a panic. The crate is pure logic with no target code, so its tests run on
//! the host against trees dumped from QEMU's `virt` machines and against hand-built hostile blobs.
//!
//! The format is the flattened one that chapter 5 of the Devicetree Specification (release 0.4)
//! defines, and the one libfdt reads.
//!
//! # Examples
//!
//! Parse a blob once, then ask it questions. QEMU's riscv64 `virt` machine, as the crate's test
//! fixture holds it:
//!
//! ```
//! use device_tree_blob::{DeviceTreeBlob, Region};
//!
//! let blob = include_bytes!(concat!(
//!     env!("CARGO_MANIFEST_DIR"),
//!     "/tests/fixtures/qemu-riscv64-virt.dtb"
//! ));
//! let tree = DeviceTreeBlob::from_bytes(blob)?;
//!
//! let mut ram = [Region::default(); 4];
//! let banks = tree.memory_regions(&mut ram)?;
//! assert_eq!(&ram[..banks], [Region::new(0x8000_0000, 0x800_0000)]);
//!
//! // A device found by what it is, whatever this machine calls its node.
//! let mut uart = [Region::default(); 1];
//! let found = tree.node_register_regions_compatible(b"ns16550a", &mut uart)?;
//! assert_eq!(&uart[..found], [Region::new(0x1000_0000, 0x100)]);
//!
//! // Any node by its path, and any of its properties.
//! let chosen = tree.find_node(b"/chosen").expect("QEMU writes /chosen");
//! assert_eq!(chosen.property(b"stdout-path"), Some(&b"/soc/serial@10000000\0"[..]));
//! # Ok::<(), device_tree_blob::Error>(())
//! ```

#![no_std]

/// A contiguous span of physical memory.
///
/// Ordered by `start`, then by `size_bytes`, so a sorted memory map lists its regions by address.
///
/// The fields are public to read. The type is `#[non_exhaustive]`, so a later field (the node a
/// region came from, say) breaks no caller; build one with [`Region::new`] or [`Region::default`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub struct Region {
    /// The physical address of the first byte.
    pub start: u64,
    /// Length in bytes.
    pub size_bytes: u64,
}

impl Region {
    /// A region of `size_bytes` bytes from `start`.
    ///
    /// The type is `#[non_exhaustive]`, so a caller outside the crate builds one here, or takes
    /// [`Region::default`] (zero bytes at address zero) to fill an output array. Nothing is checked:
    /// a region whose end wraps is representable, and [`end`](Self::end) saturates for it.
    ///
    /// # Examples
    ///
    /// ```
    /// use device_tree_blob::Region;
    ///
    /// let uart = Region::new(0x1000_0000, 0x100);
    /// assert_eq!(uart.end(), 0x1000_0100);
    /// let mut out = [Region::default(); 8];
    /// out[0] = uart;
    /// ```
    pub const fn new(start: u64, size_bytes: u64) -> Self {
        Region { start, size_bytes }
    }

    /// One past the last byte, **saturating**.
    ///
    /// Saturating because anyone can build one with [`Region::new`] whose
    /// `start + size_bytes` wraps, and a caller placing an allocator over every RAM region may call this
    /// before it can report a failure; a plain add would panic there under overflow checks
    /// (regression in `tests/hostile.rs`). A saturated end is still wrong, so the parser refuses a
    /// wrapping region with [`Error::RegionOverflow`]; this is the backstop, not the check.
    ///
    /// # Examples
    ///
    /// ```
    /// use device_tree_blob::Region;
    ///
    /// assert_eq!(Region::new(0x1000, 0x100).end(), 0x1100);
    /// assert_eq!(Region::new(u64::MAX, 2).end(), u64::MAX);
    /// ```
    pub fn end(&self) -> u64 {
        self.start.saturating_add(self.size_bytes)
    }
}

/// Why parsing the blob failed.
///
/// Each fault has its own variant, as libfdt separates `FDT_ERR_TRUNCATED`, `FDT_ERR_BADVALUE` and
/// `FDT_ERR_BADSTRUCTURE`, so a caller printing the error at boot names the fault the firmware made.
/// The enum is `#[non_exhaustive]`: a later fault gets its own variant without breaking a caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Error {
    /// The first four bytes were not `0xd00dfeed`. Either the pointer is wrong or the
    /// bootloader did not hand over a device tree at all.
    BadMagic(u32),
    /// The blob claims a version this parser does not read: its `last_compatible_version` is above 17.
    UnsupportedVersion(u32),
    /// The blob, or one of its blocks, ends before something it must hold: an offset in the header
    /// points outside the blob, the strings block runs past the blob's end, a property's name
    /// offset lies past the strings block, a property's value runs past the structure block, or the
    /// walk reaches the end of the structure block without its end token.
    Truncated,
    /// A value has the wrong shape for what it holds: an integer property that is neither 4 nor 8
    /// bytes long, a node or property name with no terminating zero byte inside its block, or a `reg`
    /// that does not fit a [`Region`]. That last is a cell count above [`MAXIMUM_CELLS`], a
    /// nonzero cell above the low two (a value wider than 64 bits), or a length that is not a
    /// whole number of (address, size) pairs.
    BadValue,
    /// A token this parser does not recognize. The structure block is malformed.
    BadToken(u32),
    /// The caller's output slice was too small to hold every region found, or, for
    /// [`node_properties`](DeviceTreeBlob::node_properties), a value for every matching node.
    TooManyRegions,
    /// The structure block is not one tree: a node closes when none is open, the block's end
    /// token arrives while a node is still open, there is no root node or a second one, or a
    /// property lies outside every node or after its node's first child.
    BadStructure,
    /// The structure block nests deeper than [`MAXIMUM_DEPTH`].
    TooDeep,
    /// The header's `totalsize` is larger than [`MAXIMUM_TOTAL_SIZE_BYTES`], so
    /// [`from_pointer`](DeviceTreeBlob::from_pointer) refused to build a slice of that length over
    /// memory nobody has checked. Carries the size claimed.
    TooLarge(usize),
    /// A `reg` pair whose `start + size` does not fit in 64 bits, so the region names memory that
    /// cannot exist.
    ///
    /// Refused rather than clamped, and here rather than left to [`Region::end`]: a caller deciding
    /// where RAM is should be told the firmware's memory map is impossible rather than quietly
    /// work around it.
    RegionOverflow,
}

impl core::fmt::Display for Error {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::BadMagic(magic) => write!(formatter, "bad device tree magic {magic:#010x}"),
            Error::UnsupportedVersion(version) => {
                write!(formatter, "unsupported device tree version {version}")
            }
            Error::Truncated => formatter.write_str("device tree truncated"),
            Error::BadValue => formatter.write_str("malformed device tree property value or name"),
            Error::BadToken(token) => write!(formatter, "unknown device tree token {token:#x}"),
            Error::BadStructure => formatter.write_str("device tree nodes do not balance"),
            Error::TooDeep => formatter.write_str("device tree nests deeper than the maximum"),
            Error::TooManyRegions => formatter.write_str("too many regions for the output slice"),
            Error::TooLarge(size) => {
                write!(
                    formatter,
                    "device tree claims {size} bytes, above the ceiling"
                )
            }
            Error::RegionOverflow => formatter.write_str("region wraps the 64-bit address space"),
        }
    }
}

impl core::error::Error for Error {}

// Structure-block tokens.
const FDT_BEGIN_NODE: u32 = 0x1;
const FDT_END_NODE: u32 = 0x2;
const FDT_PROP: u32 = 0x3;
const FDT_NOP: u32 = 0x4;
const FDT_END: u32 = 0x9;

const MAGIC: u32 = 0xd00d_feed;
const HEADER_BYTES: usize = 40;

/// The largest `totalsize` [`DeviceTreeBlob::from_pointer`] will believe, 2 MiB.
///
/// `from_pointer` trusts the header's length before anything is validated, and the magic says only
/// that the pointer is at a blob. Without this ceiling a `totalsize` of `0xffff_ffff` becomes a
/// 4 GiB slice read past the end of RAM, a fault on the boot path before any handler can say why.
/// 2 MiB is Linux's `MAX_FDT_SIZE` (`SZ_2M` in `arch/arm64/include/asm/boot.h`); QEMU's `virt`
/// blobs are under 64 KiB.
#[doc(alias = "MAX_FDT_SIZE")]
#[doc(alias = "totalsize")]
pub const MAXIMUM_TOTAL_SIZE_BYTES: usize = 2 * 1024 * 1024;

/// The most cells a `#address-cells` or `#size-cells` declaration may give a `reg` value, as
/// libfdt's `FDT_MAX_NCELLS`. A `reg` read under a larger count is [`Error::BadValue`].
#[doc(alias = "FDT_MAX_NCELLS")]
pub const MAXIMUM_CELLS: u32 = 4;

/// How deeply the structure block may nest, the root counting as depth 1: 64, as Linux's
/// `FDT_MAX_DEPTH`.
///
/// A lookup keeps a few words per open node on the caller's stack, so the nesting has a bound. A
/// tree nested deeper is refused with [`Error::TooDeep`] by every lookup alike, rather than read by
/// some and not others. Real trees nest well under ten deep.
#[doc(alias = "FDT_MAX_DEPTH")]
pub const MAXIMUM_DEPTH: usize = 64;

fn be32(bytes: &[u8], at: usize) -> Result<u32, Error> {
    // `at + 4` is a checked add, not a bare one: `at` comes straight out of the (untrusted) blob,
    // and a near-`usize::MAX` offset would otherwise panic on the overflow before `get` ever runs.
    // Proved total in the verification module.
    let end = at.checked_add(4).ok_or(Error::Truncated)?;
    let slice = bytes.get(at..end).ok_or(Error::Truncated)?;
    Ok(u32::from_be_bytes(slice.try_into().unwrap()))
}

fn be64(bytes: &[u8], at: usize) -> Result<u64, Error> {
    let end = at.checked_add(8).ok_or(Error::Truncated)?;
    let slice = bytes.get(at..end).ok_or(Error::Truncated)?;
    Ok(u64::from_be_bytes(slice.try_into().unwrap()))
}

/// A parsed, borrowed device tree blob.
///
/// Each lookup walks the structure block from its first token, so a lookup costs one pass over the
/// tree and holds nothing between calls. Every walk refuses the same faults when it reaches them:
/// a tree whose nesting does not balance ([`Error::BadStructure`]), one nested deeper than
/// [`MAXIMUM_DEPTH`] ([`Error::TooDeep`]), and a structure block that ends before its end token
/// ([`Error::Truncated`]). A lookup that finds its answer first returns it without walking on.
///
/// The tree is `Copy`: it is a borrow of the blob and a few offsets, so two consumers can each hold
/// one. Its `Debug` prints the total size and the block offsets, never the blob's bytes.
#[derive(Clone, Copy)]
pub struct DeviceTreeBlob<'a> {
    bytes: &'a [u8],
    /// The structure block alone, as the prefix of the blob that ends where the block does, so an
    /// offset into it is an offset into the blob and a read past the block is a read past the end.
    structure: &'a [u8],
    structure_offset: usize,
    strings_offset: usize,
    /// The strings block alone, `size_dt_strings` bytes from `off_dt_strings`. A property's name is
    /// found inside it and must end inside it, as libfdt's `fdt_get_string` reads one.
    strings: &'a [u8],
    reservations_offset: usize,
    /// The root node: its name, and where its contents start in the structure block. `from_bytes`
    /// finds it in its walk.
    root_name: &'a [u8],
    root_at: usize,
}

impl core::fmt::Debug for DeviceTreeBlob<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("DeviceTreeBlob")
            .field("total_size", &self.bytes.len())
            .field("structure_offset", &self.structure_offset)
            .field(
                "structure_size",
                &self.structure.len().saturating_sub(self.structure_offset),
            )
            .field("strings_offset", &self.strings_offset)
            .field("strings_size", &self.strings.len())
            .field("reservations_offset", &self.reservations_offset)
            .finish()
    }
}

impl<'a> DeviceTreeBlob<'a> {
    /// Parse the blob at `pointer`, whose length the blob's own header gives.
    ///
    /// Reads the first 8 bytes alone, the magic and `totalsize`, and builds a slice over the
    /// whole blob only once the magic matches and the size is at most
    /// [`MAXIMUM_TOTAL_SIZE_BYTES`]. Every read is byte-wise, so `pointer` needs no alignment.
    ///
    /// # Safety
    ///
    /// `pointer` must point at a device tree blob, and for the whole of `'a`:
    ///
    /// - the blob's first 8 bytes, and then the `totalsize` bytes its header declares (at most
    ///   [`MAXIMUM_TOTAL_SIZE_BYTES`]), must be readable memory, one allocation or mapping from
    ///   `pointer` on;
    /// - nothing may write to those bytes, neither this program nor a device nor other firmware,
    ///   since the tree hands out `&'a [u8]` borrows of them.
    ///
    /// The 8 bytes are read before anything is validated, which is the one leap of faith: a wrong
    /// pointer almost certainly fails the magic check that follows, but an unreadable one faults.
    ///
    /// # Errors
    ///
    /// Those of [`from_bytes`](Self::from_bytes), and [`Error::TooLarge`] when the header's
    /// `totalsize` is above [`MAXIMUM_TOTAL_SIZE_BYTES`].
    ///
    /// # Examples
    ///
    /// A blob in this program's own memory stands in for the one firmware hands over:
    ///
    /// ```
    /// use device_tree_blob::DeviceTreeBlob;
    ///
    /// let blob: &'static [u8] = include_bytes!(concat!(
    ///     env!("CARGO_MANIFEST_DIR"),
    ///     "/tests/fixtures/qemu-riscv64-virt.dtb"
    /// ));
    /// // SAFETY: `blob` is a whole device tree blob, readable and never written for the whole program.
    /// let tree = unsafe { DeviceTreeBlob::from_pointer(blob.as_ptr()) }?;
    /// assert_eq!(tree.total_size(), blob.len());
    /// # Ok::<(), device_tree_blob::Error>(())
    /// ```
    #[doc(alias = "from_ptr")]
    pub unsafe fn from_pointer(pointer: *const u8) -> Result<Self, Error> {
        // Read just enough to learn how long the thing claims to be.
        // SAFETY: the caller's contract is that `pointer` points at a blob valid for `'a`. This reads only the magic and the size, the deliberate leap of faith the magic check on the next line exists to catch.
        let header = unsafe { core::slice::from_raw_parts(pointer, 8) };
        let magic = be32(header, 0)?;
        if magic != MAGIC {
            return Err(Error::BadMagic(magic));
        }
        let total = be32(header, 4)? as usize;
        if total > MAXIMUM_TOTAL_SIZE_BYTES {
            return Err(Error::TooLarge(total));
        }

        // SAFETY: the magic checked out, so `pointer` really is a blob, and `total` is the length it
        // declares for itself, now bounded by `MAXIMUM_TOTAL_SIZE_BYTES`; the caller's contract covers the
        // whole of it for `'a`.
        let bytes = unsafe { core::slice::from_raw_parts(pointer, total) };
        Self::from_bytes(bytes)
    }

    /// Parse a blob already in hand as a safe slice. [`from_pointer`](Self::from_pointer) builds
    /// one once it has trusted the header, and calls this.
    ///
    /// A `bytes` longer than the header's `totalsize` is accepted and trimmed to it, so a blob
    /// read into a larger buffer parses as itself. [`MAXIMUM_TOTAL_SIZE_BYTES`] bounds
    /// [`from_pointer`](Self::from_pointer) only: a slice in hand is already as long as it is. The header's
    /// `version` decides where the structure block ends (`size_dt_struct` from version 17, the
    /// strings block before it), and a `last_compatible_version` above 17 is refused. The strings
    /// block (`size_dt_strings` bytes) must lie inside the blob; `boot_cpuid_phys` is not read.
    ///
    /// It then walks the memory reservation block and the whole structure block once, so a tree it
    /// returns is whole: a later lookup meets only tokens, names and nesting this walk accepted,
    /// and fails, if at all, on the shape of a value it reads or a full output slice.
    ///
    /// # Errors
    ///
    /// - [`Error::BadMagic`] when the first word is not `0xd00dfeed`.
    /// - [`Error::UnsupportedVersion`] when `last_compatible_version` is above 17.
    /// - [`Error::Truncated`] when the header, a block or a value runs past the blob, or the
    ///   structure block ends before its `FDT_END`; [`Error::BadToken`] for a token the
    ///   specification does not define; [`Error::BadValue`] for a name with no terminating zero
    ///   byte; [`Error::TooDeep`] for nesting deeper than [`MAXIMUM_DEPTH`].
    /// - [`Error::BadStructure`] for nesting that does not balance, no root node or a second one, a
    ///   property outside every node, or a property after its node's first child.
    /// - [`Error::RegionOverflow`] for a reservation entry that wraps the address space.
    ///
    /// # Examples
    ///
    /// ```
    /// use device_tree_blob::DeviceTreeBlob;
    ///
    /// let blob = include_bytes!(concat!(
    ///     env!("CARGO_MANIFEST_DIR"),
    ///     "/tests/fixtures/qemu-riscv64-virt.dtb"
    /// ));
    /// let tree = DeviceTreeBlob::from_bytes(blob)?;
    /// assert_eq!(tree.total_size(), blob.len());
    /// # Ok::<(), device_tree_blob::Error>(())
    /// ```
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, Error> {
        let mut tree = Self::from_header(bytes)?;
        tree.check_reservations()?;
        (tree.root_name, tree.root_at) = tree.check_structure()?;
        Ok(tree)
    }

    /// The header checks of [`from_bytes`](Self::from_bytes), without its walks over the
    /// reservation and structure blocks: a tree whose blocks lie inside the blob, and nothing more.
    fn from_header(bytes: &'a [u8]) -> Result<Self, Error> {
        let magic = be32(bytes, 0)?;
        if magic != MAGIC {
            return Err(Error::BadMagic(magic));
        }

        let total = be32(bytes, 4)? as usize;
        if bytes.len() < total || total < HEADER_BYTES {
            return Err(Error::Truncated);
        }

        // We only understand version 17 and later, which is everything made since about
        // 2005. The `last_compatible_version` field is the blob telling us the oldest reader
        // it is still compatible with.
        let last_compatible_version = be32(bytes, 24)?;
        if last_compatible_version > 17 {
            return Err(Error::UnsupportedVersion(last_compatible_version));
        }

        let structure_start = be32(bytes, 8)? as usize;
        let strings_offset = be32(bytes, 12)? as usize;

        // Where the structure block ends. From version 17 the header says how long it is; before
        // that the block runs up to the strings block, which is how libfdt reads such a blob. A
        // walk that reaches this end without `FDT_END` is truncated; without the bound it would
        // read the strings block as tokens.
        let structure_end = if be32(bytes, 20)? >= 17 {
            structure_start
                .checked_add(be32(bytes, 36)? as usize)
                .ok_or(Error::Truncated)?
        } else {
            strings_offset
        };
        if structure_end > total || structure_end < structure_start {
            return Err(Error::Truncated);
        }

        // The strings block must lie inside the blob, as libfdt's `fdt_check_header` requires of
        // every version. Every property name is looked up inside it and nowhere else.
        let strings_end = strings_offset
            .checked_add(be32(bytes, 32)? as usize)
            .ok_or(Error::Truncated)?;
        if strings_end > total {
            return Err(Error::Truncated);
        }

        let tree = DeviceTreeBlob {
            structure_offset: structure_start,
            strings_offset,
            strings: bytes
                .get(strings_offset..strings_end)
                .ok_or(Error::Truncated)?,
            reservations_offset: be32(bytes, 16)? as usize,
            bytes: &bytes[..total],
            structure: &bytes[..structure_end],
            root_name: &[],
            root_at: structure_start,
        };

        if tree.structure_offset >= total
            || tree.strings_offset >= total
            || tree.reservations_offset >= total
        {
            return Err(Error::Truncated);
        }
        Ok(tree)
    }

    /// Walk the memory reservation block to its all-zero terminator, refusing what
    /// [`memory_reservations`](Self::memory_reservations) would refuse other than a full `out`: an
    /// entry past the blob's end ([`Error::Truncated`]) and one that wraps
    /// ([`Error::RegionOverflow`]).
    fn check_reservations(&self) -> Result<(), Error> {
        let mut at = self.reservations_offset;
        loop {
            let start = be64(self.bytes, at)?;
            let size = be64(self.bytes, at.checked_add(8).ok_or(Error::Truncated)?)?;
            at = at.checked_add(16).ok_or(Error::Truncated)?;
            if start == 0 && size == 0 {
                return Ok(());
            }
            if start.checked_add(size).is_none() {
                return Err(Error::RegionOverflow);
            }
        }
    }

    /// Walk the whole structure block once, so that every later walk over it meets only what this
    /// one accepted.
    ///
    /// Refuses every fault a walk can reach: a token it does not know ([`Error::BadToken`]), a
    /// block that ends before its end token or a value past the block ([`Error::Truncated`]), a
    /// node or property name with no terminator ([`Error::BadValue`]), nesting deeper than
    /// [`MAXIMUM_DEPTH`] ([`Error::TooDeep`]), and a shape the specification's section 5.4 rules
    /// out ([`Error::BadStructure`]): nesting that does not balance, no root node or a second one,
    /// a property outside every node, and a property after its node's first child.
    ///
    /// Returns the root node's name and where its contents start.
    fn check_structure(&self) -> Result<(&'a [u8], usize), Error> {
        // Per open node: whether a child has opened inside it, after which no property of its
        // own may follow.
        let mut has_child = [false; DEPTH_SLOTS];
        let mut root = None;
        let mut tokens = self.tokens();

        while let Some((depth, token)) = tokens.step()? {
            match token {
                Token::BeginNode { name } => {
                    if depth == 1 {
                        if root.is_some() {
                            return Err(Error::BadStructure);
                        }
                        root = Some((name, tokens.at));
                    }
                    has_child[depth - 1] = true;
                    has_child[depth] = false;
                }
                Token::EndNode => {}
                Token::Property { name, .. } => {
                    name.read()?;
                    if depth == 0 || has_child[depth] {
                        return Err(Error::BadStructure);
                    }
                }
            }
        }
        root.ok_or(Error::BadStructure)
    }

    /// How many bytes the blob occupies: the header's `totalsize`, which a longer slice given to
    /// [`from_bytes`](Self::from_bytes) is trimmed to.
    ///
    /// The blob usually lies in RAM that the memory nodes describe, so a caller that hands out that
    /// RAM reserves these bytes for as long as it reads the tree, or copies the blob elsewhere first.
    ///
    /// # Examples
    ///
    /// ```
    /// use device_tree_blob::{DeviceTreeBlob, Region};
    ///
    /// let blob = include_bytes!(concat!(
    ///     env!("CARGO_MANIFEST_DIR"),
    ///     "/tests/fixtures/qemu-riscv64-virt.dtb"
    /// ));
    /// let tree = DeviceTreeBlob::from_bytes(blob)?;
    /// // The span to keep out of the frame allocator while the tree is still read.
    /// let keep = Region::new(blob.as_ptr() as u64, tree.total_size() as u64);
    /// assert_eq!(keep.size_bytes, blob.len() as u64);
    /// # Ok::<(), device_tree_blob::Error>(())
    /// ```
    pub fn total_size(&self) -> usize {
        self.bytes.len()
    }

    /// The memory reservation block: regions the bootloader is telling us **not to
    /// touch**, before a single node is parsed.
    ///
    /// This is a separate, deliberately dead-simple structure precisely so that a
    /// kernel can honor it without having to parse anything. QEMU's `virt` leaves it
    /// empty, but a real board's firmware often does not, and a kernel that skips it
    /// will happily allocate over the firmware's own tables.
    ///
    /// An entry whose `start + size` does not fit in 64 bits is [`Error::RegionOverflow`], as a
    /// `reg` pair of the same shape is. The specification places the block on an 8-byte boundary,
    /// and that is not checked: every read here is byte-wise, so a misplaced block reads the same.
    ///
    /// # Errors
    ///
    /// [`Error::TooManyRegions`] when `out` is full before the list ends. A wrapping entry was already
    /// refused by [`from_bytes`](Self::from_bytes).
    ///
    ///
    /// # Examples
    ///
    /// QEMU's riscv64 `virt` machine, as the crate's test fixture holds it, reserves nothing here:
    ///
    /// ```
    /// use device_tree_blob::{DeviceTreeBlob, Region};
    ///
    /// let blob = include_bytes!(concat!(
    ///     env!("CARGO_MANIFEST_DIR"),
    ///     "/tests/fixtures/qemu-riscv64-virt.dtb"
    /// ));
    /// let tree = DeviceTreeBlob::from_bytes(blob)?;
    /// let mut reserved = [Region::default(); 8];
    /// assert_eq!(tree.memory_reservations(&mut reserved)?, 0);
    /// # Ok::<(), device_tree_blob::Error>(())
    /// ```
    pub fn memory_reservations(&self, out: &mut [Region]) -> Result<usize, Error> {
        let mut at = self.reservations_offset;
        let mut n = 0;

        loop {
            let start = be64(self.bytes, at)?;
            let size = be64(self.bytes, at.checked_add(8).ok_or(Error::Truncated)?)?;
            at = at.checked_add(16).ok_or(Error::Truncated)?;

            // The list is terminated by an all-zero entry.
            if start == 0 && size == 0 {
                return Ok(n);
            }
            if start.checked_add(size).is_none() {
                return Err(Error::RegionOverflow);
            }

            *out.get_mut(n).ok_or(Error::TooManyRegions)? = Region {
                start,
                size_bytes: size,
            };
            n += 1;
        }
    }

    /// Every memory node's `reg` property: the actual RAM, written into `out`.
    ///
    /// A memory node is a child of the root that is named `memory` or `memory@<address>`, or that
    /// says `device_type = "memory"`, and that the firmware has not disabled: a `status` other than
    /// `"okay"` (or the older `"ok"`) leaves the node out, as Linux leaves it out. Its `reg` is
    /// decoded with the root's cell widths. Linux's `linux,usable-memory`, which a kexec loader
    /// writes to narrow a bank, is not read.
    ///
    /// Returns how many regions it wrote; refuses a full `out` with [`Error::TooManyRegions`] and a
    /// wrapping pair with [`Error::RegionOverflow`].
    ///
    /// # Examples
    ///
    /// QEMU's riscv64 `virt` machine, as the crate's test fixture holds it:
    ///
    /// ```
    /// use device_tree_blob::{DeviceTreeBlob, Region};
    ///
    /// let blob = include_bytes!(concat!(
    ///     env!("CARGO_MANIFEST_DIR"),
    ///     "/tests/fixtures/qemu-riscv64-virt.dtb"
    /// ));
    /// let tree = DeviceTreeBlob::from_bytes(blob)?;
    /// let mut ram = [Region::default(); 4];
    /// let banks = tree.memory_regions(&mut ram)?;
    /// assert_eq!(&ram[..banks], [Region::new(0x8000_0000, 0x800_0000)]);
    /// # Ok::<(), device_tree_blob::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// - [`Error::TooManyRegions`] when `out` is full before the last region.
    /// - [`Error::RegionOverflow`] for a pair whose `start + size` wraps the address space.
    /// - [`Error::BadValue`] for a `reg` that is not a whole number of (address, size) pairs, or cell
    ///   counts above [`MAXIMUM_CELLS`], or a cell value wider than 64 bits.
    pub fn memory_regions(&self, out: &mut [Region]) -> Result<usize, Error> {
        // `reg` is a list of (address, size) pairs, but how many 32-bit cells each of those takes
        // is not fixed. It is declared by #address-cells and #size-cells on the PARENT node, which
        // for a memory node is the root. The specification's defaults are 2 and 1. Nearly every
        // 64-bit machine says 2 and 2, but they are read rather than assumed.
        let mut bus_address_cells = 2u32;
        let mut bus_size_cells = 1u32;

        let mut found = 0;
        // What the depth-2 node now open has said so far. `device_type` and `status` may follow
        // `reg`, so the node is judged when it closes. Keyed on depth 2: a child of a memory node,
        // which no real tree has, neither adds to nor clears its parent's answer.
        let mut named_memory = false;
        let mut typed_memory = false;
        let mut available = true;
        let mut register_value: Option<&[u8]> = None;
        let mut tokens = self.tokens();

        while let Some((depth, token)) = tokens.step()? {
            match token {
                Token::BeginNode { name } => {
                    if depth == 2 {
                        named_memory = names_node(b"memory", name);
                        typed_memory = false;
                        available = true;
                        register_value = None;
                    }
                }
                Token::EndNode => {
                    if depth == 2
                        && (named_memory || typed_memory)
                        && available
                        && let Some(value) = register_value
                    {
                        let remaining = out.get_mut(found..).ok_or(Error::TooManyRegions)?;
                        found +=
                            decode_regions(value, bus_address_cells, bus_size_cells, remaining)?;
                    }
                }
                Token::Property { name, value } => {
                    // The root's cell counts. A node's properties precede its children, so by the
                    // time a memory node closes these are the root's.
                    if depth == 1 {
                        declare_cells(name, value, &mut bus_address_cells, &mut bus_size_cells);
                    }
                    if depth == 2 {
                        if name.is(b"reg") {
                            register_value = Some(value);
                        } else if name.is(b"device_type") {
                            typed_memory = value == b"memory\0";
                        } else if name.is(b"status") {
                            available = value == b"okay\0" || value == b"ok\0";
                        }
                    }
                }
            }
        }
        Ok(found)
    }

    /// The register regions (`reg`, the Devicetree Specification's abbreviation for the
    /// property) of the first node below the root that `node` names, searched at any depth.
    ///
    /// `node` names a node by its full name (`b"serial@10000000"`), or by the name without its unit
    /// address (`b"serial"` names `serial@10000000`, and never `serial-bus`), as the Devicetree
    /// Specification's section 2.2.1 lets a node be named and as libfdt's `fdt_subnode_offset`
    /// matches one. An empty `node` names no node.
    ///
    /// Decodes with the `#address-cells`/`#size-cells` of the node's **parent**, carried down a
    /// per-depth stack, so a device nested under `/soc` reads as well as one under the root. A generic interrupt controller (GIC)
    /// decodes to two regions, distributor first, as its binding orders them. Matching a name
    /// rather than `compatible` is a simplification; [`node_register_regions_compatible`](Self::node_register_regions_compatible)
    /// is the correct lookup. The first match is the answer: one with no `reg` yields zero regions, and
    /// a later match's `reg` is never read in its place.
    ///
    /// # Errors
    ///
    /// - [`Error::TooManyRegions`] when `out` is full before the last region.
    /// - [`Error::RegionOverflow`] for a pair whose `start + size` wraps the address space.
    /// - [`Error::BadValue`] for a `reg` that is not a whole number of (address, size) pairs, or cell
    ///   counts above [`MAXIMUM_CELLS`], or a cell value wider than 64 bits.
    ///
    ///
    /// # Examples
    ///
    /// QEMU's riscv64 `virt` machine, as the crate's test fixture holds it:
    ///
    /// ```
    /// use device_tree_blob::{DeviceTreeBlob, Region};
    ///
    /// let blob = include_bytes!(concat!(
    ///     env!("CARGO_MANIFEST_DIR"),
    ///     "/tests/fixtures/qemu-riscv64-virt.dtb"
    /// ));
    /// let tree = DeviceTreeBlob::from_bytes(blob)?;
    /// let mut uart = [Region::default(); 1];
    /// let found = tree.node_register_regions(b"serial", &mut uart)?;
    /// assert_eq!(&uart[..found], [Region::new(0x1000_0000, 0x100)]);
    /// # Ok::<(), device_tree_blob::Error>(())
    /// ```
    #[doc(alias = "reg")]
    pub fn node_register_regions(&self, node: &[u8], out: &mut [Region]) -> Result<usize, Error> {
        // The cell counts declared by the node open at each depth, applying to its children. Depth
        // 0 is the slot above the root; the root is depth 1. The specification's defaults are 2
        // and 1.
        let mut bus_address_cells = [2u32; DEPTH_SLOTS];
        let mut bus_size_cells = [1u32; DEPTH_SLOTS];
        let mut target_at: Option<usize> = None;
        let mut tokens = self.tokens();

        while let Some((depth, token)) = tokens.step()? {
            match token {
                Token::BeginNode { name } => {
                    // A node inherits its parent's cell counts until it declares its own (its
                    // properties come before its children).
                    bus_address_cells[depth] = bus_address_cells[depth - 1];
                    bus_size_cells[depth] = bus_size_cells[depth - 1];
                    if depth >= 2 && target_at.is_none() && names_node(node, name) {
                        target_at = Some(depth);
                    }
                }
                Token::EndNode => {
                    if target_at == Some(depth) {
                        // The whole node has been walked. Had it a `reg`, the property arm would
                        // have answered, so it has none. The first match is the answer, as for
                        // `node_property` and `node_register_regions_compatible`: zero regions, and a later
                        // node's `reg` is not a substitute.
                        return Ok(0);
                    }
                }
                Token::Property { name, value } => {
                    declare_cells(
                        name,
                        value,
                        &mut bus_address_cells[depth],
                        &mut bus_size_cells[depth],
                    );
                    if target_at == Some(depth) && name.is(b"reg") {
                        // A node's own `reg` uses its parent's cells, one level up.
                        return decode_regions(
                            value,
                            bus_address_cells[depth - 1],
                            bus_size_cells[depth - 1],
                            out,
                        );
                    }
                }
            }
        }
        Ok(0)
    }

    /// The register regions (`reg`, the Devicetree Specification's abbreviation for the
    /// property) of the first node whose `compatible` property lists the entry `compatible`, searched at any depth.
    ///
    /// A match on **any** zero-byte-separated entry counts, as the binding intends: a node that says
    /// `"starfive,jh7110-rtc\0arm,pl031"` claims the real-time clock register layout. The empty piece after the
    /// final zero byte is not an entry, so an empty `compatible` matches nothing. The property may follow
    /// `reg` in the same node, so each open node's `reg` is remembered on a per-depth stack and
    /// decoded when the matched node closes; a matched parent is still answered after its
    /// children close. Returns zero regions for a match with no `reg`.
    ///
    /// # Examples
    ///
    /// QEMU's riscv64 `virt` machine, as the crate's test fixture holds it:
    ///
    /// ```
    /// use device_tree_blob::{DeviceTreeBlob, Region};
    ///
    /// let blob = include_bytes!(concat!(
    ///     env!("CARGO_MANIFEST_DIR"),
    ///     "/tests/fixtures/qemu-riscv64-virt.dtb"
    /// ));
    /// let tree = DeviceTreeBlob::from_bytes(blob)?;
    /// let mut rtc = [Region::default(); 1];
    /// let found = tree.node_register_regions_compatible(b"google,goldfish-rtc", &mut rtc)?;
    /// assert_eq!(&rtc[..found], [Region::new(0x10_1000, 0x1000)]);
    /// # Ok::<(), device_tree_blob::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// - [`Error::TooManyRegions`] when `out` is full before the last region.
    /// - [`Error::RegionOverflow`] for a pair whose `start + size` wraps the address space.
    /// - [`Error::BadValue`] for a `reg` that is not a whole number of (address, size) pairs, or cell
    ///   counts above [`MAXIMUM_CELLS`], or a cell value wider than 64 bits.
    #[doc(alias = "reg")]
    pub fn node_register_regions_compatible(
        &self,
        compatible: &[u8],
        out: &mut [Region],
    ) -> Result<usize, Error> {
        let mut bus_address_cells = [2u32; DEPTH_SLOTS];
        let mut bus_size_cells = [1u32; DEPTH_SLOTS];
        // Per open node: its `reg` value with the parent's cell counts it decodes with, and whether
        // its `compatible` named the device being looked for.
        let mut register_values = [None::<(&'a [u8], u32, u32)>; DEPTH_SLOTS];
        let mut matched = [false; DEPTH_SLOTS];
        let mut tokens = self.tokens();

        while let Some((depth, token)) = tokens.step()? {
            match token {
                Token::BeginNode { .. } => {
                    bus_address_cells[depth] = bus_address_cells[depth - 1];
                    bus_size_cells[depth] = bus_size_cells[depth - 1];
                    register_values[depth] = None;
                    matched[depth] = false;
                }
                Token::EndNode => {
                    // Depth 1 is the root, which has no `compatible` worth matching and whose `reg`
                    // would have no parent to decode against.
                    if depth >= 2 && matched[depth] {
                        return match register_values[depth] {
                            Some((value, address, size)) => {
                                decode_regions(value, address, size, out)
                            }
                            // Compatible but no `reg`: the device exists and has no register block
                            // to name. Zero regions, not an error.
                            None => Ok(0),
                        };
                    }
                }
                Token::Property { name, value } => {
                    declare_cells(
                        name,
                        value,
                        &mut bus_address_cells[depth],
                        &mut bus_size_cells[depth],
                    );
                    if depth >= 2 && name.is(b"reg") {
                        register_values[depth] = Some((
                            value,
                            bus_address_cells[depth - 1],
                            bus_size_cells[depth - 1],
                        ));
                    }
                    if name.is(b"compatible") {
                        matched[depth] = lists_entry(value, compatible);
                    }
                }
            }
        }
        Ok(0)
    }

    /// The raw bytes of property `name` on the first node whose `compatible` property lists the
    /// entry `compatible`, searched at any depth. `Ok(None)` when no such node exists, or the node has no
    /// such property.
    ///
    /// The property twin of [`node_register_regions_compatible`](Self::node_register_regions_compatible), deciding when the
    /// matched node closes for the same reason. It exists because labels differ between machines:
    /// the platform-level interrupt controller (PLIC) is `plic@c000000` on QEMU `virt` and `interrupt-controller@c000000` on the JH7110.
    ///
    /// # Errors
    ///
    /// None on a tree [`from_bytes`](Self::from_bytes) built: the value is returned raw, and that
    /// walk already accepted every token, name and nesting this one meets.
    ///
    ///
    /// # Examples
    ///
    /// QEMU's riscv64 `virt` machine, as the crate's test fixture holds it:
    ///
    /// ```
    /// use device_tree_blob::DeviceTreeBlob;
    ///
    /// let blob = include_bytes!(concat!(
    ///     env!("CARGO_MANIFEST_DIR"),
    ///     "/tests/fixtures/qemu-riscv64-virt.dtb"
    /// ));
    /// let tree = DeviceTreeBlob::from_bytes(blob)?;
    /// let sources = tree.node_property_compatible(b"riscv,plic0", b"riscv,ndev")?;
    /// assert_eq!(sources, Some(&0x5f_u32.to_be_bytes()[..]));
    /// # Ok::<(), device_tree_blob::Error>(())
    /// ```
    pub fn node_property_compatible(
        &self,
        compatible: &[u8],
        name: &[u8],
    ) -> Result<Option<&'a [u8]>, Error> {
        self.property_compatible_up(compatible, name, 0)
    }

    /// The raw bytes of property `name` on the **parent** of the first node whose `compatible`
    /// property lists the entry `compatible`. `Ok(None)` when no such node exists, or its parent
    /// has no such property.
    ///
    /// For a device described as a child of its bus, such as a power management chip under one of seven identical
    /// `snps,designware-i2c` controllers on the JH7110, whose `clocks` and `resets` sit on
    /// the bus. The parent's slot is filled when the child closes, because a node's properties
    /// precede its first subnode.
    ///
    /// # Errors
    ///
    /// None on a tree [`from_bytes`](Self::from_bytes) built: the value is returned raw, and that
    /// walk already accepted every token, name and nesting this one meets.
    ///
    ///
    /// # Examples
    ///
    /// QEMU's riscv64 `virt` machine, as the crate's test fixture holds it:
    ///
    /// ```
    /// use device_tree_blob::DeviceTreeBlob;
    ///
    /// let blob = include_bytes!(concat!(
    ///     env!("CARGO_MANIFEST_DIR"),
    ///     "/tests/fixtures/qemu-riscv64-virt.dtb"
    /// ));
    /// let tree = DeviceTreeBlob::from_bytes(blob)?;
    /// // The UART sits under `/soc`, whose addresses are two cells wide.
    /// let cells = tree.parent_property_compatible(b"ns16550a", b"#address-cells")?;
    /// assert_eq!(cells, Some(&2_u32.to_be_bytes()[..]));
    /// # Ok::<(), device_tree_blob::Error>(())
    /// ```
    pub fn parent_property_compatible(
        &self,
        compatible: &[u8],
        name: &[u8],
    ) -> Result<Option<&'a [u8]>, Error> {
        self.property_compatible_up(compatible, name, 1)
    }

    /// The shared walk behind the two `*_property_compatible` reads: property `name` on the node `up`
    /// levels above the first node whose `compatible` property lists the argument (0 for the node itself, 1 for its parent).
    fn property_compatible_up(
        &self,
        compatible: &[u8],
        name: &[u8],
        up: usize,
    ) -> Result<Option<&'a [u8]>, Error> {
        // Per open node: `name`'s value, and whether `compatible` matched.
        let mut found = [None::<&'a [u8]>; DEPTH_SLOTS];
        let mut matched = [false; DEPTH_SLOTS];
        let mut tokens = self.tokens();

        while let Some((depth, token)) = tokens.step()? {
            match token {
                Token::BeginNode { .. } => {
                    found[depth] = None;
                    matched[depth] = false;
                }
                Token::EndNode => {
                    // Depth 1 is the root, which carries no `compatible` worth matching here.
                    // `depth >= 2` and `up <= 1` keep the answer at the root or below it.
                    if depth >= 2 && matched[depth] {
                        return Ok(found[depth - up]);
                    }
                }
                Token::Property {
                    name: property_name,
                    value,
                } => {
                    // Two independent `if`s, so asking for `compatible` itself still answers.
                    if property_name.is(name) {
                        found[depth] = Some(value);
                    }
                    if property_name.is(b"compatible") {
                        matched[depth] = lists_entry(value, compatible);
                    }
                }
            }
        }
        Ok(None)
    }

    /// The raw bytes of property `name` on the first node below the root that `node` names,
    /// searched at any depth. `Ok(None)` when no such node, or the node has no such property.
    ///
    /// `node` names a node as in [`node_register_regions`](Self::node_register_regions): the full
    /// name, or the name without its unit address.
    ///
    /// The generic escape hatch next to the decoded accessors above: some properties have
    /// per-binding layouts no general decoder can know (`interrupt-map` is the motivating case:
    /// its entry width depends on three different nodes' cell counts). The caller gets the bytes
    /// (big-endian cells, as the specification lays them out) and owns the interpretation.
    ///
    /// # Errors
    ///
    /// None on a tree [`from_bytes`](Self::from_bytes) built: the value is returned raw, and that
    /// walk already accepted every token, name and nesting this one meets.
    ///
    ///
    /// # Examples
    ///
    /// QEMU's riscv64 `virt` machine, as the crate's test fixture holds it:
    ///
    /// ```
    /// use device_tree_blob::DeviceTreeBlob;
    ///
    /// let blob = include_bytes!(concat!(
    ///     env!("CARGO_MANIFEST_DIR"),
    ///     "/tests/fixtures/qemu-riscv64-virt.dtb"
    /// ));
    /// let tree = DeviceTreeBlob::from_bytes(blob)?;
    /// let console = tree.node_property(b"chosen", b"stdout-path")?;
    /// assert_eq!(console, Some(&b"/soc/serial@10000000\0"[..]));
    /// # Ok::<(), device_tree_blob::Error>(())
    /// ```
    pub fn node_property(&self, node: &[u8], name: &[u8]) -> Result<Option<&'a [u8]>, Error> {
        let mut target_at: Option<usize> = None;
        let mut tokens = self.tokens();

        while let Some((depth, token)) = tokens.step()? {
            match token {
                Token::BeginNode { name: node_name } => {
                    if depth >= 2 && target_at.is_none() && names_node(node, node_name) {
                        target_at = Some(depth);
                    }
                }
                Token::EndNode => {
                    if target_at == Some(depth) {
                        // Walked the whole matched node: it has no such property.
                        return Ok(None);
                    }
                }
                Token::Property {
                    name: property_name,
                    value,
                } => {
                    if target_at == Some(depth) && property_name.is(name) {
                        return Ok(Some(value));
                    }
                }
            }
        }
        Ok(None)
    }

    /// Property `name` on the first node below the root that `node` names (as in
    /// [`node_register_regions`](Self::node_register_regions)), **falling back to the nearest
    /// ancestor** that carries it. `Ok(None)` when no such node, or neither the node nor
    /// any ancestor has the property.
    ///
    /// For the properties the spec defines as inheritable, such as `interrupt-parent`, which QEMU's
    /// two `virt` boards and the JH7110 dtsi each write at a different level. The nearest enclosing
    /// value wins, per the spec. A node's properties precede its children, so one walk suffices:
    /// the answer is taken at the target's `END_NODE`.
    ///
    /// # Errors
    ///
    /// None on a tree [`from_bytes`](Self::from_bytes) built: the value is returned raw, and that
    /// walk already accepted every token, name and nesting this one meets.
    ///
    ///
    /// # Examples
    ///
    /// QEMU's riscv64 `virt` machine, as the crate's test fixture holds it:
    ///
    /// ```
    /// use device_tree_blob::DeviceTreeBlob;
    ///
    /// let blob = include_bytes!(concat!(
    ///     env!("CARGO_MANIFEST_DIR"),
    ///     "/tests/fixtures/qemu-riscv64-virt.dtb"
    /// ));
    /// let tree = DeviceTreeBlob::from_bytes(blob)?;
    /// // The hart has no `timebase-frequency` of its own; `/cpus` carries it.
    /// let timebase = tree.node_property_inherited(b"cpu", b"timebase-frequency")?;
    /// assert_eq!(timebase, Some(&10_000_000_u32.to_be_bytes()[..]));
    /// # Ok::<(), device_tree_blob::Error>(())
    /// ```
    pub fn node_property_inherited(
        &self,
        node: &[u8],
        name: &[u8],
    ) -> Result<Option<&'a [u8]>, Error> {
        // `name`'s value on the node open at each depth, `None` where it has none. A node's
        // beginning resets its own slot, so a closed sibling's value never reaches the ancestor
        // scan (which reads only the depths still open above the target anyway).
        let mut values = [None::<&'a [u8]>; DEPTH_SLOTS];
        let mut target_at: Option<usize> = None;
        let mut tokens = self.tokens();

        while let Some((depth, token)) = tokens.step()? {
            match token {
                Token::BeginNode { name: node_name } => {
                    values[depth] = None;
                    if depth >= 2 && target_at.is_none() && names_node(node, node_name) {
                        target_at = Some(depth);
                    }
                }
                Token::EndNode => {
                    if target_at == Some(depth) {
                        // The whole target node has been walked: its own value if it had one,
                        // else the nearest open ancestor's, root included.
                        return Ok(values[1..=depth].iter().rev().find_map(|value| *value));
                    }
                }
                Token::Property {
                    name: property_name,
                    value,
                } => {
                    if property_name.is(name) {
                        values[depth] = Some(value);
                    }
                }
            }
        }
        Ok(None)
    }

    /// The raw bytes of property `name` on the node whose pointer handle (`phandle`, the
    /// Devicetree Specification's name for a node's numeric handle, which other nodes use to refer
    /// to it) is `pointer_handle`. `Ok(None)` when no node carries that pointer handle, or the node
    /// has no such property.
    ///
    /// How a property that refers to another node is followed, such as `interrupt-parent` to the
    /// controller's `#interrupt-cells`. Both `phandle` and the legacy `linux,phandle` are honored,
    /// because old dtc wrote the latter. As in [`node_property_compatible`](Self::node_property_compatible),
    /// the answer is taken when the matching node closes.
    ///
    /// # Errors
    ///
    /// None on a tree [`from_bytes`](Self::from_bytes) built: the value is returned raw, and that
    /// walk already accepted every token, name and nesting this one meets.
    ///
    ///
    /// # Examples
    ///
    /// QEMU's riscv64 `virt` machine, as the crate's test fixture holds it:
    ///
    /// ```
    /// use device_tree_blob::DeviceTreeBlob;
    ///
    /// let blob = include_bytes!(concat!(
    ///     env!("CARGO_MANIFEST_DIR"),
    ///     "/tests/fixtures/qemu-riscv64-virt.dtb"
    /// ));
    /// let tree = DeviceTreeBlob::from_bytes(blob)?;
    /// // Every device's `interrupt-parent` is pointer handle 3, the interrupt controller.
    /// let parent = tree.node_property(b"serial", b"interrupt-parent")?.expect("the UART interrupts");
    /// let handle = u32::from_be_bytes(parent.try_into().expect("one cell"));
    /// let sources = tree.pointer_handle_property(handle, b"riscv,ndev")?;
    /// assert_eq!(sources, Some(&0x5f_u32.to_be_bytes()[..]));
    /// # Ok::<(), device_tree_blob::Error>(())
    /// ```
    #[doc(alias = "phandle")]
    pub fn pointer_handle_property(
        &self,
        pointer_handle: u32,
        name: &[u8],
    ) -> Result<Option<&'a [u8]>, Error> {
        // Per open node: `name`'s value, and whether its pointer handle matched.
        let mut found = [None::<&'a [u8]>; DEPTH_SLOTS];
        let mut matched = [false; DEPTH_SLOTS];
        let mut tokens = self.tokens();

        while let Some((depth, token)) = tokens.step()? {
            match token {
                Token::BeginNode { .. } => {
                    found[depth] = None;
                    matched[depth] = false;
                }
                Token::EndNode => {
                    // Depth 1 is the root, which no pointer handle names in practice.
                    if depth >= 2 && matched[depth] {
                        return Ok(found[depth]);
                    }
                }
                Token::Property {
                    name: property_name,
                    value,
                } => {
                    if property_name.is(name) {
                        found[depth] = Some(value);
                    }
                    if (property_name.is(b"phandle") || property_name.is(b"linux,phandle"))
                        && value.len() == 4
                        && be32(value, 0)? == pointer_handle
                    {
                        matched[depth] = true;
                    }
                }
            }
        }
        Ok(None)
    }

    /// Property `name` on **every** node below the root that `node` names (as in
    /// [`node_register_regions`](Self::node_register_regions)), in tree order: `b"cpu"` names each
    /// `cpu@<unit address>`.
    ///
    /// For a node that repeats, such as each hart's `cpu@` on a heterogeneous RISC-V machine like
    /// the JH7110, whose harts differ in their `riscv,isa`. `out[i]` is `None` when the *i*th match has no
    /// such property, which differs from there being no *i*th match. Returns the number of matching
    /// **nodes**, and refuses a full `out` with [`Error::TooManyRegions`], as the region lookups
    /// refuse theirs: a caller never reads a short answer as the whole one.
    ///
    /// # Examples
    ///
    /// QEMU's riscv64 `virt` machine, as the crate's test fixture holds it, has one hart:
    ///
    /// ```
    /// use device_tree_blob::DeviceTreeBlob;
    ///
    /// let blob = include_bytes!(concat!(
    ///     env!("CARGO_MANIFEST_DIR"),
    ///     "/tests/fixtures/qemu-riscv64-virt.dtb"
    /// ));
    /// let tree = DeviceTreeBlob::from_bytes(blob)?;
    /// let mut isa = [None; 8];
    /// let harts = tree.node_properties(b"cpu", b"riscv,isa-base", &mut isa)?;
    /// assert_eq!(isa[..harts], [Some(&b"rv64i\0"[..])]);
    /// # Ok::<(), device_tree_blob::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::TooManyRegions`] when `out` is full before the last matching node.
    pub fn node_properties(
        &self,
        node: &[u8],
        name: &[u8],
        out: &mut [Option<&'a [u8]>],
    ) -> Result<usize, Error> {
        // The depth of the node being read, `None` outside every match. Nested matches are
        // impossible by construction: a node becomes the target only while there is none, so a
        // `cpu@0/cpu@1` (which no binding produces) reads as one node.
        let mut target_at: Option<usize> = None;
        let mut matched = 0usize;
        let mut tokens = self.tokens();

        for slot in out.iter_mut() {
            *slot = None;
        }

        while let Some((depth, token)) = tokens.step()? {
            match token {
                Token::BeginNode { name: node_name } => {
                    if depth >= 2 && target_at.is_none() && names_node(node, node_name) {
                        if matched == out.len() {
                            return Err(Error::TooManyRegions);
                        }
                        target_at = Some(depth);
                        matched += 1;
                    }
                }
                Token::EndNode => {
                    if target_at == Some(depth) {
                        target_at = None;
                    }
                }
                Token::Property {
                    name: property_name,
                    value,
                } => {
                    if target_at == Some(depth) && property_name.is(name) {
                        // `matched` counts this node and is at most `out.len()`, so the slot exists.
                        if let Some(slot) = out.get_mut(matched - 1) {
                            *slot = Some(value);
                        }
                    }
                }
            }
        }
        Ok(matched)
    }

    /// The regions carved out by the root's `reserved-memory` node's children. A node of that name
    /// anywhere deeper is not the reservation list and is not read.
    ///
    /// The other place firmware names memory the OS must not touch, beside the block
    /// [`memory_reservations`](Self::memory_reservations) reads; on RISC-V, `OpenSBI` reserves its physical-memory-protection-guarded
    /// region here, and missing it faults the first write into it. Each depth-3 child's `reg` is
    /// decoded with `/reserved-memory`'s own cell counts, which default to the root's.
    ///
    /// # Errors
    ///
    /// - [`Error::TooManyRegions`] when `out` is full before the last region.
    /// - [`Error::RegionOverflow`] for a pair whose `start + size` wraps the address space.
    /// - [`Error::BadValue`] for a `reg` that is not a whole number of (address, size) pairs, or cell
    ///   counts above [`MAXIMUM_CELLS`], or a cell value wider than 64 bits.
    ///
    ///
    /// # Examples
    ///
    /// QEMU's riscv64 `virt` machine, as the crate's test fixture holds it, with the two regions
    /// `OpenSBI` reserves:
    ///
    /// ```
    /// use device_tree_blob::{DeviceTreeBlob, Region};
    ///
    /// let blob = include_bytes!(concat!(
    ///     env!("CARGO_MANIFEST_DIR"),
    ///     "/tests/fixtures/qemu-riscv64-virt.dtb"
    /// ));
    /// let tree = DeviceTreeBlob::from_bytes(blob)?;
    /// let mut kept = [Region::default(); 8];
    /// let carved = tree.reserved_memory_regions(&mut kept)?;
    /// assert_eq!(
    ///     &kept[..carved],
    ///     [Region::new(0x8000_0000, 0x4_0000), Region::new(0x8004_0000, 0x4_0000)]
    /// );
    /// # Ok::<(), device_tree_blob::Error>(())
    /// ```
    pub fn reserved_memory_regions(&self, out: &mut [Region]) -> Result<usize, Error> {
        let mut bus_address_cells = 2u32;
        let mut bus_size_cells = 2u32;
        // Whether the depth-2 node now open is `/reserved-memory`. A child of the root only, as
        // `memory_regions` reads `/memory`: one nested under another node is not the reservation
        // list, and its children would be decoded with the root's cell counts rather than their
        // own parent's.
        let mut in_reserved_memory = false;
        let mut found = 0;
        let mut tokens = self.tokens();

        while let Some((depth, token)) = tokens.step()? {
            match token {
                Token::BeginNode { name } => {
                    if depth == 2 && name == b"reserved-memory" {
                        in_reserved_memory = true;
                    }
                }
                Token::EndNode => {
                    if depth == 2 && in_reserved_memory {
                        // Walked the whole /reserved-memory node; nothing more to find.
                        return Ok(found);
                    }
                }
                Token::Property { name, value } => {
                    // The root's cell counts are the defaults for the reserved-memory children,
                    // and the node may declare its own.
                    if depth == 1 || (depth == 2 && in_reserved_memory) {
                        declare_cells(name, value, &mut bus_address_cells, &mut bus_size_cells);
                    }
                    if depth == 3 && in_reserved_memory && name.is(b"reg") {
                        let remaining = out.get_mut(found..).ok_or(Error::TooManyRegions)?;
                        found +=
                            decode_regions(value, bus_address_cells, bus_size_cells, remaining)?;
                    }
                }
            }
        }
        Ok(found)
    }

    /// The initial ramdisk, if the bootloader placed one.
    ///
    /// Declared in `/chosen` as `linux,initrd-start` and `linux,initrd-end`.
    ///
    /// **This memory is the kernel's to protect.** The bootloader loaded a file into RAM for it
    /// and said where it put it. A kernel that does not reserve it lets its frame allocator hand it
    /// out to the first caller, and the initial ramdisk is destroyed before anything reads a byte of
    /// it, a bug that shows up far from its cause.
    ///
    /// # Errors
    ///
    /// [`Error::BadValue`] when `linux,initrd-start` or `linux,initrd-end` is neither 4 nor 8 bytes
    /// long.
    ///
    ///
    /// # Examples
    ///
    /// QEMU's riscv64 `virt` machine, as the crate's test fixture holds it, was started without one:
    ///
    /// ```
    /// use device_tree_blob::DeviceTreeBlob;
    ///
    /// let blob = include_bytes!(concat!(
    ///     env!("CARGO_MANIFEST_DIR"),
    ///     "/tests/fixtures/qemu-riscv64-virt.dtb"
    /// ));
    /// let tree = DeviceTreeBlob::from_bytes(blob)?;
    /// assert_eq!(tree.initial_ramdisk()?, None);
    /// # Ok::<(), device_tree_blob::Error>(())
    /// ```
    pub fn initial_ramdisk(&self) -> Result<Option<Region>, Error> {
        let mut start: Option<u64> = None;
        let mut end: Option<u64> = None;
        let mut in_chosen = false;
        let mut tokens = self.tokens();

        while let Some((depth, token)) = tokens.step()? {
            match token {
                Token::BeginNode { name } => {
                    if depth == 2 {
                        in_chosen = name == b"chosen";
                    }
                }
                Token::EndNode => {
                    if depth == 2 {
                        in_chosen = false;
                    }
                }
                Token::Property { name, value } => {
                    if depth == 2 && in_chosen {
                        if name.is(b"linux,initrd-start") {
                            start = Some(integer(value)?);
                        } else if name.is(b"linux,initrd-end") {
                            end = Some(integer(value)?);
                        }
                    }
                }
            }
        }

        Ok(match (start, end) {
            // `linux,initrd-end` is exclusive, so an empty initial ramdisk (start == end) is a
            // "no".
            (Some(start), Some(end)) if end > start => Some(Region {
                start,
                size_bytes: end - start,
            }),
            _ => None,
        })
    }

    /// **The kernel's command line**: `/chosen/bootargs`, without its terminating zero byte, or
    /// `Ok(None)` when the tree has no `/chosen` or no such property.
    ///
    /// QEMU writes it from `-append`, U-Boot from its `bootargs` variable, and a UEFI loader from
    /// the device-tree patch it applies. Only the root's own `chosen` child counts, as for
    /// [`Self::initial_ramdisk`]. A value with no zero byte is returned whole, since the property's
    /// length bounds it either way.
    ///
    /// # Errors
    ///
    /// None on a tree [`from_bytes`](Self::from_bytes) built: the value is returned raw, and that
    /// walk already accepted every token, name and nesting this one meets.
    ///
    ///
    /// # Examples
    ///
    /// QEMU's riscv64 `virt` machine, as the crate's test fixture holds it, was started without `-append`:
    ///
    /// ```
    /// use device_tree_blob::DeviceTreeBlob;
    ///
    /// let blob = include_bytes!(concat!(
    ///     env!("CARGO_MANIFEST_DIR"),
    ///     "/tests/fixtures/qemu-riscv64-virt.dtb"
    /// ));
    /// let tree = DeviceTreeBlob::from_bytes(blob)?;
    /// let command_line = tree.boot_arguments()?.unwrap_or(b"");
    /// assert_eq!(command_line, b"");
    /// # Ok::<(), device_tree_blob::Error>(())
    /// ```
    #[doc(alias = "bootargs")]
    pub fn boot_arguments(&self) -> Result<Option<&'a [u8]>, Error> {
        let mut in_chosen = false;
        let mut tokens = self.tokens();

        while let Some((depth, token)) = tokens.step()? {
            match token {
                Token::BeginNode { name } => {
                    if depth == 2 && name == b"chosen" {
                        in_chosen = true;
                    }
                }
                Token::EndNode => {
                    if depth == 2 && in_chosen {
                        return Ok(None);
                    }
                }
                Token::Property { name, value } => {
                    if depth == 2 && in_chosen && name.is(b"bootargs") {
                        let end = value.iter().position(|&b| b == 0).unwrap_or(value.len());
                        return Ok(Some(&value[..end]));
                    }
                }
            }
        }
        Ok(None)
    }

    /// The root node, the one every other node lies below.
    ///
    /// [`from_bytes`](Self::from_bytes) found it, so this reads nothing.
    ///
    /// # Examples
    ///
    /// ```
    /// use device_tree_blob::DeviceTreeBlob;
    ///
    /// let blob = include_bytes!(concat!(
    ///     env!("CARGO_MANIFEST_DIR"),
    ///     "/tests/fixtures/qemu-riscv64-virt.dtb"
    /// ));
    /// let tree = DeviceTreeBlob::from_bytes(blob)?;
    /// let root = tree.root();
    /// assert_eq!(root.name(), b"");
    /// assert_eq!(root.property(b"model"), Some(&b"riscv-virtio,qemu\0"[..]));
    /// assert!(root.children().any(|child| child.name() == b"chosen"));
    /// # Ok::<(), device_tree_blob::Error>(())
    /// ```
    pub fn root(&self) -> Node<'a> {
        Node {
            tree: *self,
            name: self.root_name,
            contents_at: self.root_at,
            depth: 1,
        }
    }

    /// Every node of the tree, the root first, in the order the blob holds them: each node before
    /// its children, and its children before its next sibling. libfdt's `fdt_next_node` walks
    /// the same order.
    ///
    /// # Examples
    ///
    /// Every node whose `status` is `okay`:
    ///
    /// ```
    /// use device_tree_blob::DeviceTreeBlob;
    ///
    /// let blob = include_bytes!(concat!(
    ///     env!("CARGO_MANIFEST_DIR"),
    ///     "/tests/fixtures/qemu-riscv64-virt.dtb"
    /// ));
    /// let tree = DeviceTreeBlob::from_bytes(blob)?;
    /// let enabled = tree
    ///     .nodes()
    ///     .filter(|node| node.property(b"status") == Some(b"okay\0"))
    ///     .count();
    /// assert_eq!(tree.nodes().next().map(|root| root.name()), Some(&b""[..]));
    /// assert!(enabled <= tree.nodes().count());
    /// # Ok::<(), device_tree_blob::Error>(())
    /// ```
    pub fn nodes(&self) -> Nodes<'a> {
        Nodes {
            tokens: Some(self.tokens()),
        }
    }

    /// The node at `path`, such as `b"/soc/serial@10000000"`; `None` when no node is there.
    ///
    /// A path starts with `/`, which alone names the root, and names one node per component below
    /// it. Each component names a child as the lookups by name do: its whole name, or, when the
    /// component carries no unit address, its name before one, so `b"/soc/serial"` finds
    /// `/soc/serial@10000000`. The first child that matches is taken. A path that does not start
    /// with `/`, or has an empty component (`b"//soc"`, `b"/soc/"`), names no node. Aliases are
    /// not resolved.
    ///
    /// # Examples
    ///
    /// ```
    /// use device_tree_blob::DeviceTreeBlob;
    ///
    /// let blob = include_bytes!(concat!(
    ///     env!("CARGO_MANIFEST_DIR"),
    ///     "/tests/fixtures/qemu-riscv64-virt.dtb"
    /// ));
    /// let tree = DeviceTreeBlob::from_bytes(blob)?;
    /// let serial = tree.find_node(b"/soc/serial@10000000").expect("QEMU's UART");
    /// assert_eq!(serial.property(b"compatible"), Some(&b"ns16550a\0"[..]));
    /// assert_eq!(tree.find_node(b"/soc/serial").map(|node| node.name()), Some(serial.name()));
    /// assert!(tree.find_node(b"/").is_some());
    /// assert!(tree.find_node(b"soc").is_none());
    /// # Ok::<(), device_tree_blob::Error>(())
    /// ```
    pub fn find_node(&self, path: &[u8]) -> Option<Node<'a>> {
        let below_root = path.strip_prefix(b"/")?;
        let mut node = self.root();
        if below_root.is_empty() {
            return Some(node);
        }
        for component in below_root.split(|&b| b == b'/') {
            node = node
                .children()
                .find(|child| names_node(component, child.name))?;
        }
        Some(node)
    }

    /// A walk over the structure block's tokens, from its first.
    fn tokens(&self) -> Tokens<'a> {
        Tokens {
            tree: *self,
            at: self.structure_offset,
            depth: 0,
        }
    }

    /// The header of the property whose `FDT_PROP` token ended just before `at`: its value's length,
    /// the offset of its name in the strings block, where its value starts, and where the next
    /// token starts (after the value's padding).
    ///
    /// Every sum is checked, because `len` and the name offset are `u32`s from the blob and a target
    /// whose `usize` is 32 bits wide can overflow them. The value's whole extent must lie inside
    /// the structure block, so a caller can slice `value_at..value_at + len` without a further check.
    fn property_header(&self, at: usize) -> Result<PropertyHeader, Error> {
        let len = be32(self.structure, at)? as usize;
        let name_offset =
            be32(self.structure, at.checked_add(4).ok_or(Error::Truncated)?)? as usize;
        let value_at = at.checked_add(8).ok_or(Error::Truncated)?;
        let value_end = value_at.checked_add(len).ok_or(Error::Truncated)?;
        if value_end > self.structure.len() {
            return Err(Error::Truncated);
        }
        Ok(PropertyHeader {
            length_bytes: len,
            name_offset,
            value_at,
            next: skip_padded(value_at, len)?,
        })
    }

    /// A property's name: the string at `name_offset` in the strings block, which must start and
    /// end inside it.
    ///
    /// The rules are libfdt's `fdt_get_string`: an offset at or past `size_dt_strings` is refused
    /// (there `FDT_ERR_BADOFFSET`, here [`Error::Truncated`]), and the search for the terminating
    /// zero byte stops at the block's end, so a name with no terminator inside the block is refused
    /// ([`Error::BadValue`], as a node name with none inside the structure block is) rather than
    /// read on into whatever follows the block. libfdt applies the bound from version 17; here it
    /// applies to every version, since `from_bytes` checks the block lies inside the blob for all
    /// of them, as libfdt's header check does.
    fn property_name(&self, name_offset: usize) -> Result<PropertyName<'a>, Error> {
        if name_offset >= self.strings.len() {
            return Err(Error::Truncated);
        }
        Ok(PropertyName {
            rest: &self.strings[name_offset..],
        })
    }

    /// A node's name: the string at `at` in the structure block, which must end inside it.
    fn node_name(&self, at: usize) -> Result<&'a [u8], Error> {
        let rest = self.structure.get(at..).ok_or(Error::Truncated)?;
        let end = rest.iter().position(|&b| b == 0).ok_or(Error::BadValue)?;
        Ok(&rest[..end])
    }
}

mod node;

pub use node::{Children, Node, Nodes, Properties, Property};

/// One slot per depth a walk can reach, and one for depth 0 above the root, so a per-depth stack
/// indexed by a depth [`Tokens`] hands out is never out of bounds.
const DEPTH_SLOTS: usize = MAXIMUM_DEPTH + 1;

/// One token of the structure block, as [`Tokens`] hands it out. `FDT_NOP` is skipped and
/// `FDT_END` ends the walk, so neither appears.
enum Token<'a> {
    /// A node opens. Its depth is its own.
    BeginNode { name: &'a [u8] },
    /// The node open at this depth closes.
    EndNode,
    /// A property of the node open at this depth: where its name starts in the strings block, and
    /// its value, which lies inside the structure block.
    Property {
        name: PropertyName<'a>,
        value: &'a [u8],
    },
}

/// A property's name, not yet read: the strings block from the name's first byte on.
///
/// The walk hands this out instead of the name, so a lookup that compares no property name never
/// scans one for its terminator, and one that does compares only as many bytes as it wants.
/// [`DeviceTreeBlob::from_bytes`] has read every name once, so each one ends inside the block.
#[derive(Clone, Copy)]
struct PropertyName<'a> {
    rest: &'a [u8],
}

impl<'a> PropertyName<'a> {
    /// Whether this is the name `wanted`: the same bytes, then the zero byte that ends the name.
    /// A `wanted` with a zero byte in it is no name, and matches nothing.
    fn is(self, wanted: &[u8]) -> bool {
        self.rest.get(wanted.len()) == Some(&0)
            && self.rest[..wanted.len()] == *wanted
            && !wanted.contains(&0)
    }

    /// The name, up to its terminating zero byte; [`Error::BadValue`] when the strings block ends
    /// first.
    fn read(self) -> Result<&'a [u8], Error> {
        let end = self
            .rest
            .iter()
            .position(|&b| b == 0)
            .ok_or(Error::BadValue)?;
        Ok(&self.rest[..end])
    }
}

/// The one walk over the structure block that every lookup uses.
///
/// It carries the checks every lookup needs in one place: each token advances the cursor, the walk
/// never leaves the structure block, the nesting balances, and it never goes deeper than
/// [`MAXIMUM_DEPTH`]. So a depth it hands out is between 0 and `MAXIMUM_DEPTH`, and a node's depth
/// is at least 1. libfdt's `fdt_next_tag` is the same shape.
#[derive(Clone, Debug)]
struct Tokens<'a> {
    tree: DeviceTreeBlob<'a>,
    at: usize,
    /// How many nodes are open.
    depth: usize,
}

impl<'a> Tokens<'a> {
    /// The next token, with the depth of the node it belongs to; `Ok(None)` at `FDT_END`.
    fn step(&mut self) -> Result<Option<(usize, Token<'a>)>, Error> {
        loop {
            let token = be32(self.tree.structure, self.at)?;
            // `be32` succeeded, so four bytes lay inside the block at `at`, and this cannot wrap.
            self.at += 4;
            match token {
                FDT_BEGIN_NODE => {
                    let name = self.tree.node_name(self.at)?;
                    self.at = skip_name(self.at, name)?;
                    if self.depth == MAXIMUM_DEPTH {
                        return Err(Error::TooDeep);
                    }
                    self.depth += 1;
                    return Ok(Some((self.depth, Token::BeginNode { name })));
                }
                FDT_END_NODE => {
                    let depth = self.depth;
                    self.depth = depth.checked_sub(1).ok_or(Error::BadStructure)?;
                    return Ok(Some((depth, Token::EndNode)));
                }
                FDT_PROP => {
                    let header = self.tree.property_header(self.at)?;
                    self.at = header.next;
                    let name = self.tree.property_name(header.name_offset)?;
                    // `property_header` checked the value lies inside the structure block.
                    let value = &self.tree.structure
                        [header.value_at..header.value_at + header.length_bytes];
                    return Ok(Some((self.depth, Token::Property { name, value })));
                }
                FDT_NOP => {}
                FDT_END if self.depth == 0 => return Ok(None),
                FDT_END => return Err(Error::BadStructure),
                other => return Err(Error::BadToken(other)),
            }
        }
    }
}

/// Record a `#address-cells` or `#size-cells` declaration into the counts the node declares for
/// its children. A declaration that is not exactly one cell is ignored, so the inherited width
/// stands: a shorter value read as a cell would take the padding and the next token as the count.
fn declare_cells(
    name: PropertyName<'_>,
    value: &[u8],
    bus_address_cells: &mut u32,
    bus_size_cells: &mut u32,
) {
    let Ok(cell) = <[u8; 4]>::try_from(value) else {
        return;
    };
    if name.is(b"#address-cells") {
        *bus_address_cells = u32::from_be_bytes(cell);
    } else if name.is(b"#size-cells") {
        *bus_size_cells = u32::from_be_bytes(cell);
    }
}

/// Whether `wanted` names the node called `node_name`: the same name, or, when `wanted` carries no
/// unit address, the same name followed by `@` and one. libfdt's `fdt_nodename_eq_` is the same
/// rule. An empty `wanted` names nothing.
fn names_node(wanted: &[u8], node_name: &[u8]) -> bool {
    match node_name.strip_prefix(wanted) {
        Some(rest) if !wanted.is_empty() => {
            rest.is_empty() || (rest[0] == b'@' && !wanted.contains(&b'@'))
        }
        _ => false,
    }
}

/// Whether a `compatible` value, a list of zero byte-terminated strings, lists `entry`. The empty piece
/// after the final zero byte is not an entry, so an empty `entry` matches nothing.
fn lists_entry(value: &[u8], entry: &[u8]) -> bool {
    value
        .split(|&b| b == 0)
        .any(|piece| !piece.is_empty() && piece == entry)
}

/// An integer property.
///
/// The specification lets these be either 32 or 64 bits wide, and **the only way to tell is the
/// property's length**. QEMU writes `linux,initrd-start` as 8 bytes; a 32-bit platform writes 4.
/// Assume one and you silently misread the other.
fn integer(value: &[u8]) -> Result<u64, Error> {
    match value.len() {
        4 => Ok(be32(value, 0)? as u64),
        8 => be64(value, 0),
        _ => Err(Error::BadValue),
    }
}

/// Decode a `reg` property: a packed list of (address, size) pairs, where each value is `cells`
/// 32-bit big-endian words concatenated.
///
/// A cell count above [`MAXIMUM_CELLS`], or a `value` that is not a whole number of pairs, is
/// [`Error::BadValue`], as libfdt and Linux refuse both.
fn decode_regions(
    value: &[u8],
    bus_address_cells: u32,
    bus_size_cells: u32,
    out: &mut [Region],
) -> Result<usize, Error> {
    if bus_address_cells > MAXIMUM_CELLS || bus_size_cells > MAXIMUM_CELLS {
        return Err(Error::BadValue);
    }
    // At most four cells each, so neither product nor the sum can overflow.
    let start_bytes = bus_address_cells as usize * 4;
    let pair_bytes = start_bytes + bus_size_cells as usize * 4;
    if pair_bytes == 0 {
        return Ok(0);
    }
    if !value.len().is_multiple_of(pair_bytes) {
        return Err(Error::BadValue);
    }

    let mut n = 0;
    for pair in value.chunks_exact(pair_bytes) {
        let (start, size) = pair.split_at(start_bytes);
        let start = cells(start)?;
        let size = cells(size)?;

        // A zero-size region is legal and useless. Skip it rather than handing the allocator an
        // empty range to reason about.
        if size == 0 {
            continue;
        }

        // A region that runs past the top of the address space is not a region. Refused rather
        // than skipped, because a zero-size entry is a *legal* thing firmware writes and this is
        // not: see `Error::RegionOverflow`.
        if start.checked_add(size).is_none() {
            return Err(Error::RegionOverflow);
        }

        *out.get_mut(n).ok_or(Error::TooManyRegions)? = Region {
            start,
            size_bytes: size,
        };
        n += 1;
    }

    Ok(n)
}

/// Concatenate 32-bit big-endian cells into one u64. A nonzero cell above the low two is a value
/// wider than 64 bits, which a [`Region`] cannot hold, so it is [`Error::BadValue`] rather than
/// truncated to its low 64 bits as Linux's `of_read_number` does.
fn cells(value: &[u8]) -> Result<u64, Error> {
    let mut number = 0u64;
    let (whole, _) = value.as_chunks::<4>();
    for cell in whole {
        if number >> 32 != 0 {
            return Err(Error::BadValue);
        }
        // An add, not an or: the shift leaves the low 32 bits zero, so the two agree, and an add
        // has no twin (`^` reads the same as `|` here) for a mutation run to report as alive.
        number = (number << 32) + u64::from(u32::from_be_bytes(*cell));
    }
    Ok(number)
}

/// A property header, as [`DeviceTreeBlob::property_header`] reads it.
struct PropertyHeader {
    length_bytes: usize,
    name_offset: usize,
    value_at: usize,
    next: usize,
}

/// Everything in the structure block is padded to a 4-byte boundary. `None` for a length so close
/// to `usize::MAX` that rounding up wraps, which only a 32-bit target's `u32` length can reach.
fn align4(n: usize) -> Option<usize> {
    n.checked_add(3).map(|up| up & !3)
}

/// Where the token after `n` bytes of padded data at `at` starts, or `Truncated` when the sum wraps.
fn skip_padded(at: usize, n: usize) -> Result<usize, Error> {
    align4(n)
        .and_then(|padded| at.checked_add(padded))
        .ok_or(Error::Truncated)
}

/// Where the token after a node's name starts: the name, its zero byte, and the padding to four bytes.
fn skip_name(at: usize, name: &[u8]) -> Result<usize, Error> {
    skip_padded(at, name.len().checked_add(1).ok_or(Error::Truncated)?)
}

/// The cursor arithmetic, on the values a 32-bit target's `usize` would overflow, which a 64-bit
/// host cannot reach through a blob (a blob's lengths are `u32`).
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cursor_step_that_would_wrap_is_refused_and_a_normal_one_is_not() {
        assert_eq!(skip_padded(8, 5), Ok(16));
        assert_eq!(skip_padded(0, 0), Ok(0));
        assert_eq!(skip_padded(usize::MAX - 2, 4), Err(Error::Truncated));
        assert_eq!(skip_padded(0, usize::MAX - 2), Err(Error::Truncated));
        assert_eq!(skip_padded(0, usize::MAX), Err(Error::Truncated));
        assert_eq!(align4(usize::MAX - 3), Some(usize::MAX - 3));
        assert_eq!(align4(usize::MAX - 2), None);
        assert_eq!(skip_name(4, b"abc"), Ok(8));
    }
}

/// Machine-checked proofs, with Kani, of the device-tree parser's readers.
///
/// The device tree is untrusted boot input. The leaves are proved for every input: the big-endian
/// readers every field goes through, the padding helper, `cells` and `decode_regions`. `align4` is
/// proved for every `usize`, and overflows only within 3 of `usize::MAX`, where no caller reaches:
/// every length it is given comes from a blob, which is at most `MAXIMUM_TOTAL_SIZE_BYTES` through
/// `from_pointer` and at most `u32::MAX` bytes of header-declared length otherwise. Above the leaves,
/// `from_bytes` and one step of the token walk are proved total over blobs of a bounded size,
/// which is as far as bounded model checking reaches over a structure of real size; the fuzz target
/// `device_tree_blob_walk` covers the whole walk from the other side.
#[cfg(kani)]
mod verification;
