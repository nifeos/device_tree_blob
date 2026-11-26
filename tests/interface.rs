//! The crate's common traits and its `Debug` output, read on the fixtures.

use device_tree_blob::{DeviceTreeBlob, Error, Region};
use std::collections::HashSet;

const RISCV: &[u8] = include_bytes!("fixtures/qemu-riscv64-virt.dtb");

/// **The tree is `Copy`, so two consumers each hold one and read the same answers.**
#[test]
fn a_tree_copies_and_both_copies_answer_alike() {
    let tree = DeviceTreeBlob::from_bytes(RISCV).unwrap();
    let copy = tree;
    let mut first = [Region::default(); 4];
    let mut second = [Region::default(); 4];
    assert_eq!(
        tree.memory_regions(&mut first),
        copy.memory_regions(&mut second)
    );
    assert_eq!(first, second);
}

/// **`Debug` prints the sizes and the block offsets, never the blob's bytes.**
///
/// The derived form printed every byte of the blob and the structure block again, which for a
/// blob of a mebibyte is a mebibyte of log line.
#[test]
fn debug_prints_the_layout_not_the_bytes() {
    let tree = DeviceTreeBlob::from_bytes(RISCV).unwrap();
    let printed = format!("{tree:?}");
    assert!(printed.starts_with("DeviceTreeBlob {"), "{printed}");
    assert!(
        printed.contains(&format!("total_size: {}", RISCV.len())),
        "{printed}"
    );
    for field in [
        "structure_offset: ",
        "structure_size: ",
        "strings_offset: ",
        "strings_size: ",
        "reservations_offset: ",
    ] {
        assert!(printed.contains(field), "{printed} lacks {field}");
    }
    assert!(printed.len() < 200, "{printed}");
}

/// **A node prints its name, depth and offset, never the blob behind it.**
#[test]
fn a_node_prints_its_name_and_place_not_the_bytes() {
    let tree = DeviceTreeBlob::from_bytes(RISCV).unwrap();
    let serial = tree.find_node(b"/soc/serial").unwrap();
    let printed = format!("{serial:?}");
    assert!(printed.starts_with("Node {"), "{printed}");
    assert!(printed.contains("name: serial@10000000"), "{printed}");
    assert!(printed.contains("depth: 3"), "{printed}");
    assert!(printed.contains("contents_offset: "), "{printed}");
    assert!(printed.len() < 100, "{printed}");
}

/// **A region sorts by address and keeps in a set, and an error keeps in a set.**
#[test]
fn regions_sort_by_start_then_size_and_hash() {
    let mut map = [
        Region::new(0x9000_0000, 0x1000),
        Region::new(0x8000_0000, 0x2000),
        Region::new(0x8000_0000, 0x1000),
    ];
    map.sort();
    assert_eq!(
        map,
        [
            Region::new(0x8000_0000, 0x1000),
            Region::new(0x8000_0000, 0x2000),
            Region::new(0x9000_0000, 0x1000),
        ]
    );
    let set: HashSet<Region> = map.iter().copied().chain(map.iter().copied()).collect();
    assert_eq!(set.len(), 3);
    assert_eq!(Region::default(), Region::new(0, 0));

    let errors: HashSet<Error> = [Error::Truncated, Error::Truncated, Error::BadValue]
        .into_iter()
        .collect();
    assert_eq!(errors.len(), 2);
}
