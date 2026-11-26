//! The general traversal: [`DeviceTreeBlob::root`], [`DeviceTreeBlob::nodes`],
//! [`DeviceTreeBlob::find_node`], and a node's children and properties.
//!
//! The riscv64 fixture ships with its source, `qemu-riscv64-virt.dts`, so these tests read the
//! node paths and property names from that text and check the walk over the blob finds the same
//! ones, in the same order.

use device_tree_blob::{DeviceTreeBlob, Node};

const RISCV: &[u8] = include_bytes!("fixtures/qemu-riscv64-virt.dtb");
const RISCV_SOURCE: &str = include_str!("fixtures/qemu-riscv64-virt.dts");
const AARCH64: &[u8] = include_bytes!("fixtures/qemu-aarch64-virt.dtb");

/// Each node of the source, as its path and its property names, in source order.
fn source_nodes() -> Vec<(String, Vec<String>)> {
    let mut nodes: Vec<(String, Vec<String>)> = Vec::new();
    let mut open: Vec<usize> = Vec::new();
    for line in RISCV_SOURCE.lines().map(str::trim) {
        if line.starts_with("//") || line.starts_with("/dts-v1/") || line.is_empty() {
            continue;
        }
        if let Some(name) = line.strip_suffix(" {") {
            let path = match open.last() {
                None => String::from("/"),
                Some(&parent) if nodes[parent].0 == "/" => format!("/{name}"),
                Some(&parent) => format!("{}/{name}", nodes[parent].0),
            };
            open.push(nodes.len());
            nodes.push((path, Vec::new()));
        } else if line == "};" {
            open.pop();
        } else {
            let name = line
                .split([' ', ';'])
                .next()
                .expect("a property line has a name");
            let node = *open.last().expect("a property inside a node");
            nodes[node].1.push(name.to_string());
        }
    }
    nodes
}

/// The names of a node's properties, as text.
fn property_names(node: Node<'_>) -> Vec<String> {
    node.properties()
        .map(|property| String::from_utf8(property.name().to_vec()).unwrap())
        .collect()
}

/// Every node below `node`, by path, depth first, as the children walk reaches them.
fn paths_below(node: Node<'_>, path: &str, out: &mut Vec<String>) {
    for child in node.children() {
        let name = core::str::from_utf8(child.name()).unwrap();
        let child_path = if path == "/" {
            format!("/{name}")
        } else {
            format!("{path}/{name}")
        };
        out.push(child_path.clone());
        paths_below(child, &child_path, out);
    }
}

/// **Every node and every property the source names, and nothing else, in the source's order.**
/// `nodes` and a recursive `children` walk each reach the nodes in the order the source lists
/// them, `find_node` finds each by its path, and its properties are the source's.
#[test]
fn the_walk_finds_every_node_and_property_of_the_source() {
    let tree = DeviceTreeBlob::from_bytes(RISCV).unwrap();
    let source = source_nodes();
    assert_eq!(source.len(), 34);

    let mut walked = vec![String::from("/")];
    paths_below(tree.root(), "/", &mut walked);
    let expected: Vec<String> = source.iter().map(|(path, _)| path.clone()).collect();
    assert_eq!(walked, expected);

    let names: Vec<&[u8]> = tree.nodes().map(|node| node.name()).collect();
    assert_eq!(names.len(), source.len());
    for (name, path) in names.iter().zip(&expected) {
        let last = path.rsplit('/').next().unwrap();
        assert_eq!(*name, last.as_bytes(), "{path}");
    }

    for (path, properties) in &source {
        let node = tree
            .find_node(path.as_bytes())
            .unwrap_or_else(|| panic!("{path}"));
        assert_eq!(&property_names(node), properties, "{path}");
        for name in properties {
            assert!(node.property(name.as_bytes()).is_some(), "{path} {name}");
        }
    }
}

/// The aarch64 fixture has no source here, so this pins its node count, which the review measured,
/// and checks that every node `nodes` reaches is also reached from the root by `children`.
#[test]
fn the_aarch64_walk_reaches_every_node_both_ways() {
    let tree = DeviceTreeBlob::from_bytes(AARCH64).unwrap();
    assert_eq!(tree.nodes().count(), 57);
    let mut below = Vec::new();
    paths_below(tree.root(), "/", &mut below);
    assert_eq!(below.len() + 1, 57);
}

/// A path names a node by the lookups' rule: its whole name, or the name before its unit
/// address. A path must start with `/`, and an empty component names nothing.
#[test]
fn a_path_names_a_node_by_the_unit_address_rule() {
    let tree = DeviceTreeBlob::from_bytes(RISCV).unwrap();
    let serial = tree.find_node(b"/soc/serial@10000000").unwrap();
    assert_eq!(serial.name(), b"serial@10000000");
    assert_eq!(
        tree.find_node(b"/soc/serial").map(|node| node.name()),
        Some(&b"serial@10000000"[..])
    );
    assert_eq!(tree.find_node(b"/").map(|node| node.name()), Some(&b""[..]));
    for path in [
        &b""[..],
        b"soc",
        b"//soc",
        b"/soc/",
        b"/so",
        b"/soc/serial@",
        b"/soc/serial@1",
        b"/soc/serial@10000000/x",
        b"/chosen\0",
    ] {
        assert!(tree.find_node(path).is_none(), "{:?}", path.escape_ascii());
    }
}

/// A node's own property, never its parent's or a child's, and the walks end and stay ended.
#[test]
fn a_node_reads_only_its_own_properties_and_the_walks_stay_ended() {
    let tree = DeviceTreeBlob::from_bytes(RISCV).unwrap();
    let root = tree.root();
    assert!(root.property(b"#address-cells").is_some());
    let soc = tree.find_node(b"/soc").unwrap();
    assert_eq!(soc.property(b"model"), None, "the root's, not the bus's");
    assert_eq!(
        root.property(b"interrupts"),
        None,
        "a device's, not the root's"
    );
    assert_eq!(
        root.property(b"#address"),
        None,
        "a prefix of a name is not the name"
    );

    let mut children = soc.children();
    while children.next().is_some() {}
    assert!(children.next().is_none());
    let mut properties = soc.properties();
    while properties.next().is_some() {}
    assert!(properties.next().is_none());
    let mut nodes = tree.nodes();
    while nodes.next().is_some() {}
    assert!(nodes.next().is_none());

    let leaf = tree.find_node(b"/soc/serial@10000000").unwrap();
    assert_eq!(leaf.children().count(), 0);
    let first = leaf.properties().next().unwrap();
    assert_eq!(leaf.property(first.name()), Some(first.value()));
}
