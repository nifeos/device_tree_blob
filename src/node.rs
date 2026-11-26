//! The node handle and the walks over nodes, children and properties.

use crate::{DeviceTreeBlob, Token, Tokens};

/// One node of the tree: a handle to where it lies in the blob, which reads nothing until asked.
///
/// [`DeviceTreeBlob::root`], [`DeviceTreeBlob::nodes`], [`DeviceTreeBlob::find_node`] and
/// [`Node::children`] hand one out. It is `Copy` and borrows the blob, as the tree does, and every
/// walk from it finds only what [`DeviceTreeBlob::from_bytes`] accepted, so none of its methods
/// fails.
#[derive(Clone, Copy)]
pub struct Node<'a> {
    pub(crate) tree: DeviceTreeBlob<'a>,
    pub(crate) name: &'a [u8],
    /// Where the node's properties start, just after its name.
    pub(crate) contents_at: usize,
    /// The node's own depth: 1 for the root.
    pub(crate) depth: usize,
}

impl core::fmt::Debug for Node<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Node")
            .field("name", &self.name.escape_ascii())
            .field("depth", &self.depth)
            .field("contents_offset", &self.contents_at)
            .finish()
    }
}

impl<'a> Node<'a> {
    /// The node's name, unit address included: `b"serial@10000000"`, or `b""` for the root.
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
    /// let serial = tree.find_node(b"/soc/serial").expect("QEMU's UART");
    /// assert_eq!(serial.name(), b"serial@10000000");
    /// # Ok::<(), device_tree_blob::Error>(())
    /// ```
    pub fn name(&self) -> &'a [u8] {
        self.name
    }

    /// The raw value of the node's own property `name`; `None` when the node has none. Nothing is
    /// inherited from a parent.
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
    /// let chosen = tree.find_node(b"/chosen").expect("QEMU writes /chosen");
    /// assert!(chosen.property(b"stdout-path").is_some());
    /// assert_eq!(chosen.property(b"no-such-property"), None);
    /// # Ok::<(), device_tree_blob::Error>(())
    /// ```
    pub fn property(&self, name: &[u8]) -> Option<&'a [u8]> {
        let mut tokens = self.walk();
        while let Ok(Some((depth, Token::Property { name: found, value }))) = tokens.step() {
            if depth == self.depth && found.is(name) {
                return Some(value);
            }
        }
        None
    }

    /// The node's own properties, in the order the blob holds them.
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
    /// assert!(root.properties().any(|property| property.name() == b"#address-cells"));
    /// for property in root.properties() {
    ///     assert!(!property.name().is_empty());
    /// }
    /// # Ok::<(), device_tree_blob::Error>(())
    /// ```
    pub fn properties(&self) -> Properties<'a> {
        Properties {
            tokens: Some(self.walk()),
            depth: self.depth,
        }
    }

    /// The node's children, in the order the blob holds them; their own children are not visited.
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
    /// let cpus = tree.find_node(b"/cpus").expect("QEMU writes /cpus");
    /// let harts = cpus
    ///     .children()
    ///     .filter(|child| child.property(b"device_type") == Some(b"cpu\0"))
    ///     .count();
    /// assert!(harts >= 1);
    /// # Ok::<(), device_tree_blob::Error>(())
    /// ```
    pub fn children(&self) -> Children<'a> {
        Children {
            tokens: Some(self.walk()),
            depth: self.depth,
        }
    }

    /// A walk over the node's contents, from its first property.
    fn walk(&self) -> Tokens<'a> {
        Tokens {
            tree: self.tree,
            at: self.contents_at,
            depth: self.depth,
        }
    }
}

/// One property of a node: its name and its raw value, as the blob holds them.
///
/// [`Node::properties`] hands these out.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Property<'a> {
    pub(crate) name: &'a [u8],
    pub(crate) value: &'a [u8],
}

impl<'a> Property<'a> {
    /// The property's name, from the strings block: `b"compatible"`.
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
    /// let serial = tree.find_node(b"/soc/serial").expect("QEMU's UART");
    /// let compatible = serial
    ///     .properties()
    ///     .find(|property| property.name() == b"compatible")
    ///     .expect("the UART says what it is");
    /// assert_eq!(compatible.value(), b"ns16550a\0");
    /// # Ok::<(), device_tree_blob::Error>(())
    /// ```
    pub fn name(&self) -> &'a [u8] {
        self.name
    }

    /// The property's raw value, which may be empty: a property with no value is a flag.
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
    /// let serial = tree.find_node(b"/soc/serial").expect("QEMU's UART");
    /// let compatible = serial
    ///     .properties()
    ///     .find(|property| property.name() == b"compatible")
    ///     .expect("the UART says what it is");
    /// assert_eq!(compatible.value(), b"ns16550a\0");
    /// # Ok::<(), device_tree_blob::Error>(())
    /// ```
    pub fn value(&self) -> &'a [u8] {
        self.value
    }
}

/// Every node of a tree, in the order the blob holds them; [`DeviceTreeBlob::nodes`].
#[derive(Clone, Debug)]
pub struct Nodes<'a> {
    /// `None` once the walk has ended.
    pub(crate) tokens: Option<Tokens<'a>>,
}

impl<'a> Iterator for Nodes<'a> {
    type Item = Node<'a>;

    fn next(&mut self) -> Option<Node<'a>> {
        let tokens = self.tokens.as_mut()?;
        loop {
            match tokens.step() {
                Ok(Some((depth, Token::BeginNode { name }))) => {
                    return Some(Node {
                        tree: tokens.tree,
                        name,
                        contents_at: tokens.at,
                        depth,
                    });
                }
                Ok(Some(_)) => {}
                // `from_bytes` walked the same tokens, so the walk meets no error; one would end
                // it.
                Ok(None) | Err(_) => {
                    self.tokens = None;
                    return None;
                }
            }
        }
    }
}

impl core::iter::FusedIterator for Nodes<'_> {}

/// The children of one node; [`Node::children`].
#[derive(Clone, Debug)]
pub struct Children<'a> {
    /// `None` once the node has closed.
    pub(crate) tokens: Option<Tokens<'a>>,
    /// The parent's depth.
    pub(crate) depth: usize,
}

impl<'a> Iterator for Children<'a> {
    type Item = Node<'a>;

    fn next(&mut self) -> Option<Node<'a>> {
        let tokens = self.tokens.as_mut()?;
        loop {
            match tokens.step() {
                Ok(Some((depth, Token::BeginNode { name }))) if depth == self.depth + 1 => {
                    return Some(Node {
                        tree: tokens.tree,
                        name,
                        contents_at: tokens.at,
                        depth,
                    });
                }
                Ok(Some((depth, Token::EndNode))) if depth == self.depth => break,
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => break,
            }
        }
        self.tokens = None;
        None
    }
}

impl core::iter::FusedIterator for Children<'_> {}

/// The properties of one node; [`Node::properties`].
#[derive(Clone, Debug)]
pub struct Properties<'a> {
    /// `None` once the node's properties have ended.
    pub(crate) tokens: Option<Tokens<'a>>,
    /// The node's depth.
    pub(crate) depth: usize,
}

impl<'a> Iterator for Properties<'a> {
    type Item = Property<'a>;

    fn next(&mut self) -> Option<Property<'a>> {
        let tokens = self.tokens.as_mut()?;
        // A node's properties come before its first child, as `from_bytes` checked, so the first
        // token that is not a property of this node ends them.
        if let Ok(Some((depth, Token::Property { name, value }))) = tokens.step()
            && depth == self.depth
            && let Ok(name) = name.read()
        {
            return Some(Property { name, value });
        }
        self.tokens = None;
        None
    }
}

impl core::iter::FusedIterator for Properties<'_> {}
