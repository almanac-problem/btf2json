//! Code that directly works with BTF type information.
//!
//! This is the only code that should be affected by a change in our backend
//! BTF library.
//!
//! Provides a stable API for working with BTF to the rest of the crate.
// TODO: Still way too leaky...

use crate::cli::Cli;
use crate::elf;
use crate::image::raw::RawImage;
use crate::image::traits::MemoryImage;

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::convert::TryFrom;
use std::fmt;
use std::fs::File;
use std::iter::Iterator;
use std::path::Path;
use std::rc::Rc;

use anyhow::{bail, Context, Error, Result};
use btf_rs::BtfType;
use memmap2::Mmap;

const BTF_MAGIC_BE: [u8; 2] = [0xeb, 0x9f];
const BTF_MAGIC_LE: [u8; 2] = [0x9f, 0xeb];
const BTF_HDR_LEN_MIN: usize = 24;
/// Arbitrary plausible minimum for BTF section size
const BTF_SIZE_MIN: usize = 100_000;
/// Arbitrary plausible maximum for BTF section size
const BTF_SIZE_MAX: usize = 50_000_000;

/// Represents a partitioning of the types into the categories that Volatility
/// distinguishes between, plus a processed view of all typedefs. The starting
/// point for generating an ISF file.
pub type VolIdSets = (BTreeSet<Id>, BTreeSet<Id>, BTreeSet<Id>, Typedefs);

#[derive(Debug)]
pub enum SourceRaw {
    Mapped(Mmap),
    Carved(Vec<u8>),
}

impl AsRef<[u8]> for SourceRaw {
    fn as_ref(&self) -> &[u8] {
        match self {
            SourceRaw::Carved(bytes) => bytes,
            SourceRaw::Mapped(mmap) => mmap,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Endian {
    Big,
    Little,
}

/// Representation of a BTF file.
pub struct Btf {
    pub endian: Endian,
    raw: Rc<SourceRaw>,
    name: String,
    btf: btf_rs::Btf,
}

impl TryFrom<&Cli> for Btf {
    type Error = Error;

    fn try_from(cli: &Cli) -> Result<Self> {
        if cli.btf.is_some() {
            log::debug!("Provided separate file for BTF, extracing section.");
            let file_path: &Path = Path::new(cli.btf.as_ref().unwrap());
            let file = File::open(file_path)?;
            let mmap = unsafe { Mmap::map(&file)? };
            let (endian, btf_sec) = get_btf_section(&mmap)?;
            let btf = btf_rs::Btf::from_bytes(btf_sec)?;
            Ok(Btf {
                endian,
                raw: Rc::new(SourceRaw::Mapped(mmap)),
                name: file_path
                    .file_name()
                    .context("")?
                    .to_owned()
                    .into_string()
                    .expect(""),
                btf,
            })
        } else if cli.image.is_some() {
            log::debug!("Got memory image, extracting BTF section.");

            // TODO: Abstract after other source types are implemented
            let image = RawImage::open(cli.image.as_ref().unwrap())?;
            let (endian, btf_bytes) = carve_btf(&image)?;
            let btf = btf_rs::Btf::from_bytes(btf_bytes)?;
            Ok(Btf {
                endian,
                raw: Rc::new(SourceRaw::Carved(btf_bytes.to_vec())),
                name: format!("carved-from-{}", image.name()),
                btf,
            })
        } else {
            bail!("No source for BTF information provided!")
        }
    }
}

impl Btf {
    const MAX_BTF_ID: Id = Id(0xFFFFFFFF);

    /// Returns the memory-mapped BTF file.
    pub fn raw(&self) -> Rc<SourceRaw> {
        self.raw.clone()
    }

    /// Returns the name of the file that the BTF information was obtained from.
    pub fn name(&self) -> &String {
        &self.name
    }

    /// Starts at the given node in the type tree and walks up to the root.
    pub fn resolve_type_chain(&self, tx: TypeEx) -> ResolvedType {
        let mut rt = ResolvedType {
            path: ResolutionPath::new(),
            tx,
        };
        rt.path.record_node(&rt.tx);
        loop {
            let Some(trait_object) = rt.tx.t.t.as_btf_type() else {
                return rt;
            };
            rt.tx = match (
                self.btf.resolve_chained_type(trait_object),
                trait_object.get_type_id(),
            ) {
                (Ok(t), Ok(id)) => {
                    let tx = TypeEx {
                        t: t.into(),
                        id: id.into(),
                    };
                    rt.path.record_node(&tx);
                    tx
                }
                _ => return rt,
            };
        }
    }

    /// Returns all names of the type with `id`.
    ///
    /// Optionally, uses `typedefs` to derive alternative names for the type.
    /// Only typedefs that reach the type without indirections lead to
    /// alternative names.
    pub fn get_names_by_id(&self, id: Id, typedefs: Option<&Typedefs>) -> Result<Vec<String>> {
        let mut names = Vec::new();
        let t = self.btf.resolve_type_by_id(id.into())?;

        if let btf_rs::Type::Void = t {
            log::trace!("[{}] is void", id);
            return Ok(vec![String::from(t.name())]);
        };

        names.push(match self.get_strtab_entry_by_id(id) {
            Ok(name) => {
                log::trace!("[{}] name strtab: {}", id, &name);
                name
            }
            Err(_) => {
                log::trace!("[{}] is anonymous", id);
                format!("unnamed_{}_{}", t.name(), id)
            }
        });

        let Some(tds_bk) = typedefs.and_then(|td| td.bk.get(&id)) else {
            log::trace!("[{}] has no bk typedefs", id);
            return Ok(names);
        };
        log::trace!("[{}] bk typedefs: {:?}", id, tds_bk);
        names.extend(tds_bk.iter().filter_map(|td_bk| {
            let Some(rt) = typedefs.and_then(|td| td.fw.get(td_bk)) else {
                panic!(
                    "{}",
                    format!(
                        "Inconsistency in typedefs: no fwd typedef entry for {}",
                        td_bk
                    )
                );
            };
            if rt.path.has_indirections() {
                log::trace!("[{}] omiting typedef {} due to indirections", id, td_bk);
                None
            } else {
                let name = self.get_strtab_entry_by_id(*td_bk).unwrap();
                log::trace!("[{}] name typedef: {}", id, name);
                Some(name)
            }
        }));

        Ok(names)
    }

    /// Returns the string table entry of the type with `id`.
    ///
    /// Fails if the entry is empty.
    pub fn get_strtab_entry_by_id(&self, id: Id) -> Result<String> {
        let t = self.btf.resolve_type_by_id(id.into())?;
        let t = t
            .as_btf_type()
            .context(format!("Type {} has no string table entry.", id))?;
        let name = self.btf.resolve_name(t)?;
        if name.is_empty() {
            bail!(format!("Type {} has no name.", id))
        } else {
            Ok(name)
        }
    }

    /// Returns the type with the given `id`.
    pub fn get_type_by_id(&self, id: Id) -> Result<Type> {
        Ok(Type {
            t: self.btf.resolve_type_by_id(id.into())?,
        })
    }

    /// Returns a partitioning of the types into the categories that Volatility
    /// distinguishes between as well as a processed view of all typedefs.
    ///
    /// Volatility distinguishes between user types, enum types, and base types.
    pub fn gen_vol_id_sets(&self) -> Result<VolIdSets> {
        let mut basic_ids: BTreeSet<Id> = BTreeSet::new();
        let mut enum_ids: BTreeSet<Id> = BTreeSet::new();
        let mut user_ids: BTreeSet<Id> = BTreeSet::new();
        let mut typedefs_bk: HashMap<Id, Vec<Id>> = HashMap::new();
        let mut typedefs_fw: HashMap<Id, ResolvedType> = HashMap::new();

        for id in Id::range(Id(0), Self::MAX_BTF_ID) {
            match self.get_type_by_id(id) {
                Ok(t) => {
                    if t.is_base() {
                        log::trace!("[{}] is base", id);
                        basic_ids.insert(id);
                    } else if t.is_enum() {
                        log::trace!("[{}] is enum", id);
                        enum_ids.insert(id);
                    } else if t.is_user() {
                        log::trace!("[{}] is user", id);
                        user_ids.insert(id);
                    } else if t.is_typedef() {
                        let rt = self.resolve_type_chain(TypeEx { t, id });
                        log::trace!(
                            "[{}] is typedef: path {:?}, target {}",
                            id,
                            rt.path,
                            rt.tx.id
                        );
                        if let std::collections::hash_map::Entry::Vacant(e) =
                            typedefs_bk.entry(rt.tx.id)
                        {
                            e.insert(vec![id]);
                        } else {
                            let v = typedefs_bk.get_mut(&rt.tx.id).unwrap();
                            v.push(id);
                        }
                        typedefs_fw.insert(id, rt);
                    }
                }
                Err(_) => {
                    log::debug!("Section defines {} types", u32::from(id) - 1);
                    break;
                }
            }
        }
        log::debug!(
            "ID sets: base {}, enum {}, user {}",
            basic_ids.len(),
            enum_ids.len(),
            user_ids.len()
        );

        Ok((
            user_ids,
            enum_ids,
            basic_ids,
            Typedefs {
                fw: typedefs_fw,
                bk: typedefs_bk,
            },
        ))
    }
}

/// Representation of a BTF type.
// TODO: Library leaks here...
#[derive(Debug, Clone)]
pub struct Type {
    pub t: btf_rs::Type,
}

impl From<btf_rs::Type> for Type {
    fn from(type_: btf_rs::Type) -> Self {
        Self { t: type_ }
    }
}

impl Type {
    pub fn as_enum(&self) -> Option<&dyn Enum> {
        match &self.t {
            btf_rs::Type::Enum(e) => Some(e),
            btf_rs::Type::Enum64(e64) => Some(e64),
            _ => None,
        }
    }

    pub fn as_has_members(&self) -> Option<&dyn HasMembers> {
        match &self.t {
            btf_rs::Type::Struct(s) => Some(s),
            btf_rs::Type::Union(u) => Some(u),
            _ => None,
        }
    }

    fn is_typedef(&self) -> bool {
        matches!(self.t, btf_rs::Type::Typedef(_))
    }

    pub fn is_func(&self) -> bool {
        matches!(self.t, btf_rs::Type::FuncProto(_))
    }

    pub fn is_base(&self) -> bool {
        matches!(
            self.t,
            btf_rs::Type::Void | btf_rs::Type::Int(_) | btf_rs::Type::Float(_)
        )
    }

    pub fn is_enum(&self) -> bool {
        matches!(self.t, btf_rs::Type::Enum(_) | btf_rs::Type::Enum64(_))
    }

    fn is_user(&self) -> bool {
        matches!(self.t, btf_rs::Type::Struct(_) | btf_rs::Type::Union(_))
    }

    pub fn is_struct(&self) -> bool {
        matches!(self.t, btf_rs::Type::Struct(_))
    }

    pub fn is_fwd(&self) -> bool {
        matches!(self.t, btf_rs::Type::Fwd(_))
    }

    pub fn is_fwd_struct(&self) -> bool {
        matches!(&self.t, btf_rs::Type::Fwd(fwd) if fwd.is_struct())
    }

    pub fn is_fwd_union(&self) -> bool {
        matches!(&self.t, btf_rs::Type::Fwd(fwd) if fwd.is_union())
    }

    pub fn is_union(&self) -> bool {
        matches!(self.t, btf_rs::Type::Union(_))
    }

    pub fn signed(&self) -> Option<bool> {
        match &self.t {
            btf_rs::Type::Int(i) => Some(i.is_signed()),
            btf_rs::Type::Enum(e) => Some(e.is_signed()),
            btf_rs::Type::Enum64(e64) => Some(e64.is_signed()),
            btf_rs::Type::Void => Some(false),
            btf_rs::Type::Ptr(_) => Some(false),
            btf_rs::Type::Float(_) => Some(true),
            _ => None,
        }
    }

    pub fn size(&self) -> Option<usize> {
        Some(match &self.t {
            btf_rs::Type::Int(i) => i.size(),
            btf_rs::Type::Enum(e) => e.size(),
            btf_rs::Type::Union(u) => u.size(),
            btf_rs::Type::Struct(s) => s.size(),
            btf_rs::Type::Float(f) => f.size(),
            btf_rs::Type::Enum64(e64) => e64.size(),
            _ => return None,
        })
    }
}

/// Resolved typedefs.
pub struct Typedefs {
    /// Map from typedef nodes to the root nodes that they resolve to. Including
    /// the resolution path.
    pub fw: HashMap<Id, ResolvedType>,
    /// Map from root nodes to the typedef nodes that resolve to them. Without
    /// resolution path.
    pub bk: HashMap<Id, Vec<Id>>,
}

/// Discriminant of an enum variant.
pub struct EnumValue(i128);

impl From<EnumValue> for i128 {
    fn from(ev: EnumValue) -> i128 {
        ev.0
    }
}

/// Extension trait for uniform handling of enums of different sizes.
pub trait Enum {
    /// Returns a map from the name of an enum variant to the corresponding
    /// discriminant,
    fn variants(&self, btf: &Btf) -> HashMap<String, EnumValue>;
}

impl Enum for btf_rs::Enum {
    fn variants(&self, btf: &Btf) -> HashMap<String, EnumValue> {
        self.members
            .iter()
            .map(|m| {
                (
                    btf.btf.resolve_name(m).expect("Unnamed enum member"),
                    EnumValue(m.val() as i128),
                )
            })
            .collect()
    }
}

impl Enum for btf_rs::Enum64 {
    fn variants(&self, btf: &Btf) -> HashMap<String, EnumValue> {
        self.members
            .iter()
            .map(|m| {
                (
                    btf.btf.resolve_name(m).expect("Unnamed enum member"),
                    EnumValue(m.val() as i128),
                )
            })
            .collect()
    }
}

/// Extension trait for uniform handling of types that have members (structs and
/// unions).
pub trait HasMembers {
    /// Returns the members of this type.
    fn members(&self) -> Vec<Member>;
}

impl HasMembers for btf_rs::Struct {
    fn members(&self) -> Vec<Member> {
        self.members
            .iter()
            .enumerate()
            .map(|(idx, m)| Member::from((idx as u64, m)))
            .collect()
    }
}

/// Member of a struct or union type.
pub struct Member<'a> {
    m: &'a btf_rs::Member,
    idx: u64,
}

impl<'a> From<(u64, &'a btf_rs::Member)> for Member<'a> {
    fn from((idx, m): (u64, &'a btf_rs::Member)) -> Self {
        Self { m, idx }
    }
}

impl Member<'_> {
    /// Returns the name of this member.
    pub fn name(&self, btf: &Btf) -> String {
        match btf.btf.resolve_name(self.m) {
            Ok(name) if !name.is_empty() => name,
            _ => format!("unnamed_member_{}", self.idx),
        }
    }

    /// Returns true iff the member is a bitfield.
    pub fn is_bitfield(&self) -> bool {
        self.m.bitfield_size().is_some_and(|s| s != 0)
    }

    /// Returns true iff the member is unnamed.
    pub fn is_anon(&self) -> bool {
        self.m
            .get_name_offset()
            .expect("BUG: member without name offset")
            == 0
    }

    /// Returns the extended type of this member.
    pub fn get_tx(&self, btf: &Btf) -> TypeEx {
        let id = self
            .m
            .get_type_id()
            .expect("BUG: member without type")
            .into();
        TypeEx {
            t: btf.get_type_by_id(id).expect("BUG: member without type"),
            id,
        }
    }

    /// Returns the offset of the member in bytes.
    pub fn byte_offset(&self) -> u64 {
        (self.m.bit_offset() >> 3) as u64
    }

    /// Returns extra information about bitfield members.
    pub fn bitfield_info(&self) -> Option<BitfieldInfo> {
        Some(BitfieldInfo {
            position: (self.m.bit_offset() & 0x07) as u8,
            length: self.m.bitfield_size().map(|x| x as u8)?,
        })
    }
}

/// Information about a bitfield member.
pub struct BitfieldInfo {
    /// Offset of the first bit belonging to this bitfield into the byte where
    /// it begins.
    pub position: u8,
    /// Length of the bitfield in bits.
    pub length: u8,
}

/// Representation of a BTF ID.
#[derive(Copy, Ord, PartialOrd, Hash, Eq, PartialEq, Debug, Clone)]
pub struct Id(u32);

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u32> for Id {
    fn from(id: u32) -> Self {
        Self(id)
    }
}

impl From<Id> for u32 {
    fn from(id: Id) -> u32 {
        id.0
    }
}

impl Id {
    fn range(start: Id, end: Id) -> IdRange {
        let next = if start < end { Some(start) } else { None };
        IdRange { end, next }
    }
}

struct IdRange {
    end: Id,
    next: Option<Id>,
}

impl Iterator for IdRange {
    type Item = Id;

    fn next(&mut self) -> Option<Self::Item> {
        let next = self.next.take();
        if let Some(id) = &next {
            let next = Id(id.0 + 1);

            self.next = if next < self.end { Some(next) } else { None };
        }
        next
    }
}

/// A _relevant_ node that may be encountered on the way to the base node.
///
/// The qualifier nodes `restrict`, `volatile`, and `const` are not considered
/// relevant for profile generation.
#[derive(Debug)]
pub enum ResolutionPathNode {
    Pointer,
    Array(u64),
    Typedef(Id),
}

impl ResolutionPathNode {
    /// Returns true iff this node is an indirection.
    ///
    /// Array and pointer nodes are indirections.
    fn is_indirection(&self) -> bool {
        !matches!(self, Self::Typedef(_))
    }
}

/// A path through the type tree that ends at a root node.
#[derive(Debug)]
pub struct ResolutionPath(VecDeque<ResolutionPathNode>);

impl ResolutionPath {
    fn new() -> Self {
        Self(VecDeque::new())
    }

    /// Returns the first node in the resolution path.
    pub fn pop_node(&mut self) -> Option<ResolutionPathNode> {
        self.0.pop_front()
    }

    /// Adds a node to the end of the resolution path.
    fn record_node(&mut self, tx: &TypeEx) {
        match &tx.t.t {
            btf_rs::Type::Array(arr) => self
                .0
                .push_back(ResolutionPathNode::Array(arr.len() as u64)),
            btf_rs::Type::Ptr(_) => self.0.push_back(ResolutionPathNode::Pointer),
            btf_rs::Type::Typedef(_) => self.0.push_back(ResolutionPathNode::Typedef(tx.id)),
            _ => (),
        }
    }

    /// Returns true iff this resolution path contains indirections.
    fn has_indirections(&self) -> bool {
        self.0.iter().any(|node| node.is_indirection())
    }

    /// Returns the first typedef that has no more indirections on its path to
    /// the root.
    fn naming_typedef(&self) -> Option<Id> {
        match self
            .0
            .iter()
            .rev()
            .take_while(|n| !n.is_indirection())
            .last()
        {
            Some(ResolutionPathNode::Typedef(id)) => Some(*id),
            _ => None,
        }
    }
}

/// A BTF type together with its ID.
#[derive(Debug, Clone)]
pub struct TypeEx {
    pub t: Type,
    pub id: Id,
}

/// An extended BTF type together with its path to the root.
#[derive(Debug)]
pub struct ResolvedType {
    pub path: ResolutionPath,
    pub tx: TypeEx,
}

impl ResolvedType {
    /// Returns a name for this type.
    ///
    /// For named types it returns the name. For unnamed types it tries to find
    /// a typedef and then falls back to a unique unnamed naming scheme.
    pub fn name(&self, btf: &Btf) -> String {
        if let btf_rs::Type::FuncProto(_) = self.tx.t.t {
            String::from("function")
        } else if let btf_rs::Type::Void = self.tx.t.t {
            String::from("void")
        } else if let Ok(name) = btf.get_strtab_entry_by_id(self.tx.id) {
            name
        } else if let Some(naming_typedef) = self.path.naming_typedef() {
            btf.get_strtab_entry_by_id(naming_typedef)
                .expect("BUG: naming typedef without name")
        } else {
            format!("unnamed_{}_{}", self.tx.t.t.name(), self.tx.id)
        }
    }
}

/// Extracts BTF section from kernel binaries and determines endianness.
fn get_btf_section(mmap: &Mmap) -> Result<(Endian, &[u8])> {
    if mmap[0..2] == BTF_MAGIC_LE {
        log::debug!("Got stand alone .BTF section, little endian");
        Ok((Endian::Little, mmap))
    } else if mmap[0..2] == BTF_MAGIC_BE {
        log::debug!("Got stand alone .BTF section, big endian");
        Ok((Endian::Big, mmap))
    } else if let Ok(endian) = elf::is_elf(mmap) {
        elf::extract_btfsec(mmap).map(|sec| (endian, sec))
    } else {
        bail!(
            "Provided BTF file neither .BTF section nor ELF: {:x}",
            mmap[0]
        )
    }
}

// BTF Carving
// More specific scanning to reduce false positives
// BTF version has not changed since inception
// Flags
const BTF_SCANNING_MAGIC_BE: [u8; 4] = [0xeb, 0x9f, 0x01, 0x00];
const BTF_SCANNING_MAGIC_LE: [u8; 4] = [0x9f, 0xeb, 0x01, 0x00];

pub fn carve_btf<I: MemoryImage>(image: &I) -> Result<(Endian, &[u8])> {
    let data = image.as_ref();

    let mut best = (0, 0, Endian::Little);

    for (magic, endian) in [
        (&BTF_SCANNING_MAGIC_LE[..], Endian::Little),
        (&BTF_SCANNING_MAGIC_BE[..], Endian::Big),
    ] {
        for offset in image.scan_bytes(magic) {
            let Some(btf_size) = btf_heuristics(data, offset, &endian) else {
                continue;
            };

            if btf_size > best.1 {
                best = (offset, btf_size, endian);
            }
        }
    }

    let btf_bytes = &data[best.0..best.0 + best.1];

    Ok((best.2, btf_bytes))
}

// Based on https://www.kernel.org/doc/html/latest/bpf/btf.html and manually tested heuristics
pub fn btf_heuristics(data: &[u8], offset: usize, endian: &Endian) -> Option<usize> {
    if offset + BTF_HDR_LEN_MIN > data.len() {
        return None;
    }

    let hdr = &data[offset..];

    let read_u32 = if *endian == Endian::Big {
        |d: &[u8], off: usize| u32::from_be_bytes(d[off..off + 4].try_into().unwrap())
    } else {
        |d: &[u8], off: usize| u32::from_le_bytes(d[off..off + 4].try_into().unwrap())
    };

    let hdr_len = read_u32(hdr, 4) as usize;
    let type_off = read_u32(hdr, 8) as usize;
    let type_len = read_u32(hdr, 12) as usize;
    let str_off = read_u32(hdr, 16) as usize;
    let str_len = read_u32(hdr, 20) as usize;

    // Basic header validation
    if hdr_len < BTF_HDR_LEN_MIN {
        return None;
    }
    if type_len == 0 || str_len == 0 {
        return None;
    }

    // Calculate total size
    let data_end = std::cmp::max(type_off + type_len, str_off + str_len);
    let total_size = hdr_len + data_end;

    // Size sanity check - Drastically cut down scan times when testing
    if total_size < BTF_SIZE_MIN || total_size > BTF_SIZE_MAX {
        return None;
    }

    // Bounds check
    if offset + total_size > data.len() {
        return None;
    }

    // First byte of string section must be \0
    let str_start = offset + hdr_len + str_off;
    if str_start >= data.len() || data[str_start] != 0 {
        return None;
    }

    // Try parsing with btf_rs to confirm validity
    let btf_bytes = &data[offset..offset + total_size];
    if btf_rs::Btf::from_bytes(btf_bytes).is_err() {
        return None;
    }

    Some(total_size)
}
