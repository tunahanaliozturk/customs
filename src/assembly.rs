//! Rules C301 to C304 over the assemblies of a package: the PE headers
//! through `object`, and a reader of its own for the ECMA-335 metadata
//! (ADR 0002).
//!
//! The bytes are hostile. Every offset, size, count and index that comes
//! from the file is checked against the slice it points into, with checked
//! arithmetic, before it is used: reads go through `get`, or through a range
//! computed from the length of the slice it cuts. The row counts are checked against the size of the table stream before any
//! row is read, so a count cannot size an allocation or a loop beyond the
//! bytes that are really there. Names are compared in place, reading at most
//! the length of the name looked for, so the work is linear in the rows read.
//! Metadata that readers could read differently is refused (ADR 0006).

use std::collections::BTreeMap;

use object::FileKind;
use object::pe;
use object::read::pe::{ImageNtHeaders, PeFile, SectionTable};

use crate::inventory::{Asset, ManagedRole, NativeFormat};
use crate::package::{Entry, Files, Limits, PackagePath, thousands};
use crate::scan::{Finding, FindingRule, Gap, GapRule, Outcome};

/// Why a file is not an assembly customs can read.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Unreadable {
    /// Not a PE file.
    NotPe,
    /// A PE file without a CLI header: native code.
    Native,
    /// A PE file with a CLI header whose headers or metadata cannot be read,
    /// or could be read in more than one way.
    Malformed(&'static str),
    /// Over a limit: a C002 gap.
    Limit(String),
}

use Unreadable::Malformed;

/// Tables 0x00 to 0x2C of ECMA-335 partition II chapter 22. The portable
/// PDB tables from 0x30 never appear in an assembly and are refused.
const TABLES: usize = 0x2D;

const MODULE: usize = 0x00;
const TYPE_REF: usize = 0x01;
const TYPE_DEF: usize = 0x02;
const FIELD_PTR: usize = 0x03;
const FIELD: usize = 0x04;
const METHOD_PTR: usize = 0x05;
const METHOD_DEF: usize = 0x06;
const PARAM_PTR: usize = 0x07;
const PARAM: usize = 0x08;
const INTERFACE_IMPL: usize = 0x09;
const MEMBER_REF: usize = 0x0A;
const DECL_SECURITY: usize = 0x0E;
const STAND_ALONE_SIG: usize = 0x11;
const EVENT_PTR: usize = 0x13;
const EVENT: usize = 0x14;
const PROPERTY_PTR: usize = 0x16;
const PROPERTY: usize = 0x17;
const MODULE_REF: usize = 0x1A;
const TYPE_SPEC: usize = 0x1B;
const IMPL_MAP: usize = 0x1C;
const ENC_LOG: usize = 0x1E;
const ENC_MAP: usize = 0x1F;
const ASSEMBLY: usize = 0x20;
const ASSEMBLY_REF: usize = 0x23;
const FILE: usize = 0x26;
const EXPORTED_TYPE: usize = 0x27;
const MANIFEST_RESOURCE: usize = 0x28;
const GENERIC_PARAM: usize = 0x2A;
const METHOD_SPEC: usize = 0x2B;
const GENERIC_PARAM_CONSTRAINT: usize = 0x2C;

/// The row of `TypeDef` that is `<Module>`. The first row, by ECMA-335
/// II.22.37; a reader that takes another row misses every module
/// initialiser and reports the type initialiser of an ordinary type.
const MODULE_TYPE_ROW: u32 = 1;

/// `MethodAttributes.RTSpecialName`.
const RT_SPECIAL_NAME: u32 = 0x1000;

/// The longest name read whole, for messages and the oracle tests. Names
/// that are only compared are read to the length of the name looked for.
const NAME_LIMIT: usize = 1024;

/// A coded index (II.24.2.6): the tag bits and the tables it can point to.
/// Its width depends only on these, so unused tags are left out.
#[derive(Debug, Clone, Copy)]
struct Coded {
    bits: u32,
    tables: &'static [usize],
}

const TYPE_DEF_OR_REF: Coded = Coded {
    bits: 2,
    tables: &[TYPE_DEF, TYPE_REF, TYPE_SPEC],
};
const HAS_CONSTANT: Coded = Coded {
    bits: 2,
    tables: &[FIELD, PARAM, PROPERTY],
};
const HAS_CUSTOM_ATTRIBUTE: Coded = Coded {
    bits: 5,
    tables: &[
        METHOD_DEF,
        FIELD,
        TYPE_REF,
        TYPE_DEF,
        PARAM,
        INTERFACE_IMPL,
        MEMBER_REF,
        MODULE,
        DECL_SECURITY,
        PROPERTY,
        EVENT,
        STAND_ALONE_SIG,
        MODULE_REF,
        TYPE_SPEC,
        ASSEMBLY,
        ASSEMBLY_REF,
        FILE,
        EXPORTED_TYPE,
        MANIFEST_RESOURCE,
        GENERIC_PARAM,
        GENERIC_PARAM_CONSTRAINT,
        METHOD_SPEC,
    ],
};
const HAS_FIELD_MARSHAL: Coded = Coded {
    bits: 1,
    tables: &[FIELD, PARAM],
};
const HAS_DECL_SECURITY: Coded = Coded {
    bits: 2,
    tables: &[TYPE_DEF, METHOD_DEF, ASSEMBLY],
};
const MEMBER_REF_PARENT: Coded = Coded {
    bits: 3,
    tables: &[TYPE_DEF, TYPE_REF, MODULE_REF, METHOD_DEF, TYPE_SPEC],
};
const HAS_SEMANTICS: Coded = Coded {
    bits: 1,
    tables: &[EVENT, PROPERTY],
};
const METHOD_DEF_OR_REF: Coded = Coded {
    bits: 1,
    tables: &[METHOD_DEF, MEMBER_REF],
};
const MEMBER_FORWARDED: Coded = Coded {
    bits: 1,
    tables: &[FIELD, METHOD_DEF],
};
const IMPLEMENTATION: Coded = Coded {
    bits: 2,
    tables: &[FILE, ASSEMBLY_REF, EXPORTED_TYPE],
};
const CUSTOM_ATTRIBUTE_TYPE: Coded = Coded {
    bits: 3,
    tables: &[METHOD_DEF, MEMBER_REF],
};
const RESOLUTION_SCOPE: Coded = Coded {
    bits: 2,
    tables: &[MODULE, MODULE_REF, ASSEMBLY_REF, TYPE_REF],
};
const TYPE_OR_METHOD_DEF: Coded = Coded {
    bits: 1,
    tables: &[TYPE_DEF, METHOD_DEF],
};

/// One column of a table.
#[derive(Debug, Clone, Copy)]
enum Col {
    U16,
    U32,
    Str,
    Guid,
    Blob,
    Index(usize),
    Code(Coded),
}

use Col::{Blob, Code, Guid, Index, Str, U16, U32};

/// The most columns of any table (`Assembly` and `AssemblyRef`).
const MAX_COLUMNS: usize = 9;

/// The columns of every table, II.22.2 to II.22.39. Row sizes, and so the
/// offset of every later table, depend on all of them.
const SCHEMA: [&[Col]; TABLES] = [
    /* 0x00 Module */ &[U16, Str, Guid, Guid, Guid],
    /* 0x01 TypeRef */ &[Code(RESOLUTION_SCOPE), Str, Str],
    /* 0x02 TypeDef */
    &[
        U32,
        Str,
        Str,
        Code(TYPE_DEF_OR_REF),
        Index(FIELD),
        Index(METHOD_DEF),
    ],
    /* 0x03 FieldPtr */ &[Index(FIELD)],
    /* 0x04 Field */ &[U16, Str, Blob],
    /* 0x05 MethodPtr */ &[Index(METHOD_DEF)],
    /* 0x06 MethodDef */ &[U32, U16, U16, Str, Blob, Index(PARAM)],
    /* 0x07 ParamPtr */ &[Index(PARAM)],
    /* 0x08 Param */ &[U16, U16, Str],
    /* 0x09 InterfaceImpl */ &[Index(TYPE_DEF), Code(TYPE_DEF_OR_REF)],
    /* 0x0A MemberRef */ &[Code(MEMBER_REF_PARENT), Str, Blob],
    /* 0x0B Constant: a type byte and a padding byte */
    &[U16, Code(HAS_CONSTANT), Blob],
    /* 0x0C CustomAttribute */
    &[
        Code(HAS_CUSTOM_ATTRIBUTE),
        Code(CUSTOM_ATTRIBUTE_TYPE),
        Blob,
    ],
    /* 0x0D FieldMarshal */ &[Code(HAS_FIELD_MARSHAL), Blob],
    /* 0x0E DeclSecurity */ &[U16, Code(HAS_DECL_SECURITY), Blob],
    /* 0x0F ClassLayout */ &[U16, U32, Index(TYPE_DEF)],
    /* 0x10 FieldLayout */ &[U32, Index(FIELD)],
    /* 0x11 StandAloneSig */ &[Blob],
    /* 0x12 EventMap */ &[Index(TYPE_DEF), Index(EVENT)],
    /* 0x13 EventPtr */ &[Index(EVENT)],
    /* 0x14 Event */ &[U16, Str, Code(TYPE_DEF_OR_REF)],
    /* 0x15 PropertyMap */ &[Index(TYPE_DEF), Index(PROPERTY)],
    /* 0x16 PropertyPtr */ &[Index(PROPERTY)],
    /* 0x17 Property */ &[U16, Str, Blob],
    /* 0x18 MethodSemantics */ &[U16, Index(METHOD_DEF), Code(HAS_SEMANTICS)],
    /* 0x19 MethodImpl */
    &[
        Index(TYPE_DEF),
        Code(METHOD_DEF_OR_REF),
        Code(METHOD_DEF_OR_REF),
    ],
    /* 0x1A ModuleRef */ &[Str],
    /* 0x1B TypeSpec */ &[Blob],
    /* 0x1C ImplMap */ &[U16, Code(MEMBER_FORWARDED), Str, Index(MODULE_REF)],
    /* 0x1D FieldRVA */ &[U32, Index(FIELD)],
    /* 0x1E EncLog */ &[U32, U32],
    /* 0x1F EncMap */ &[U32],
    /* 0x20 Assembly */ &[U32, U16, U16, U16, U16, U32, Blob, Str, Str],
    /* 0x21 AssemblyProcessor */ &[U32],
    /* 0x22 AssemblyOS */ &[U32, U32, U32],
    /* 0x23 AssemblyRef */ &[U16, U16, U16, U16, U32, Blob, Str, Str, Blob],
    /* 0x24 AssemblyRefProcessor */ &[U32, Index(ASSEMBLY_REF)],
    /* 0x25 AssemblyRefOS */ &[U32, U32, U32, Index(ASSEMBLY_REF)],
    /* 0x26 File */ &[U32, Str, Blob],
    /* 0x27 ExportedType */ &[U32, U32, Str, Str, Code(IMPLEMENTATION)],
    /* 0x28 ManifestResource */ &[U32, U32, Str, Code(IMPLEMENTATION)],
    /* 0x29 NestedClass */ &[Index(TYPE_DEF), Index(TYPE_DEF)],
    /* 0x2A GenericParam */ &[U16, U16, Code(TYPE_OR_METHOD_DEF), Str],
    /* 0x2B MethodSpec */ &[Code(METHOD_DEF_OR_REF), Blob],
    /* 0x2C GenericParamConstraint */ &[Index(GENERIC_PARAM), Code(TYPE_DEF_OR_REF)],
];

/// Tables that only an uncompressed (`#-`) or edit-and-continue stream may
/// hold. In a `#~` stream `System.Reflection.Metadata` refuses them, and with
/// them a method list means something else, so customs refuses them too.
const INDIRECT_TABLES: [usize; 7] = [
    FIELD_PTR,
    METHOD_PTR,
    PARAM_PTR,
    EVENT_PTR,
    PROPERTY_PTR,
    ENC_LOG,
    ENC_MAP,
];

/// The heap size flags of the `#~` header (II.24.2.6), and two that
/// `System.Reflection.Metadata` and the runtime honour beyond it.
const WIDE_STRINGS: u8 = 0x01;
const WIDE_GUIDS: u8 = 0x02;
const WIDE_BLOBS: u8 = 0x04;
const DELTA: u8 = 0x20;
const EXTRA_DATA: u8 = 0x40;

/// Reads an unsigned little-endian number of up to eight bytes.
fn le(bytes: &[u8]) -> u64 {
    bytes.iter().rev().fold(0, |n, b| (n << 8) | u64::from(*b))
}

/// `bytes[at..at + n]`, or `None` where that is not inside `bytes`.
fn slice(bytes: &[u8], at: usize, n: usize) -> Option<&[u8]> {
    bytes.get(at..at.checked_add(n)?)
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    slice(bytes, at, 4).and_then(|b| u32::try_from(le(b)).ok())
}

fn size(n: u32) -> usize {
    // usize is at least 32 bits on every target the crate builds for.
    usize::try_from(n).unwrap_or(usize::MAX)
}

/// A forward reader over a slice that fails instead of running past it.
struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], Unreadable> {
        let taken = slice(self.bytes, self.at, n).ok_or(Malformed(what))?;
        self.at += n;
        Ok(taken)
    }

    fn number(&mut self, n: usize, what: &'static str) -> Result<u64, Unreadable> {
        self.take(n, what).map(le)
    }

    fn u32(&mut self, what: &'static str) -> Result<u32, Unreadable> {
        self.take(4, what)
            .map(|b| u32::try_from(le(b)).unwrap_or(u32::MAX))
    }
}

/// The parsed metadata: the table data, the string heap, and where each
/// table and column is. Built once; every later read is checked again.
#[derive(Debug)]
struct Metadata<'a> {
    tables: &'a [u8],
    strings: &'a [u8],
    rows: [u32; TABLES],
    start: [usize; TABLES],
    row_size: [usize; TABLES],
    column: [[usize; MAX_COLUMNS]; TABLES],
    width: [[usize; MAX_COLUMNS]; TABLES],
}

/// Reads the name of a stream header: at most 32 bytes with the NUL, then
/// padding to a multiple of four (II.24.2.2).
fn stream_name<'a>(cursor: &mut Cursor<'a>) -> Result<&'a [u8], Unreadable> {
    let window = cursor
        .bytes
        .get(cursor.at..)
        .map(|rest| &rest[..rest.len().min(32)])
        .unwrap_or_default();
    let length = window
        .iter()
        .position(|b| *b == 0)
        .ok_or(Malformed("a stream name has no end within 32 bytes"))?;
    let padded = (length + 1).next_multiple_of(4);
    let name = cursor.take(padded, "a stream name runs past the metadata")?;
    Ok(name.get(..length).unwrap_or_default())
}

impl<'a> Metadata<'a> {
    /// Parses the metadata root, the stream headers and the `#~` header,
    /// and checks that every table fits in its stream.
    fn parse(bytes: &'a [u8], limits: &Limits) -> Result<Self, Unreadable> {
        let mut root = Cursor { bytes, at: 0 };
        if root.u32("the metadata is shorter than its signature")? != 0x424A_5342 {
            return Err(Malformed("the metadata does not start with BSJB"));
        }
        root.take(8, "the metadata root is cut short")?;
        let version = root.u32("the metadata root is cut short")?;
        root.take(size(version), "the version string runs past the metadata")?;
        root.take(2, "the metadata root is cut short")?;
        let streams = root.number(2, "the metadata root is cut short")?;

        let mut table_stream = None;
        let mut strings = None;
        let mut seen: Vec<&[u8]> = Vec::new();
        for _ in 0..streams {
            let offset = size(root.u32("a stream header runs past the metadata")?);
            let length = size(root.u32("a stream header runs past the metadata")?);
            let name = stream_name(&mut root)?;
            let data =
                slice(bytes, offset, length).ok_or(Malformed("a stream runs past the metadata"))?;
            match name {
                b"#~" | b"#Strings" | b"#US" | b"#GUID" | b"#Blob" | b"#-" | b"#JTD" | b"#Pdb" => {
                    // Two streams of one name are read differently by
                    // different readers: System.Reflection.Metadata keeps
                    // the last.
                    if seen.contains(&name) {
                        return Err(Malformed("two metadata streams have the same name"));
                    }
                    seen.push(name);
                }
                _ => {}
            }
            match name {
                b"#~" => table_stream = Some(data),
                b"#Strings" => strings = Some(data),
                b"#-" => {
                    return Err(Malformed(
                        "uncompressed metadata tables (#-), which customs does not read",
                    ));
                }
                b"#JTD" | b"#Pdb" => {
                    return Err(Malformed(
                        "a stream that only edit-and-continue or a PDB has",
                    ));
                }
                _ => {}
            }
        }
        let table_stream = table_stream.ok_or(Malformed("no #~ table stream"))?;
        Self::tables(table_stream, strings.unwrap_or_default(), limits)
    }

    fn tables(stream: &'a [u8], strings: &'a [u8], limits: &Limits) -> Result<Self, Unreadable> {
        let mut cursor = Cursor {
            bytes: stream,
            at: 0,
        };
        cursor.take(6, "the #~ header is cut short")?;
        let heaps = u8::try_from(cursor.number(1, "the #~ header is cut short")?).unwrap_or(0);
        cursor.take(1, "the #~ header is cut short")?;
        let valid = cursor.number(8, "the #~ header is cut short")?;
        cursor.take(8, "the #~ header is cut short")?;
        if valid >> TABLES != 0 {
            return Err(Malformed("the #~ stream names tables that do not exist"));
        }
        if INDIRECT_TABLES.iter().any(|t| valid & (1 << t) != 0) {
            return Err(Malformed(
                "pointer or edit-and-continue tables in a #~ stream",
            ));
        }
        if heaps & DELTA != 0 {
            return Err(Malformed("an edit-and-continue delta"));
        }
        let mut rows = [0u32; TABLES];
        for (table, count) in rows.iter_mut().enumerate() {
            if valid & (1 << table) != 0 {
                *count = cursor.u32("the row counts run past the #~ stream")?;
                if *count > limits.table_rows {
                    return Err(Unreadable::Limit(format!(
                        "limit reached: {} rows in metadata table 0x{table:02X}, over the limit of {}",
                        thousands(u64::from(*count)),
                        thousands(u64::from(limits.table_rows))
                    )));
                }
            }
        }
        if heaps & EXTRA_DATA != 0 {
            // Four bytes some obfuscators add; the runtime skips them.
            cursor.take(4, "the #~ header is cut short")?;
        }
        let tables = stream.get(cursor.at..).unwrap_or_default();

        let heap = |flag: u8| if heaps & flag != 0 { 4 } else { 2 };
        let index = |table: usize| if rows[table] < 0x1_0000 { 2 } else { 4 };
        let coded = |c: Coded| {
            let small = 1u32 << (16 - c.bits);
            if c.tables.iter().all(|t| rows[*t] < small) {
                2
            } else {
                4
            }
        };
        let mut metadata = Self {
            tables,
            strings,
            rows,
            start: [0; TABLES],
            row_size: [0; TABLES],
            column: [[0; MAX_COLUMNS]; TABLES],
            width: [[0; MAX_COLUMNS]; TABLES],
        };
        let mut offset: u64 = 0;
        for (table, columns) in SCHEMA.iter().enumerate() {
            let mut row_size = 0;
            for (i, col) in columns.iter().enumerate() {
                let width = match col {
                    U16 => 2,
                    U32 => 4,
                    Str => heap(WIDE_STRINGS),
                    Guid => heap(WIDE_GUIDS),
                    Blob => heap(WIDE_BLOBS),
                    Index(t) => index(*t),
                    Code(c) => coded(*c),
                };
                metadata.column[table][i] = row_size;
                metadata.width[table][i] = width;
                row_size += width;
            }
            metadata.row_size[table] = row_size;
            metadata.start[table] = usize::try_from(offset).unwrap_or(usize::MAX);
            // At most 2^24 rows of at most 36 bytes in each of 45 tables:
            // this cannot overflow a u64, and the check below bounds it.
            offset += u64::from(rows[table]) * row_size as u64;
        }
        if offset > tables.len() as u64 {
            return Err(Malformed("the tables are larger than the #~ stream"));
        }
        Ok(metadata)
    }

    /// One cell. Rows count from 1, as in tokens.
    fn cell(&self, table: usize, row: u32, column: usize) -> Result<u32, Unreadable> {
        let outside = Malformed("an index points outside its table");
        if row == 0 || row > *self.rows.get(table).ok_or(outside.clone())? {
            return Err(outside);
        }
        let at = (size(row) - 1)
            .checked_mul(self.row_size[table])
            .and_then(|n| n.checked_add(self.start[table]))
            .and_then(|n| n.checked_add(*self.column[table].get(column)?))
            .ok_or(outside.clone())?;
        let width = *self.width[table].get(column).ok_or(outside.clone())?;
        slice(self.tables, at, width)
            .map(|b| u32::try_from(le(b)).unwrap_or(u32::MAX))
            .ok_or(outside)
    }

    /// Whether the string at `index` is `expected`, compared in place:
    /// at most `expected.len() + 1` bytes are read.
    fn name_is(&self, index: u32, expected: &[u8], ignore_case: bool) -> bool {
        let Some(found) = slice(self.strings, size(index), expected.len() + 1) else {
            return false;
        };
        let (text, end) = found.split_at(expected.len());
        end == [0]
            && if ignore_case {
                text.eq_ignore_ascii_case(expected)
            } else {
                text == expected
            }
    }

    /// The string at `index`, up to its NUL, read for at most
    /// [`NAME_LIMIT`] bytes. Index 0 is the empty string, also when there is
    /// no string heap.
    fn name(&self, index: u32) -> Result<&'a [u8], Unreadable> {
        if index == 0 {
            return Ok(&[]);
        }
        let rest = self
            .strings
            .get(size(index)..)
            .ok_or(Malformed("a name points outside the string heap"))?;
        let window = &rest[..rest.len().min(NAME_LIMIT)];
        let end = window
            .iter()
            .position(|b| *b == 0)
            .ok_or(Malformed("a name has no end within 1,024 bytes"))?;
        Ok(&window[..end])
    }

    /// The `MethodDef` row of the module initialiser: a method of
    /// `<Module>` named `.cctor` with `RTSpecialName`.
    fn module_initializer(&self) -> Result<Option<u32>, Unreadable> {
        let types = self.rows[TYPE_DEF];
        let methods = self.rows[METHOD_DEF];
        if types < MODULE_TYPE_ROW {
            return Ok(None);
        }
        // The method list of a type runs to the start of the next type's,
        // or to the end of the table for the last type (II.22.37).
        let first = self.cell(TYPE_DEF, MODULE_TYPE_ROW, 5)?;
        let end = if MODULE_TYPE_ROW < types {
            self.cell(TYPE_DEF, MODULE_TYPE_ROW + 1, 5)?
        } else {
            methods.saturating_add(1)
        };
        if first == 0 || first >= end {
            return Ok(None);
        }
        if end > methods.saturating_add(1) {
            return Err(Malformed(
                "the method list of <Module> runs past the MethodDef table",
            ));
        }
        for row in first..end {
            let flags = self.cell(METHOD_DEF, row, 2)?;
            let name = self.cell(METHOD_DEF, row, 3)?;
            if flags & RT_SPECIAL_NAME != 0 && self.name_is(name, b".cctor", false) {
                return Ok(Some(row));
            }
        }
        Ok(None)
    }

    /// The rows of `ImplMap`: mapping flags, the member as a coded index,
    /// the import name and the `ModuleRef` row. An empty import name, which
    /// II.22.22 forbids, is refused: what it binds to is up to the reader.
    fn imports(&self) -> impl Iterator<Item = Result<[u32; 4], Unreadable>> + '_ {
        (1..=self.rows[IMPL_MAP]).map(|row| {
            let name = self.cell(IMPL_MAP, row, 2)?;
            if name == 0 || self.strings.get(size(name)).is_none_or(|b| *b == 0) {
                return Err(Malformed("a P/Invoke has an empty import name"));
            }
            Ok([
                self.cell(IMPL_MAP, row, 0)?,
                self.cell(IMPL_MAP, row, 1)?,
                name,
                self.cell(IMPL_MAP, row, 3)?,
            ])
        })
    }

    /// The name of a `ModuleRef` row; row 0 is no module.
    fn module_name(&self, row: u32) -> Result<&'a [u8], Unreadable> {
        if row == 0 {
            return Ok(&[]);
        }
        self.name(self.cell(MODULE_REF, row, 0)?)
    }
}

/// Native functions that change memory protection or put code into another
/// process, matched ignoring ASCII case. Functions that load a library or
/// find an export are not here: 20 of the 300 packages of the benign corpus
/// import them, the build-time collector of coverlet.collector among them.
const PINVOKE_SHORT_LIST: [&str; 25] = [
    "VirtualProtect",
    "VirtualProtectEx",
    "VirtualAlloc",
    "VirtualAlloc2",
    "VirtualAllocEx",
    "NtProtectVirtualMemory",
    "ZwProtectVirtualMemory",
    "NtAllocateVirtualMemory",
    "ZwAllocateVirtualMemory",
    "mprotect",
    "WriteProcessMemory",
    "NtWriteVirtualMemory",
    "ZwWriteVirtualMemory",
    "CreateRemoteThread",
    "CreateRemoteThreadEx",
    "NtCreateThreadEx",
    "ZwCreateThreadEx",
    "RtlCreateUserThread",
    "QueueUserAPC",
    "NtQueueApcThread",
    "SetThreadContext",
    "NtSetContextThread",
    "NtUnmapViewOfSection",
    "ZwUnmapViewOfSection",
    "process_vm_writev",
];

/// Obfuscator markers: a type an obfuscator adds to what it protects, as
/// namespace, name and obfuscator. Only markers seen in a real package are
/// here (open question 10 in the design).
const MARKERS: [(&str, &str, &str); 1] = [("", "DotfuscatorAttribute", "Dotfuscator")];

/// What reading one assembly found.
#[derive(Debug, Default)]
struct Report {
    findings: Vec<Finding>,
    gaps: Vec<Gap>,
}

/// Cuts a value from a file to 240 characters, as the `MSBuild` rules do.
fn cut(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    match text.char_indices().nth(240) {
        Some((at, _)) => text[..at].to_owned(),
        None => text.into_owned(),
    }
}

/// An assembly whose PE headers and metadata were read.
#[derive(Debug)]
struct Assembly<'a> {
    bytes: &'a [u8],
    sections: SectionTable<'a>,
    metadata: Metadata<'a>,
}

fn headers<Pe: ImageNtHeaders>(
    bytes: &[u8],
) -> Result<(SectionTable<'_>, Option<(u32, u32)>), Unreadable> {
    let file =
        PeFile::<Pe>::parse(bytes).map_err(|_| Malformed("the PE headers cannot be read"))?;
    let cli = file
        .data_directory(pe::IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)
        .map(pe::ImageDataDirectory::address_range);
    Ok((file.section_table(), cli))
}

impl<'a> Assembly<'a> {
    /// Reads the PE headers, the CLI header and the metadata.
    fn read(bytes: &'a [u8], limits: &Limits) -> Result<Self, Unreadable> {
        let (sections, cli) = match FileKind::parse(bytes) {
            Ok(FileKind::Pe32) => headers::<pe::ImageNtHeaders32>(bytes)?,
            Ok(FileKind::Pe64) => headers::<pe::ImageNtHeaders64>(bytes)?,
            _ if bytes.starts_with(b"MZ") => {
                return Err(Malformed("the PE headers cannot be read"));
            }
            _ => return Err(Unreadable::NotPe),
        };
        let (rva, length) = match cli {
            Some((0, 0)) | None => return Err(Unreadable::Native),
            Some(range) => range,
        };
        if length < 72 {
            return Err(Malformed("the CLI header is shorter than 72 bytes"));
        }
        let header = sections
            .pe_data_at(bytes, rva)
            .and_then(|data| data.get(..72))
            .ok_or(Malformed("the CLI header is outside the file"))?;
        let metadata_rva = u32_at(header, 8).ok_or(Malformed("the CLI header is cut short"))?;
        let metadata_size = u32_at(header, 12).ok_or(Malformed("the CLI header is cut short"))?;
        let metadata = sections
            .pe_data_at(bytes, metadata_rva)
            .and_then(|data| data.get(..size(metadata_size)))
            .filter(|data| !data.is_empty())
            .ok_or(Malformed("the metadata is outside the file"))?;
        Ok(Self {
            bytes,
            sections,
            metadata: Metadata::parse(metadata, limits)?,
        })
    }

    /// The size of the IL of a method body, from its tiny or fat header
    /// (II.25.4), if the body is there and fits in its section.
    fn code_size(&self, method: u32) -> Result<Option<u32>, Unreadable> {
        let rva = self.metadata.cell(METHOD_DEF, method, 0)?;
        if rva == 0 {
            return Ok(None);
        }
        let Some(body) = self.sections.pe_data_at(self.bytes, rva) else {
            return Ok(None);
        };
        let (header, code) = match body.first() {
            Some(b) if b & 0x3 == 0x2 => (1, u32::from(b >> 2)),
            Some(b) if b & 0x3 == 0x3 => match (slice(body, 0, 2).map(le), u32_at(body, 4)) {
                (Some(flags), Some(code)) if flags >> 12 == 3 => (12, code),
                _ => return Ok(None),
            },
            _ => return Ok(None),
        };
        let fits = size(code)
            .checked_add(header)
            .is_some_and(|end| end <= body.len());
        Ok(fits.then_some(code))
    }

    /// The P/Invoke imports of methods: method row, mapping flags, import
    /// name and module name. For the oracle tests, which read whole names.
    #[cfg(test)]
    fn method_imports(&self) -> Result<Vec<(u32, u32, String, String)>, Unreadable> {
        let mut out = Vec::new();
        for row in self.metadata.imports() {
            let [flags, member, name, module] = row?;
            if member & 1 == 1 {
                out.push((
                    member >> 1,
                    flags,
                    String::from_utf8_lossy(self.metadata.name(name)?).into_owned(),
                    String::from_utf8_lossy(self.metadata.module_name(module)?).into_owned(),
                ));
            }
        }
        out.sort();
        Ok(out)
    }

    /// C301 to C303 for this assembly, at most `limits.findings_per_file`
    /// of them; past that, a C002 gap.
    fn check(&self, path: &str, limits: &Limits) -> Result<Report, Unreadable> {
        let mut report = Report::default();
        let finding = |rule, message: String, evidence: String| {
            let mut found = Finding::new(rule, Some(path.to_owned()), message);
            found.evidence = Some(evidence);
            found
        };
        if let Some(method) = self.metadata.module_initializer()? {
            let evidence = match self.code_size(method)? {
                Some(code) => format!("{} bytes of IL", thousands(u64::from(code))),
                None => "no readable method body".to_owned(),
            };
            report.findings.push(finding(
                FindingRule::C301,
                "module initialiser".to_owned(),
                evidence,
            ));
        }
        let mut dropped: u64 = 0;
        for row in self.metadata.imports() {
            let [_, _, name, module] = row?;
            let Some(function) = PINVOKE_SHORT_LIST
                .iter()
                .find(|f| self.metadata.name_is(name, f.as_bytes(), true))
            else {
                continue;
            };
            if report.findings.len() as u64 >= limits.findings_per_file {
                dropped += 1;
                continue;
            }
            let module = cut(self.metadata.module_name(module)?);
            report.findings.push(finding(
                FindingRule::C302,
                format!("P/Invoke to {function}"),
                format!("{module}!{function}"),
            ));
        }
        let mut markers = BTreeMap::new();
        for table in [TYPE_DEF, TYPE_REF] {
            for row in 1..=self.metadata.rows[table] {
                let name = self.metadata.cell(table, row, 1)?;
                let namespace = self.metadata.cell(table, row, 2)?;
                for (space, type_name, tool) in MARKERS {
                    if self.metadata.name_is(name, type_name.as_bytes(), false)
                        && self.metadata.name_is(namespace, space.as_bytes(), false)
                    {
                        markers.insert(type_name, tool);
                    }
                }
            }
        }
        for (type_name, tool) in markers {
            report.findings.push(finding(
                FindingRule::C303,
                format!("marker of the obfuscator {tool}"),
                type_name.to_owned(),
            ));
        }
        if dropped > 0 {
            report.gaps.push(Gap::new(
                GapRule::C002,
                Some(path.to_owned()),
                format!(
                    "limit reached: {} more P/Invoke findings in one assembly, over the limit of {}; not listed",
                    thousands(dropped),
                    thousands(limits.findings_per_file)
                ),
            ));
        }
        Ok(report)
    }
}

/// Whether a path is in a folder that the inventory lists by extension as
/// build-time code, `build*/` or `tools/`, where native tools are normal.
fn in_tool_folder(path: &PackagePath) -> bool {
    let first = path.as_str().split('/').next().unwrap_or_default();
    [
        "BUILD",
        "BUILDTRANSITIVE",
        "BUILDMULTITARGETING",
        "BUILDCROSSTARGETING",
        "TOOLS",
    ]
    .iter()
    .any(|folder| first.eq_ignore_ascii_case(folder))
}

/// Whether an asset is code that runs in the compiler or in `MSBuild`.
fn build_time(asset: Asset) -> bool {
    matches!(
        asset,
        Asset::Analyzer
            | Asset::Managed {
                role: ManagedRole::BuildTime
            }
    )
}

/// Reads every assembly of a package and adds C301 to C304 to `outcome`.
/// Findings in an analyzer or a build-time assembly are raised one step. A
/// native PE, ELF or Mach-O file under `build*/` or `tools/`, which the
/// inventory listed as build-time code by its extension, becomes a native
/// binary (C104); anywhere else NuGet expects managed code, so it is C304.
pub(crate) fn scan(
    files: &mut dyn Files,
    entries: &[Entry],
    assets: &mut [(PackagePath, Asset)],
    limits: &Limits,
    outcome: &mut Outcome,
) {
    let index: BTreeMap<&PackagePath, &Entry> = entries.iter().map(|e| (&e.path, e)).collect();
    for (path, asset) in assets.iter_mut() {
        if !matches!(asset, Asset::Analyzer | Asset::Managed { .. }) {
            continue;
        }
        let Some(entry) = index.get(path) else {
            continue;
        };
        let cap = limits.assembly_bytes.saturating_add(1);
        let bytes = match files.read(entry, cap, limits, &mut outcome.budget) {
            Err(gap) => {
                outcome.gaps.push(gap);
                continue;
            }
            Ok(bytes) if bytes.len() as u64 > limits.assembly_bytes => {
                outcome.gaps.push(Gap::new(
                    GapRule::C002,
                    Some(path.as_str().to_owned()),
                    format!(
                        "limit reached: an assembly over {} bytes; not read",
                        thousands(limits.assembly_bytes)
                    ),
                ));
                continue;
            }
            Ok(bytes) => bytes,
        };
        let raise = build_time(*asset);
        let report = Assembly::read(&bytes, limits)
            .and_then(|assembly| assembly.check(path.as_str(), limits));
        let problem = match report {
            Ok(report) => {
                outcome.findings.extend(
                    report
                        .findings
                        .into_iter()
                        .map(|f| if raise { f.raised() } else { f }),
                );
                outcome.gaps.extend(report.gaps);
                continue;
            }
            Err(problem) => problem,
        };
        let native = match (&problem, crate::inventory::sniff(&bytes)) {
            (Unreadable::Native, _) => Some(NativeFormat::Pe),
            (Unreadable::NotPe, Some(format)) => Some(format),
            _ => None,
        };
        if let (true, Some(format)) = (in_tool_folder(path), native) {
            *asset = Asset::Native { format };
            continue;
        }
        let reason = match problem {
            Unreadable::Limit(message) => {
                outcome.gaps.push(Gap::new(
                    GapRule::C002,
                    Some(path.as_str().to_owned()),
                    message,
                ));
                continue;
            }
            Unreadable::NotPe => "not a PE file",
            Unreadable::Native => "a native PE file without a CLI header",
            Malformed(reason) => reason,
        };
        let mut found = Finding::new(
            FindingRule::C304,
            Some(path.as_str().to_owned()),
            "not a readable managed assembly".to_owned(),
        );
        found.evidence = Some(reason.to_owned());
        outcome
            .findings
            .push(if raise { found.raised() } else { found });
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Read as _;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    use serde_json::{Value, json};

    use super::*;

    fn root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
    }

    fn fixture(name: &str) -> Vec<u8> {
        fs::read(
            root()
                .join("tests")
                .join("fixtures")
                .join("assemblies")
                .join(name),
        )
        .unwrap()
    }

    /// The 64-bit FNV-1a hash of the imports, as the oracle's `--digest`
    /// computes it.
    fn fnv1a64(imports: &[(u32, u32, String, String)]) -> u64 {
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for (method, flags, name, module) in imports {
            for b in format!("{method}\t{flags}\t{name}\t{module}\n").bytes() {
                hash = (hash ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
            }
        }
        hash
    }

    /// What customs reads from an assembly, in the shape the oracle prints.
    fn describe(bytes: &[u8], digest: bool) -> Value {
        let limits = Limits::default();
        let facts = Assembly::read(bytes, &limits).and_then(|assembly| {
            let initializer = match assembly.metadata.module_initializer()? {
                Some(method) => json!({ "code_size": assembly.code_size(method)? }),
                None => Value::Null,
            };
            Ok((
                assembly.metadata.rows.to_vec(),
                initializer,
                assembly.method_imports()?,
            ))
        });
        match facts {
            Err(_) => json!({ "managed": false }),
            Ok((rows, initializer, imports)) => {
                let imports = if digest {
                    json!({
                        "count": imports.len(),
                        "fnv1a64": format!("{:016x}", fnv1a64(&imports)),
                    })
                } else {
                    imports
                        .iter()
                        .map(|(method, flags, name, module)| {
                            json!({ "method": method, "flags": flags, "name": name, "module": module })
                        })
                        .collect()
                };
                json!({
                    "managed": true,
                    "rows": rows,
                    "module_initializer": initializer,
                    "imports": imports,
                })
            }
        }
    }

    /// The oracle's record without its key and its reason, which customs
    /// does not try to match.
    fn expected(record: &Value) -> Value {
        let mut expected = record.clone();
        if let Some(fields) = expected.as_object_mut() {
            for key in ["file", "entry", "reason"] {
                fields.remove(key);
            }
        }
        expected
    }

    fn oracle(path: &Path) -> Vec<Value> {
        fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    #[test]
    fn the_reader_agrees_with_the_oracle_on_every_fixture_assembly() {
        let records = oracle(
            &root()
                .join("tests")
                .join("fixtures")
                .join("assemblies")
                .join("oracle.jsonl"),
        );
        assert_eq!(records.len(), 5);
        for record in records {
            let name = record["file"].as_str().unwrap();
            assert_eq!(describe(&fixture(name), false), expected(&record), "{name}");
        }
    }

    #[test]
    #[ignore = "needs the corpus: python corpus/corpus.py fetch"]
    fn the_reader_agrees_with_the_oracle_on_every_corpus_assembly() {
        let records = oracle(&root().join("corpus").join("metadata-oracle.jsonl"));
        let dir = root().join("target").join("corpus");
        let mut archives: BTreeMap<String, zip::ZipArchive<fs::File>> = BTreeMap::new();
        let mut differ = Vec::new();
        let mut managed = 0;
        for record in &records {
            let file = record["file"].as_str().unwrap();
            let entry = record["entry"].as_str().unwrap();
            if !archives.contains_key(file) {
                let opened = zip::ZipArchive::new(fs::File::open(dir.join(file)).unwrap()).unwrap();
                archives.insert(file.to_owned(), opened);
            }
            let archive = archives.get_mut(file).unwrap();
            let mut bytes = Vec::new();
            archive
                .by_name(entry)
                .unwrap()
                .read_to_end(&mut bytes)
                .unwrap();
            let actual = describe(&bytes, true);
            if actual["managed"] == true {
                managed += 1;
            }
            if actual != expected(record) {
                differ.push(format!(
                    "{file} {entry}\n  customs {actual}\n  oracle  {record}"
                ));
            }
        }
        assert!(
            differ.is_empty(),
            "{} of {} assemblies differ:\n{}",
            differ.len(),
            records.len(),
            differ.join("\n")
        );
        assert!(managed > 0, "no managed assembly in the corpus oracle");
    }

    /// A metadata root with the given streams, laid out back to back.
    fn metadata_root(streams: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let version = b"v4.0.30319\0\0";
        let mut out = Vec::new();
        out.extend(0x424A_5342u32.to_le_bytes());
        out.extend([1, 0, 1, 0, 0, 0, 0, 0]);
        out.extend(u32::try_from(version.len()).unwrap().to_le_bytes());
        out.extend(version);
        out.extend([0, 0]);
        out.extend(u16::try_from(streams.len()).unwrap().to_le_bytes());
        let headers: usize = streams
            .iter()
            .map(|(name, _)| 8 + (name.len() + 1).next_multiple_of(4))
            .sum();
        let mut offset = out.len() + headers;
        let mut data: Vec<u8> = Vec::new();
        for (name, bytes) in streams {
            out.extend(u32::try_from(offset).unwrap().to_le_bytes());
            out.extend(u32::try_from(bytes.len()).unwrap().to_le_bytes());
            let mut padded = name.as_bytes().to_vec();
            padded.push(0);
            padded.resize(padded.len().next_multiple_of(4), 0);
            out.extend(padded);
            offset += bytes.len();
            data.extend(bytes);
        }
        out.extend(data);
        out
    }

    /// A `#~` stream: the header, the row counts and the table bytes.
    fn table_stream(heaps: u8, rows: &[(usize, u32)], extra: &[u8], tables: &[u8]) -> Vec<u8> {
        let valid = rows.iter().fold(0u64, |v, (t, _)| v | (1 << t));
        let mut out = vec![0, 0, 0, 0, 2, 0, heaps, 1];
        out.extend(valid.to_le_bytes());
        out.extend(0u64.to_le_bytes());
        let mut sorted = rows.to_vec();
        sorted.sort_unstable();
        for (_, count) in sorted {
            out.extend(count.to_le_bytes());
        }
        out.extend(extra);
        out.extend(tables);
        out
    }

    fn index(value: u32, wide: bool) -> Vec<u8> {
        if wide {
            value.to_le_bytes().to_vec()
        } else {
            u16::try_from(value).unwrap().to_le_bytes().to_vec()
        }
    }

    /// `<Module>` with one method, `.cctor` with `RTSpecialName`, in string
    /// columns of two or four bytes.
    fn module_with_initializer(heaps: u8, extra: &[u8]) -> Vec<u8> {
        let wide = heaps & WIDE_STRINGS != 0;
        let strings = b"\0<Module>\0.cctor\0".to_vec();
        let mut tables = Vec::new();
        // TypeDef: flags, name, namespace, extends, field list, method list.
        tables.extend(0u32.to_le_bytes());
        tables.extend(index(1, wide));
        tables.extend(index(0, wide));
        tables.extend([0, 0, 1, 0, 1, 0]);
        // MethodDef: RVA, impl flags, flags, name, signature, param list.
        tables.extend(0u32.to_le_bytes());
        tables.extend([0, 0]);
        tables.extend(0x1891u16.to_le_bytes());
        tables.extend(index(10, wide));
        tables.extend([0, 0, 1, 0]);
        metadata_root(&[
            (
                "#~",
                table_stream(heaps, &[(TYPE_DEF, 1), (METHOD_DEF, 1)], extra, &tables),
            ),
            ("#Strings", strings),
        ])
    }

    fn parse(bytes: &[u8]) -> Result<Metadata<'_>, Unreadable> {
        Metadata::parse(bytes, &Limits::default())
    }

    #[test]
    fn the_module_initialiser_is_found_in_narrow_and_wide_string_columns() {
        let narrow = module_with_initializer(0, &[]);
        assert_eq!(parse(&narrow).unwrap().module_initializer(), Ok(Some(1)));
        let wide = module_with_initializer(WIDE_STRINGS, &[]);
        assert_eq!(parse(&wide).unwrap().module_initializer(), Ok(Some(1)));
        // Read with the wrong width, the same bytes name something else.
        let mut misread = wide.clone();
        let flags = misread
            .windows(4)
            .position(|w| w == [2, 0, WIDE_STRINGS, 1])
            .unwrap();
        misread[flags + 2] = 0;
        assert_ne!(
            parse(&misread).map(|m| m.module_initializer()),
            Ok(Ok(Some(1)))
        );
    }

    /// With 65,536 methods an index into `MethodDef` is four bytes wide, in
    /// `TypeDef` and everywhere else. Only the corpus has assemblies that
    /// large; this one is built here.
    #[test]
    fn a_table_of_65536_rows_widens_every_index_into_it() {
        let methods = 0x1_0000u32;
        let mut tables = Vec::new();
        // TypeDef: flags, name, namespace, extends, field list, then a
        // method list of four bytes that starts at the last method.
        tables.extend([0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0]);
        tables.extend(methods.to_le_bytes());
        for row in 1..=methods {
            // MethodDef: RVA, impl flags, flags, name, signature, params.
            let (flags, name) = if row == methods {
                (0x1891u16, 10u16)
            } else {
                (0, 1)
            };
            tables.extend([0, 0, 0, 0, 0, 0]);
            tables.extend(flags.to_le_bytes());
            tables.extend(name.to_le_bytes());
            tables.extend([0, 0, 1, 0]);
        }
        let bytes = metadata_root(&[
            (
                "#~",
                table_stream(0, &[(TYPE_DEF, 1), (METHOD_DEF, methods)], &[], &tables),
            ),
            ("#Strings", b"\0<Module>\0.cctor\0".to_vec()),
        ]);
        assert_eq!(
            parse(&bytes).unwrap().module_initializer(),
            Ok(Some(methods))
        );
    }

    /// A `Module` row before `TypeDef`, and the `.cctor` in the second
    /// `MethodDef` row, after a blob column: each heap flag moves it.
    #[test]
    fn every_heap_size_flag_widens_its_columns() {
        for heaps in [
            0,
            WIDE_STRINGS,
            WIDE_GUIDS,
            WIDE_BLOBS,
            WIDE_STRINGS | WIDE_GUIDS | WIDE_BLOBS,
        ] {
            let s = |v: u32| index(v, heaps & WIDE_STRINGS != 0);
            let g = |v: u32| index(v, heaps & WIDE_GUIDS != 0);
            let b = |v: u32| index(v, heaps & WIDE_BLOBS != 0);
            let mut tables = Vec::new();
            // Module: generation, name, three GUIDs.
            tables.extend([0, 0]);
            tables.extend(s(1));
            tables.extend([g(1), g(0), g(0)].concat());
            // TypeDef: <Module> with methods 1 and 2.
            tables.extend(0u32.to_le_bytes());
            tables.extend([s(1), s(0)].concat());
            tables.extend([0, 0, 1, 0, 1, 0]);
            // MethodDef: an ordinary method, then the .cctor.
            for (flags, name) in [(0u16, 1), (0x1891, 10)] {
                tables.extend(0u32.to_le_bytes());
                tables.extend([0, 0]);
                tables.extend(flags.to_le_bytes());
                tables.extend([s(name), b(0)].concat());
                tables.extend([1, 0]);
            }
            let bytes = metadata_root(&[
                (
                    "#~",
                    table_stream(
                        heaps,
                        &[(MODULE, 1), (TYPE_DEF, 1), (METHOD_DEF, 2)],
                        &[],
                        &tables,
                    ),
                ),
                ("#Strings", b"\0<Module>\0.cctor\0".to_vec()),
            ]);
            assert_eq!(
                parse(&bytes).unwrap().module_initializer(),
                Ok(Some(2)),
                "heap flags {heaps:#04x}"
            );
        }
    }

    #[test]
    fn extra_data_after_the_row_counts_is_skipped_as_the_runtime_skips_it() {
        let bytes = module_with_initializer(EXTRA_DATA, &[0xAA; 4]);
        assert_eq!(parse(&bytes).unwrap().module_initializer(), Ok(Some(1)));
    }

    #[test]
    fn a_row_count_over_the_limit_is_a_gap_and_one_at_it_is_not() {
        let limits = Limits {
            table_rows: 2,
            ..Limits::default()
        };
        let over = metadata_root(&[("#~", table_stream(0, &[(MODULE_REF, 3)], &[], &[0; 6]))]);
        assert!(matches!(
            Metadata::parse(&over, &limits),
            Err(Unreadable::Limit(_))
        ));
        let at = metadata_root(&[("#~", table_stream(0, &[(MODULE_REF, 2)], &[], &[0; 4]))]);
        assert!(Metadata::parse(&at, &limits).is_ok());
    }

    #[test]
    fn row_counts_that_need_more_bytes_than_the_stream_has_are_refused() {
        for rows in [1, 0x00FF_FFFF] {
            let bytes = metadata_root(&[(
                "#~",
                table_stream(
                    0,
                    &[(TYPE_DEF, rows), (GENERIC_PARAM_CONSTRAINT, rows)],
                    &[],
                    &[0; 13],
                ),
            )]);
            assert_eq!(
                parse(&bytes).err(),
                Some(Malformed("the tables are larger than the #~ stream"))
            );
        }
    }

    #[test]
    fn metadata_that_readers_could_read_differently_is_refused() {
        let tables = || table_stream(0, &[], &[], &[]);
        let refused = [
            metadata_root(&[("#~", tables()), ("#~", tables())]),
            metadata_root(&[
                ("#~", tables()),
                ("#Strings", vec![0]),
                ("#Strings", vec![0]),
            ]),
            metadata_root(&[("#-", tables())]),
            metadata_root(&[("#~", tables()), ("#-", tables())]),
            metadata_root(&[("#Strings", vec![0])]),
            metadata_root(&[("#~", table_stream(DELTA, &[], &[], &[]))]),
            metadata_root(&[("#~", table_stream(0, &[(METHOD_PTR, 0)], &[], &[]))]),
            metadata_root(&[("#~", table_stream(0, &[(ENC_LOG, 0)], &[], &[]))]),
            metadata_root(&[("#~", table_stream(0, &[(0x30, 0)], &[], &[]))]),
        ];
        for (i, bytes) in refused.iter().enumerate() {
            assert!(matches!(parse(bytes), Err(Malformed(_))), "case {i}");
        }
        assert!(parse(&metadata_root(&[("#~", tables()), ("#Other", vec![1])])).is_ok());
    }

    #[test]
    fn a_method_list_that_runs_past_the_table_is_refused() {
        let mut tables = Vec::new();
        for method_list in [1u16, 9] {
            tables.extend([0; 12]);
            tables.extend(method_list.to_le_bytes());
        }
        tables.extend([0; 14]);
        let bytes = metadata_root(&[(
            "#~",
            table_stream(0, &[(TYPE_DEF, 2), (METHOD_DEF, 1)], &[], &tables),
        )]);
        assert!(matches!(
            parse(&bytes).unwrap().module_initializer(),
            Err(Malformed(_))
        ));
    }

    #[test]
    fn names_are_compared_in_place_and_read_to_a_limit() {
        let mut heap = vec![0];
        heap.extend(b".cctor\0");
        heap.extend(vec![b'A'; NAME_LIMIT + 1]);
        let bytes = metadata_root(&[("#~", table_stream(0, &[], &[], &[])), ("#Strings", heap)]);
        let metadata = parse(&bytes).unwrap();
        assert!(metadata.name_is(1, b".cctor", false));
        assert!(!metadata.name_is(1, b".CCTOR", false));
        assert!(metadata.name_is(1, b".CCTOR", true));
        assert!(!metadata.name_is(1, b".cct", false));
        assert!(!metadata.name_is(u32::MAX, b".cctor", false));
        assert_eq!(metadata.name(1), Ok(&b".cctor"[..]));
        assert_eq!(metadata.name(0), Ok(&b""[..]));
        assert!(metadata.name(8).is_err());
        assert!(metadata.name(u32::MAX).is_err());
    }

    /// A metadata reader that read every name to its end would take
    /// quadratic time here: 200,000 types and imports that all point at one
    /// name of a megabyte with no end.
    #[test]
    fn rows_that_all_point_at_one_endless_name_are_read_in_linear_time() {
        let rows = 200_000u32;
        let mut tables = Vec::new();
        for _ in 0..rows {
            // TypeDef: flags, name, namespace, extends (4 bytes, as the
            // table has over 2^14 rows), field list, method list.
            tables.extend([0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0]);
        }
        for _ in 0..rows {
            // ImplMap: flags, member, import name, module.
            tables.extend([0, 0, 0, 0, 1, 0, 0, 0]);
        }
        let mut heap = vec![0];
        heap.extend(vec![b'A'; 1 << 20]);
        let bytes = metadata_root(&[
            (
                "#~",
                table_stream(0, &[(TYPE_DEF, rows), (IMPL_MAP, rows)], &[], &tables),
            ),
            ("#Strings", heap),
        ]);
        let started = Instant::now();
        let assembly = Assembly {
            bytes: &[],
            sections: SectionTable::default(),
            metadata: parse(&bytes).unwrap(),
        };
        let report = assembly.check("lib/a.dll", &Limits::default()).unwrap();
        assert_eq!(report.findings, Vec::new());
        assert!(started.elapsed() < Duration::from_secs(60));
    }

    #[test]
    fn findings_past_the_limit_of_one_assembly_are_one_gap() {
        let rows = 5u32;
        let mut tables = Vec::new();
        for _ in 0..rows {
            tables.extend([0, 0, 0, 0, 1, 0, 0, 0]);
        }
        let bytes = metadata_root(&[
            ("#~", table_stream(0, &[(IMPL_MAP, rows)], &[], &tables)),
            ("#Strings", b"\0virtualprotect\0".to_vec()),
        ]);
        let assembly = Assembly {
            bytes: &[],
            sections: SectionTable::default(),
            metadata: parse(&bytes).unwrap(),
        };
        let limits = Limits {
            findings_per_file: 3,
            ..Limits::default()
        };
        let report = assembly.check("lib/a.dll", &limits).unwrap();
        assert_eq!(report.findings.len(), 3);
        assert_eq!(
            report.findings[0].evidence.as_deref(),
            Some("!VirtualProtect")
        );
        assert_eq!(report.gaps.len(), 1);
        assert!(report.gaps[0].message.contains("2 more"));
    }

    /// Checks metadata with one `ImplMap` row whose import name is at `name`
    /// in a heap that holds `VirtualProtect` at 1 and an empty string at 16.
    fn check_import(name: u16) -> Result<Report, Unreadable> {
        let mut tables = vec![0, 0, 1, 0];
        tables.extend(name.to_le_bytes());
        tables.extend([0, 0]);
        let bytes = metadata_root(&[
            ("#~", table_stream(0, &[(IMPL_MAP, 1)], &[], &tables)),
            ("#Strings", b"\0VirtualProtect\0\0".to_vec()),
        ]);
        let assembly = Assembly {
            bytes: &[],
            sections: SectionTable::default(),
            metadata: parse(&bytes).unwrap(),
        };
        assembly.check("lib/a.dll", &Limits::default())
    }

    /// ECMA-335 II.22.22: `ImportName` shall index a non-empty string.
    #[test]
    fn an_import_without_a_name_is_refused() {
        assert_eq!(check_import(1).unwrap().findings.len(), 1);
        for name in [0, 16] {
            assert_eq!(
                check_import(name).err(),
                Some(Malformed("a P/Invoke has an empty import name")),
                "name index {name}"
            );
        }
    }

    fn read_and_check(bytes: &[u8]) -> Result<Report, Unreadable> {
        let limits = Limits::default();
        Assembly::read(bytes, &limits).and_then(|a| a.check("lib/a.dll", &limits))
    }

    #[test]
    fn every_truncation_of_an_assembly_is_refused_without_a_panic() {
        let bytes = fixture("ModuleInit.dll");
        assert_eq!(read_and_check(&bytes).unwrap().findings.len(), 1);
        for length in 0..bytes.len() {
            // Most cuts leave the headers whole and cut the metadata or a
            // body; the point is that none of them panics.
            let _ = read_and_check(&bytes[..length]);
        }
        assert_eq!(
            read_and_check(&bytes[..64]).err(),
            Some(Malformed("the PE headers cannot be read"))
        );
        assert_eq!(read_and_check(b"\x7fELF").err(), Some(Unreadable::NotPe));
    }

    /// A package view over bytes in memory.
    struct Memory(Vec<u8>);

    impl Files for Memory {
        fn entries(&mut self, _: &Limits, _: &mut Outcome) -> Vec<Entry> {
            Vec::new()
        }

        fn read(
            &mut self,
            _: &Entry,
            cap: u64,
            _: &Limits,
            budget: &mut crate::package::Budget,
        ) -> Result<Vec<u8>, Gap> {
            let n = self.0.len().min(usize::try_from(cap).unwrap());
            budget.bytes += n as u64;
            Ok(self.0[..n].to_vec())
        }
    }

    fn scan_one(bytes: Vec<u8>, path: &str, asset: Asset, limits: &Limits) -> (Asset, Outcome) {
        let path = PackagePath::new(path, limits).unwrap();
        let entries = [Entry {
            path: path.clone(),
            size: bytes.len() as u64,
            key: 0,
        }];
        let mut assets = [(path, asset)];
        let mut outcome = Outcome::default();
        scan(
            &mut Memory(bytes),
            &entries,
            &mut assets,
            limits,
            &mut outcome,
        );
        (assets[0].1, outcome)
    }

    #[test]
    fn an_assembly_one_byte_over_the_limit_is_a_gap_and_read_no_further() {
        let bytes = fixture("ModuleInit.dll");
        let lib = Asset::Managed {
            role: ManagedRole::Lib,
        };
        let at = Limits {
            assembly_bytes: bytes.len() as u64,
            ..Limits::default()
        };
        let (_, outcome) = scan_one(bytes.clone(), "lib/a.dll", lib, &at);
        assert_eq!(outcome.findings.len(), 1);
        assert_eq!(outcome.gaps, Vec::new());

        let over = Limits {
            assembly_bytes: bytes.len() as u64 - 1,
            ..Limits::default()
        };
        let (_, outcome) = scan_one(bytes.clone(), "lib/a.dll", lib, &over);
        assert_eq!(outcome.findings, Vec::new());
        assert_eq!(outcome.gaps.len(), 1);
        assert!(outcome.gaps[0].message.contains("an assembly over"));
        assert_eq!(outcome.budget.bytes, bytes.len() as u64);
    }

    #[test]
    fn native_code_under_tools_becomes_a_native_binary_and_elsewhere_is_c304() {
        let elf = b"\x7fELF\x02\x01\x01".to_vec();
        let tool = Asset::Managed {
            role: ManagedRole::BuildTime,
        };
        let (asset, outcome) =
            scan_one(elf.clone(), "tools/linux/gen.dll", tool, &Limits::default());
        assert_eq!(
            asset,
            Asset::Native {
                format: NativeFormat::Elf
            }
        );
        assert_eq!(outcome.findings, Vec::new());
        // A task assembly that UsingTask names in lib/ is build-time code,
        // but lib/ is where NuGet expects managed code.
        let (asset, outcome) = scan_one(elf, "lib/net8.0/gen.dll", tool, &Limits::default());
        assert_eq!(asset, tool);
        assert_eq!(outcome.findings.len(), 1);
        assert_eq!(outcome.findings[0].rule, FindingRule::C304);
        assert_eq!(outcome.findings[0].severity, crate::scan::Severity::Error);
    }

    #[test]
    fn every_change_of_one_byte_is_read_or_refused_without_a_panic() {
        let bytes = fixture("ModuleInit.dll");
        let mut changed = bytes.clone();
        for at in 0..bytes.len() {
            for value in [0x00, 0xFF, 0x80, 0x01] {
                changed[at] = value;
                let _ = read_and_check(&changed);
            }
            changed[at] = bytes[at];
        }
    }
}
