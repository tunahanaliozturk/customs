//! XML as MSBuild and NuGet read it: decoding, the XML declaration, the DTD,
//! a table of line starts, and the identity a nuspec declares.
//!
//! What MSBuild does, checked in its source on 2026-11-22: it reads project
//! files with `DtdProcessing.Ignore`, detects UTF-8 and UTF-16 from the byte
//! order mark and honours any encoding the XML declaration names
//! (`src/Build/Xml/XmlReaderExtension.cs`).

use roxmltree::{Document, Node, ParsingOptions};

use crate::package::Limits;

/// Decoded text, and why the file is C004 if it is. Each reason completes
/// the sentence "an MSBuild file that ...".
#[derive(Debug)]
pub(crate) struct Decoded {
    pub(crate) text: String,
    pub(crate) problems: Vec<String>,
}

/// Decodes a file as MSBuild would.
pub(crate) fn decode(bytes: &[u8]) -> Decoded {
    match bytes {
        [0xEF, 0xBB, 0xBF, rest @ ..] => utf8(rest),
        [0xFF, 0xFE, rest @ ..] => utf16(rest, false),
        [0xFE, 0xFF, rest @ ..] => utf16(rest, true),
        [b'<', 0, ..] => utf16(bytes, false),
        [0, b'<', ..] => utf16(bytes, true),
        _ => utf8(bytes),
    }
}

fn utf16(bytes: &[u8], big_endian: bool) -> Decoded {
    let (pairs, rest) = bytes.as_chunks::<2>();
    let units: Vec<u16> = pairs
        .iter()
        .map(|pair| {
            if big_endian {
                u16::from_be_bytes(*pair)
            } else {
                u16::from_le_bytes(*pair)
            }
        })
        .collect();
    let mut problems = Vec::new();
    let text = match String::from_utf16(&units) {
        Ok(text) if rest.is_empty() => text,
        _ => {
            problems.push("is not valid UTF-16".to_owned());
            String::from_utf16_lossy(&units)
        }
    };
    match declaration(text.as_bytes()) {
        Declaration::Unterminated => {
            problems.push("has an XML declaration that does not end".to_owned());
        }
        Declaration::Encoding(name) if !is_utf16(&name) => {
            problems.push(format!("is UTF-16 but declares the encoding {name}"));
        }
        Declaration::Encoding(_) | Declaration::None => {}
    }
    Decoded { text, problems }
}

fn utf8(bytes: &[u8]) -> Decoded {
    let mut problems = Vec::new();
    let declared = match declaration(bytes) {
        Declaration::Unterminated => {
            problems.push("has an XML declaration that does not end".to_owned());
            None
        }
        Declaration::Encoding(name) if !is_utf8(&name) => {
            problems.push(format!("declares the encoding {name}"));
            Some(name)
        }
        Declaration::Encoding(_) | Declaration::None => None,
    };
    let text = match (std::str::from_utf8(bytes), declared) {
        (Ok(text), _) => text.to_owned(),
        // A file that declares a single-byte encoding is read by MSBuild in
        // that encoding; reading each byte as a character keeps every ASCII
        // construct where it is.
        (Err(_), Some(_)) => bytes.iter().map(|b| char::from(*b)).collect(),
        // Anything else is read as .NET would, with replacement characters.
        (Err(_), None) => {
            problems.push("is not valid UTF-8 or UTF-16".to_owned());
            String::from_utf8_lossy(bytes).into_owned()
        }
    };
    Decoded { text, problems }
}

fn is_utf8(name: &str) -> bool {
    ["utf-8", "utf8"]
        .iter()
        .any(|n| name.eq_ignore_ascii_case(n))
}

fn is_utf16(name: &str) -> bool {
    ["utf-16", "utf-16le", "utf-16be", "unicode", "ucs-2"]
        .iter()
        .any(|n| name.eq_ignore_ascii_case(n))
}

#[derive(Debug)]
enum Declaration {
    None,
    Unterminated,
    Encoding(String),
}

/// The XML declaration at the start of the text, read to its `?>` however
/// far that is.
fn declaration(bytes: &[u8]) -> Declaration {
    let Some(rest) = bytes.strip_prefix(b"<?xml") else {
        return Declaration::None;
    };
    if !rest
        .first()
        .is_some_and(|b| b.is_ascii_whitespace() || *b == b'?')
    {
        return Declaration::None;
    }
    let Some(end) = rest.windows(2).position(|w| w == b"?>") else {
        return Declaration::Unterminated;
    };
    let declaration = String::from_utf8_lossy(&rest[..end]);
    let Some(at) = declaration.find("encoding") else {
        return Declaration::None;
    };
    let after = &declaration[at + "encoding".len()..];
    let encoding = after
        .trim_start()
        .strip_prefix('=')
        .map(str::trim_start)
        .and_then(|value| {
            let quote = value.chars().next().filter(|c| *c == '"' || *c == '\'')?;
            let value = &value[1..];
            Some(value[..value.find(quote)?].to_owned())
        });
    encoding.map_or(Declaration::None, Declaration::Encoding)
}

/// Replaces a document type declaration in the prolog with spaces, keeping
/// line breaks, so that the file parses as MSBuild reads it: with the DTD
/// ignored. Only the prolog is looked at, so `<!DOCTYPE` in a comment or a
/// value later in the file blanks nothing. Returns whether there was one.
pub(crate) fn blank_doctype(text: &mut String) -> bool {
    let bytes = text.as_bytes();
    let mut i = 0;
    let start = loop {
        while bytes.get(i).is_some_and(u8::is_ascii_whitespace) {
            i += 1;
        }
        let rest = &bytes[i..];
        let skip = if rest.starts_with(b"<?") {
            find(rest, b"?>").map(|e| e + 2)
        } else if rest.starts_with(b"<!--") {
            find(rest, b"-->").map(|e| e + 3)
        } else if rest.starts_with(b"<!DOCTYPE") {
            break i;
        } else {
            return false;
        };
        match skip {
            Some(skip) => i += skip,
            None => return false,
        }
    };
    let mut depth = 0_usize;
    let mut quote = None;
    let mut end = bytes.len();
    let mut j = start + "<!DOCTYPE".len();
    while j < bytes.len() {
        let b = bytes[j];
        match quote {
            Some(q) if b == q => quote = None,
            Some(_) => {}
            None if bytes[j..].starts_with(b"<!--") => {
                j = find(&bytes[j..], b"-->").map_or(bytes.len(), |e| j + e + 2);
            }
            None => match b {
                b'"' | b'\'' => quote = Some(b),
                b'[' => depth += 1,
                b']' => depth = depth.saturating_sub(1),
                b'>' if depth == 0 => {
                    end = j + 1;
                    break;
                }
                _ => {}
            },
        }
        j += 1;
    }
    let blanked: String = text[start..end]
        .chars()
        .map(|c| if c == '\n' || c == '\r' { c } else { ' ' })
        .collect();
    text.replace_range(start..end, &blanked);
    true
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// The byte offset where each line starts. `\n`, `\r\n` and a lone `\r`
/// each end a line.
#[derive(Debug)]
pub(crate) struct Lines(Vec<usize>);

impl Lines {
    pub(crate) fn new(text: &str) -> Self {
        let bytes = text.as_bytes();
        let mut starts = vec![0];
        for (i, b) in bytes.iter().enumerate() {
            let ends = *b == b'\n' || (*b == b'\r' && bytes.get(i + 1) != Some(&b'\n'));
            if ends {
                starts.push(i + 1);
            }
        }
        Self(starts)
    }

    /// The 1-based line of a byte offset.
    pub(crate) fn line(&self, offset: usize) -> u32 {
        u32::try_from(self.0.partition_point(|&start| start <= offset)).unwrap_or(u32::MAX)
    }
}

/// Parsing options: DTDs refused (they are blanked before parsing) and the
/// node limit applied.
pub(crate) fn options<'input>(limits: &Limits) -> ParsingOptions<'input> {
    ParsingOptions {
        allow_dtd: false,
        nodes_limit: u32::try_from(limits.xml_nodes).unwrap_or(u32::MAX),
        ..ParsingOptions::default()
    }
}

/// All text children of a node, joined: a comment inside `<id>` does not
/// cut the ID short.
fn text_of(node: Node<'_, '_>) -> String {
    node.children()
        .filter(Node::is_text)
        .filter_map(|n| n.text())
        .collect()
}

/// The ID and version a nuspec declares, if it is well-formed and has both.
pub(crate) fn nuspec_identity(bytes: &[u8], limits: &Limits) -> Option<(String, String)> {
    let mut text = decode(bytes).text;
    blank_doctype(&mut text);
    let doc = Document::parse_with_options(&text, options(limits)).ok()?;
    let metadata = doc
        .root_element()
        .children()
        .find(|n| n.tag_name().name() == "metadata")?;
    let field = |name: &str| {
        metadata
            .children()
            .find(|n| n.tag_name().name() == name)
            .map(|n| text_of(n).trim().to_owned())
            .filter(|t| !t.is_empty())
    };
    Some((field("id")?, field("version")?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodings_are_detected_as_msbuild_detects_them() {
        let plain = |bytes: &[u8]| decode(bytes);
        assert_eq!(plain(b"\xEF\xBB\xBF<P/>").text, "<P/>");
        assert_eq!(plain(b"<\0P\0/\0>\0").text, "<P/>");
        assert_eq!(plain(b"\0<\0P\0/\0>").text, "<P/>");
        assert_eq!(plain(b"<P/>").problems, Vec::<String>::new());
        assert_eq!(
            plain(b"<?xml version='1.0' encoding='iso-8859-1'?><P/>").problems,
            ["declares the encoding iso-8859-1"]
        );
        assert_eq!(
            plain(b"<?xml version='1.0' encoding='UTF-8'?><P/>").problems,
            Vec::<String>::new()
        );
        let latin = plain(b"<?xml version='1.0' encoding='windows-1252'?><P a='\xE9'/>");
        assert_eq!(latin.problems.len(), 1);
        assert!(latin.text.contains('\u{e9}'));
        assert_eq!(
            plain(b"<P a='\xE9'/>").problems,
            ["is not valid UTF-8 or UTF-16"]
        );
        assert_eq!(
            plain(b"<?xml version='1.0'").problems,
            ["has an XML declaration that does not end"]
        );
        assert_eq!(
            plain(b"\xFF\xFE<\0?\0x\0m\0l\0 \0e\0n\0c\0o\0d\0i\0n\0g\0=\0'\0x\0'\0?\0>\0").problems,
            ["is UTF-16 but declares the encoding x"]
        );
        assert_eq!(plain(b"\xFF\xFE<\0P").problems, ["is not valid UTF-16"]);
        // A processing instruction that only starts with "xml" is not one.
        assert_eq!(
            plain(b"<?xml-stylesheet href='a'?><P/>").problems,
            Vec::<String>::new()
        );
    }

    #[test]
    fn a_doctype_in_the_prolog_is_blanked_without_moving_lines() {
        let mut text =
            "<?xml version=\"1.0\"?>\n<!-- c -->\n<!DOCTYPE P [\n<!ENTITY e \"]>\">\n]>\n<P/>"
                .to_owned();
        assert!(blank_doctype(&mut text));
        assert_eq!(text.lines().count(), 6);
        assert!(text.ends_with("\n<P/>"));
        assert!(!text.contains("ENTITY"));
        assert!(Document::parse(&text).is_ok());

        let mut later = "<P><!-- <!DOCTYPE x \" --><Q/></P>".to_owned();
        assert!(!blank_doctype(&mut later));
        assert!(later.contains("<Q/>"));
    }

    #[test]
    fn lines_count_lf_crlf_and_lone_cr_once_each() {
        let text = "a\nb\r\nc\rd\n<!-- x\ny -->\ne";
        let lines = Lines::new(text);
        let line_of = |needle: &str| lines.line(text.find(needle).unwrap());
        assert_eq!(line_of("a"), 1, "the first line");
        assert_eq!(line_of("b"), 2);
        assert_eq!(line_of("c"), 3, "after CRLF");
        assert_eq!(line_of("d"), 4, "after a lone CR");
        assert_eq!(line_of("y -->"), 6);
        assert_eq!(line_of("e"), 7, "the last line, after a multi-line comment");
        assert_eq!(Lines::new("").line(0), 1);
    }

    #[test]
    fn a_nuspec_gives_the_id_and_version() {
        let nuspec = b"<package xmlns='urn:x'><metadata><id> Contoso.<!--c-->A </id><version>1.0.0</version></metadata></package>";
        assert_eq!(
            nuspec_identity(nuspec, &Limits::default()),
            Some(("Contoso.A".to_owned(), "1.0.0".to_owned()))
        );
        assert_eq!(nuspec_identity(b"<package/>", &Limits::default()), None);
        assert_eq!(
            nuspec_identity(
                b"<package><metadata><id> </id><version>1.0.0</version></metadata></package>",
                &Limits::default()
            ),
            None
        );
    }
}
