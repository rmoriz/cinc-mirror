//! Apache-style autoindex parsing.
//!
//! Upstream serves plain Apache directory listings behind the OSU OSL mirror
//! navigation. A listing therefore contains links that are not entries at all:
//! `?C=N;O=D` sort links, an absolute `Parent Directory` link, `../`, the
//! stylesheet `<link>` and absolute `https://ftp.osuosl.org/...` navigation.
//!
//! The scanner is deliberately small and allocation-free per tag: it looks at
//! `<a ...>` tags only, reads the `href` attribute, then keeps a value only when
//! it is a relative, single path component. Anything malformed simply produces
//! no entry — the parser never panics on hostile HTML.

use percent_encoding::percent_decode_str;

/// One entry in an upstream directory listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexEntry {
    /// Entry name below the listed directory, percent-decoded and without the
    /// trailing slash a directory link carries.
    pub name: String,
    /// Whether the entry is a directory (the link ended with `/`).
    pub is_dir: bool,
}

/// Parse the `<a href="...">` entries of an Apache autoindex.
///
/// Sort links, absolute paths, absolute URLs and traversal are dropped, as are
/// names that are not a single path component. The result keeps document order.
#[must_use]
pub fn parse_index(html: &str) -> Vec<IndexEntry> {
    parse_anchors(html)
        .into_iter()
        .filter_map(entry_from_href)
        .collect()
}

/// Parse an autoindex and report whether the document contained any `<a>` tag.
///
/// [`super::Source::list`] uses this to tell an empty directory (which still has
/// sort links) from a page that is not a listing at all.
pub(crate) fn parse_anchors(html: &str) -> Vec<&str> {
    let mut hrefs = Vec::new();
    let mut cursor = 0;

    while let Some(offset) = html[cursor..].find('<') {
        let tag_start = cursor + offset;
        let Some(length) = html[tag_start..].find('>') else {
            break;
        };
        let tag = &html[tag_start..tag_start + length];
        cursor = tag_start + length + 1;

        if is_anchor_tag(tag) {
            if let Some(href) = attribute_value(tag, "href") {
                hrefs.push(href);
            }
        }
    }

    hrefs
}

/// Keep only relative links that name a single, safe path component.
pub(crate) fn entry_from_href(href: &str) -> Option<IndexEntry> {
    if href.is_empty()
        || href.starts_with('?')
        || href.starts_with('#')
        || href.starts_with('/')
        || href.contains("://")
    {
        return None;
    }

    let is_dir = href.ends_with('/');
    let without_slash = if is_dir {
        href.strip_suffix('/')?
    } else {
        href
    };

    let name = percent_decode_str(without_slash).decode_utf8().ok()?;

    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.chars().any(char::is_control)
    {
        return None;
    }

    Some(IndexEntry {
        name: name.into_owned(),
        is_dir,
    })
}

fn is_anchor_tag(tag: &str) -> bool {
    let Some(rest) = tag.strip_prefix("<a").or_else(|| tag.strip_prefix("<A")) else {
        return false;
    };

    rest.starts_with(|ch: char| ch.is_ascii_whitespace())
}

/// Read the value of a quoted attribute from an already isolated tag.
fn attribute_value<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let lowered = tag.to_ascii_lowercase();
    let mut cursor = 0;

    while let Some(offset) = lowered[cursor..].find(name) {
        let start = cursor + offset;
        let separated = start == 0 || tag.as_bytes()[start - 1].is_ascii_whitespace();
        let rest = tag[start + name.len()..].trim_start();

        if separated {
            if let Some(rest) = rest.strip_prefix('=') {
                let value = rest.trim_start();
                if let Some(quote) = value.chars().next().filter(|ch| *ch == '"' || *ch == '\'') {
                    let value = &value[quote.len_utf8()..];
                    if let Some(end) = value.find(quote) {
                        return Some(&value[..end]);
                    }
                }
            }
        }

        cursor = start + name.len();
    }

    None
}
