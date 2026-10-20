//! Bounded XML events, retaining only one direct child of the document root.

use std::collections::HashSet;
use std::io::{self, BufRead, BufReader, Read};

use quick_xml::XmlVersion;
use quick_xml::events::Event;
use quick_xml::name::ResolveResult;
use quick_xml::reader::NsReader;

use crate::index::IndexError;
use crate::release::ParseLimits;

const MAX_DEPTH: usize = 64;
const MAX_ATTRIBUTES: usize = 128;
const MAX_NAMESPACES: usize = 32;
const MAX_STANZA_ELEMENTS: usize = 65_536;

pub(super) struct Element {
    pub(super) name: String,
    in_document_namespace: bool,
    attributes: Vec<(String, String)>,
    pub(super) children: Vec<Element>,
    pub(super) text: String,
}

impl Element {
    pub(super) fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find_map(|(key, value)| (key == name).then_some(value.as_str()))
    }

    pub(super) fn field(&self, name: &'static str) -> Result<Option<&Self>, IndexError> {
        let mut found = None;
        for child in &self.children {
            if child.name == name && child.in_document_namespace {
                if found.is_some() {
                    return Err(IndexError::DuplicateField(name.to_owned()));
                }
                found = Some(child);
            }
        }
        Ok(found)
    }

    pub(super) fn scalar(&self) -> Result<&str, IndexError> {
        if !self.children.is_empty() {
            return Err(invalid("nested element in scalar XML field"));
        }
        Ok(self.text.trim())
    }

    pub(super) fn in_document_namespace(&self) -> bool {
        self.in_document_namespace
    }
}

fn invalid(error: impl std::fmt::Display) -> IndexError {
    IndexError::Deb822(format!("RPM XML: {error}"))
}

fn namespace_name(namespace: ResolveResult<'_>) -> Result<String, IndexError> {
    match namespace {
        ResolveResult::Unbound => Ok(String::new()),
        ResolveResult::Bound(namespace) => {
            if namespace.as_ref().len() > 1024 {
                return Err(invalid("XML namespace name exceeds 1024 bytes"));
            }
            Ok(quick_xml::escape::unescape(namespace.as_ref())
                .map_err(invalid)?
                .into_owned())
        }
        ResolveResult::Unknown(_) => Err(invalid("undeclared namespace prefix")),
    }
}

fn valid_text(text: &str) -> Result<(), IndexError> {
    if text.chars().any(|character| {
        !matches!(character, '\u{9}' | '\u{a}' | '\u{d}' | '\u{20}'..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..='\u{10ffff}')
    }) {
        return Err(invalid("illegal XML character"));
    }
    Ok(())
}

pub(super) fn document<R, F>(
    reader: R,
    root_name: &str,
    expected_namespace: &str,
    limits: &ParseLimits,
    max_bytes: u64,
    mut child: F,
) -> Result<(), IndexError>
where
    R: Read,
    F: FnMut(Element) -> Result<(), IndexError>,
{
    let source = BoundedInput {
        inner: BufReader::new(reader),
        remaining: max_bytes,
        event_remaining: 0,
    };
    let mut reader = NsReader::from_reader(source);
    reader.config_mut().check_comments = true;
    reader
        .resolver_mut()
        .set_max_namespace_bindings(MAX_NAMESPACES);
    let mut buffer = Vec::new();
    let mut stack: Vec<Element> = Vec::new();
    let mut root_seen = false;
    let mut root_closed = false;
    let mut declaration_seen = false;
    let mut version = XmlVersion::Implicit1_0;
    let mut root_namespace = String::new();
    let mut stanza_start = 0u64;
    let mut stanza_elements = 0usize;
    loop {
        let position = reader.buffer_position();
        let stanza_remaining = if stack.len() >= 2 {
            limits
                .max_stanza
                .saturating_sub((position - stanza_start) as usize)
        } else {
            limits.max_stanza
        };
        reader.get_mut().event_remaining = limits.max_line.min(stanza_remaining);
        buffer.clear();
        let (namespace, event) = reader
            .read_resolved_event_into(&mut buffer)
            .map_err(invalid)?;
        let namespace = namespace_name(namespace)?;
        match &event {
            Event::Start(start) | Event::Empty(start) => {
                if root_closed || stack.len() >= MAX_DEPTH {
                    return Err(invalid("multiple roots or XML nesting limit exceeded"));
                }
                let name = start.local_name().into_inner().to_owned();
                let mut attributes = Vec::new();
                let mut seen_attributes = HashSet::new();
                for (count, attribute) in start.attributes().enumerate() {
                    if count >= MAX_ATTRIBUTES {
                        return Err(invalid("XML attribute limit exceeded"));
                    }
                    let attribute = attribute.map_err(invalid)?;
                    let (attribute_namespace, local) =
                        reader.resolver().resolve_attribute(attribute.key);
                    let attribute_namespace = namespace_name(attribute_namespace)?;
                    let local = local.into_inner().to_owned();
                    if !seen_attributes.insert((attribute_namespace.clone(), local.clone())) {
                        return Err(IndexError::DuplicateField(local));
                    }
                    let value = attribute.normalized_value(version).map_err(invalid)?;
                    valid_text(&value)?;
                    if (attribute.key.as_ref() == "xmlns"
                        || attribute.key.as_ref().starts_with("xmlns:"))
                        && value.len() > 1024
                    {
                        return Err(invalid("XML namespace name exceeds 1024 bytes"));
                    }
                    if attribute_namespace.is_empty() {
                        attributes.push((local, value.into_owned()));
                    }
                }
                if stack.is_empty() {
                    if root_seen
                        || name != root_name
                        || (!namespace.is_empty() && namespace != expected_namespace)
                    {
                        return Err(invalid("unexpected XML document root"));
                    }
                    root_seen = true;
                    root_namespace = namespace.clone();
                } else {
                    if stack.len() == 1 {
                        stanza_start = position;
                        stanza_elements = 0;
                    }
                    stanza_elements += 1;
                    if stanza_elements > MAX_STANZA_ELEMENTS {
                        return Err(invalid("XML stanza element limit exceeded"));
                    }
                }
                stack.push(Element {
                    name,
                    in_document_namespace: namespace == root_namespace,
                    attributes,
                    children: Vec::new(),
                    text: String::new(),
                });
                if matches!(event, Event::Empty(_)) {
                    complete(&mut stack, &mut root_closed, &mut child)?;
                }
            }
            Event::End(_) => {
                complete(&mut stack, &mut root_closed, &mut child)?;
            }
            Event::Text(text) => {
                let text = text.xml_content(version);
                append_text(&mut stack, &text)?;
            }
            Event::CData(text) => {
                if stack.is_empty() {
                    return Err(invalid("CDATA outside document root"));
                }
                let text = text.xml_content(version);
                append_text(&mut stack, &text)?;
            }
            Event::GeneralRef(reference) => {
                if stack.is_empty() {
                    return Err(invalid("entity outside document root"));
                }
                let escaped = format!("&{};", reference.as_ref());
                let text = quick_xml::escape::unescape(&escaped).map_err(invalid)?;
                append_text(&mut stack, &text)?;
            }
            Event::Decl(declaration) => {
                if root_seen || declaration_seen {
                    return Err(invalid("misplaced XML declaration"));
                }
                declaration_seen = true;
                version = declaration.xml_version().map_err(invalid)?;
                if let Some(encoding) = declaration.encoding() {
                    let encoding = encoding.map_err(invalid)?;
                    if !encoding.eq_ignore_ascii_case("utf-8") {
                        return Err(invalid("RPM XML requires UTF-8"));
                    }
                }
            }
            Event::DocType(_) => return Err(invalid("DTD is not supported")),
            Event::Eof => {
                if !root_seen || !root_closed || !stack.is_empty() {
                    return Err(invalid("incomplete XML document"));
                }
                return Ok(());
            }
            Event::Comment(comment) => valid_text(comment.as_ref())?,
            Event::PI(instruction) => valid_text(instruction.as_ref())?,
        }
        if stack.len() >= 2 && reader.buffer_position() - stanza_start > limits.max_stanza as u64 {
            return Err(IndexError::TooLarge { stanza: 0 });
        }
    }
}

fn append_text(stack: &mut [Element], text: &str) -> Result<(), IndexError> {
    valid_text(text)?;
    let depth = stack.len();
    if let Some(element) = stack.last_mut() {
        if depth == 1 {
            if !text.trim().is_empty() {
                return Err(invalid("text outside root children"));
            }
        } else {
            element.text.push_str(text);
        }
    } else if !text.trim().is_empty() {
        return Err(invalid("text outside document root"));
    }
    Ok(())
}

fn complete<F>(
    stack: &mut Vec<Element>,
    root_closed: &mut bool,
    child: &mut F,
) -> Result<(), IndexError>
where
    F: FnMut(Element) -> Result<(), IndexError>,
{
    let element = stack
        .pop()
        .ok_or_else(|| invalid("unexpected closing element"))?;
    if stack.is_empty() {
        *root_closed = true;
    } else if stack.len() == 1 {
        child(element)?;
    } else if let Some(parent) = stack.last_mut() {
        parent.children.push(element);
    }
    Ok(())
}

struct BoundedInput<R> {
    inner: BufReader<R>,
    remaining: u64,
    event_remaining: usize,
}

impl<R: Read> BufRead for BoundedInput<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        let buffer = self.inner.fill_buf()?;
        if buffer.is_empty() {
            return Ok(buffer);
        }
        let allowed = buffer
            .len()
            .min(self.event_remaining)
            .min(self.remaining as usize);
        if allowed == 0 {
            return Err(io::Error::other(
                "RPM XML event, stanza or aggregate bound exceeded",
            ));
        }
        Ok(&buffer[..allowed])
    }

    fn consume(&mut self, count: usize) {
        self.event_remaining -= count;
        self.remaining -= count as u64;
        self.inner.consume(count);
    }
}

impl<R: Read> Read for BoundedInput<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let buffer = self.fill_buf()?;
        let count = buffer.len().min(output.len());
        output[..count].copy_from_slice(&buffer[..count]);
        self.consume(count);
        Ok(count)
    }
}
