//! Minimal XML document builder (writing) and parser (reading) used for S3
//! request/response bodies. Serialization escapes text via quick-xml.

use quick_xml::Reader;
use quick_xml::escape::escape;
use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};

pub const XMLNS_S3: &str = crate::error::XMLNS_S3;

pub struct Xml {
    buf: String,
}

impl Xml {
    pub fn new() -> Self {
        Self { buf: String::new() }
    }

    /// Open an element, optionally with attributes.
    pub fn open(mut self, name: &str, attrs: &[(&str, &str)]) -> Self {
        self.buf.push('<');
        self.buf.push_str(name);
        for (k, v) in attrs {
            self.buf.push(' ');
            self.buf.push_str(k);
            self.buf.push_str("=\"");
            self.buf.push_str(&escape(*v));
            self.buf.push('"');
        }
        self.buf.push('>');
        self
    }

    /// Leaf element with escaped text content.
    pub fn el(self, name: &str, text: &str) -> Self {
        self.open(name, &[]).text_raw(&escape(text)).close(name)
    }

    /// Leaf element with raw (already-escaped) text content.
    pub fn el_raw(self, name: &str, text: &str) -> Self {
        self.open(name, &[]).text_raw(text).close(name)
    }

    fn text_raw(mut self, text: &str) -> Self {
        self.buf.push_str(text);
        self
    }

    pub fn close(mut self, name: &str) -> Self {
        self.buf.push_str("</");
        self.buf.push_str(name);
        self.buf.push('>');
        self
    }

    pub fn finish(self) -> String {
        self.buf
    }
}

/// Parse a query-string-free XML document into a tree of (tag, text, children).
/// Used for small S3 request payloads (Delete, CompleteMultipartUpload,
/// CreateBucket location constraint).
#[derive(Debug, Clone)]
pub struct XmlNode {
    pub tag: String,
    pub text: String,
    pub children: Vec<XmlNode>,
}

impl XmlNode {
    pub fn find_all(&self, tag: &str) -> Vec<&XmlNode> {
        let mut out = Vec::new();
        self.walk(tag, &mut out);
        out
    }
    fn walk<'a>(&'a self, tag: &str, out: &mut Vec<&'a XmlNode>) {
        for c in &self.children {
            if c.tag == tag {
                out.push(c);
            }
            c.walk(tag, out);
        }
    }
    pub fn child(&self, tag: &str) -> Option<&XmlNode> {
        self.children.iter().find(|c| c.tag == tag)
    }
    pub fn text_of(&self, tag: &str) -> Option<String> {
        self.child(tag).map(|c| c.text.clone())
    }
}

/// Parse the first document root; returns Err on malformed XML.
pub fn parse(data: &[u8]) -> Result<XmlNode, ()> {
    let mut reader = Reader::from_reader(data);
    reader.config_mut().trim_text(true);
    let mut stack: Vec<XmlNode> = Vec::new();
    loop {
        match reader.read_event() {
            Ok(Event::Start(start)) => {
                let tag = String::from_utf8_lossy(start.name().as_ref()).into_owned();
                stack.push(XmlNode {
                    tag,
                    text: String::new(),
                    children: Vec::new(),
                });
            }
            Ok(Event::Empty(start)) => {
                let tag = String::from_utf8_lossy(start.name().as_ref()).into_owned();
                let node = XmlNode {
                    tag,
                    text: String::new(),
                    children: Vec::new(),
                };
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(node);
                } else {
                    return Ok(node);
                }
            }
            Ok(Event::Text(t)) => {
                if let Some(parent) = stack.last_mut() {
                    parent.text.push_str(&t.unescape().map_err(|_| ())?);
                }
            }
            Ok(Event::End(_)) => {
                let node = stack.pop().ok_or(())?;
                match stack.last_mut() {
                    Some(parent) => parent.children.push(node),
                    None => return Ok(node),
                }
            }
            Ok(Event::Eof) => return Err(()),
            Ok(_) => {}
            Err(_) => return Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_error_doc() {
        let doc = Xml::new()
            .open("Error", &[("xmlns", XMLNS_S3)])
            .el("Code", "NoSuchKey")
            .close("Error")
            .finish();
        assert_eq!(
            doc,
            "<Error xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Code>NoSuchKey</Code></Error>"
        );
    }

    #[test]
    fn escaping() {
        let doc = Xml::new().el("Key", "a<b>&\"c\"").finish();
        assert_eq!(doc, "<Key>a&lt;b&gt;&amp;&quot;c&quot;</Key>");
    }

    #[test]
    fn parse_delete_body() {
        let body = r#"<Delete><Object><Key>a</Key></Object><Object><Key>b/c</Key></Object><Quiet>true</Quiet></Delete>"#;
        let root = parse(body.as_bytes()).unwrap();
        assert_eq!(root.tag, "Delete");
        let keys: Vec<String> = root
            .find_all("Key")
            .into_iter()
            .map(|n| n.text.clone())
            .collect();
        assert_eq!(keys, vec!["a", "b/c"]);
        assert_eq!(root.text_of("Quiet").as_deref(), Some("true"));
    }

    #[test]
    fn parse_complete_multipart() {
        let body = r#"<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>"aaa"</ETag></Part><Part><PartNumber>2</PartNumber><ETag>"bbb"</ETag></Part></CompleteMultipartUpload>"#;
        let root = parse(body.as_bytes()).unwrap();
        let parts: Vec<(u32, String)> = root
            .find_all("Part")
            .iter()
            .map(|p| {
                (
                    p.text_of("PartNumber").unwrap().parse().unwrap(),
                    p.text_of("ETag").unwrap().trim_matches('"').to_string(),
                )
            })
            .collect();
        assert_eq!(parts, vec![(1, "aaa".into()), (2, "bbb".into())]);
    }

    #[test]
    fn parse_malformed() {
        assert!(parse(b"<not-closed").is_err());
    }
}
