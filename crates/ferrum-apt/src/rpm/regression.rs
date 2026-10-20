#![allow(clippy::expect_used)]

use super::*;
use crate::pacman::zstd::{raw_frame, skippable_frame};
use std::io::Write;

const INDEX: &str = "9/BaseOS/x86_64/os/repodata/primary.xml.zst";

fn package(name: &str) -> String {
    format!(
        "<package type=\"rpm\"><name>{name}</name><arch>x86_64</arch>\
         <version epoch=\"0\" ver=\"1\" rel=\"2\"/>\
         <checksum type=\"sha256\">{}</checksum><size package=\"123\"/>\
         <location href=\"Packages/{name}.rpm\"/></package>",
        "a".repeat(64)
    )
}

fn document(package: &str) -> String {
    format!("<metadata xmlns=\"http://linux.duke.edu/metadata/common\">{package}</metadata>")
}

fn parse(bytes: &[u8], limits: &ParseLimits) -> Result<Vec<PackageRecord>, IndexError> {
    let mut records = Vec::new();
    parse_rpm_primary_xml(&mut Cursor::new(bytes), INDEX, limits, &mut |record| {
        records.push(record);
        Ok(())
    })?;
    Ok(records)
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(bytes).expect("encode gzip fixture");
    encoder.finish().expect("finish gzip fixture")
}

#[test]
fn primary_uses_element_boundaries_comments_and_namespaces() {
    let limits = ParseLimits::default();
    let valid = document(&package("valid").replace("</package>", "</package >"));
    let records = parse(valid.as_bytes(), &limits).expect("legal closing whitespace");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].package, "valid");

    let commented = document(&format!("<!--{}-->{}", package("fake"), package("real")));
    let records = parse(commented.as_bytes(), &limits).expect("comments are not packages");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].package, "real");
    assert!(
        parse(
            document(&format!("<!--{}-->", package("fake"))).as_bytes(),
            &limits
        )
        .expect("empty metadata is valid")
        .is_empty()
    );

    let prefixed = document(&package("prefixed"))
        .replace("xmlns=", "xmlns:m=")
        .replace("<metadata", "<m:metadata")
        .replace("</metadata", "</m:metadata");
    // Bind the default namespace separately: the prefix and default binding have
    // the same expanded name, so the package remains a direct metadata child.
    let prefixed = prefixed.replace(
        "<m:metadata ",
        "<m:metadata xmlns=\"http://linux.duke.edu/metadata/common\" ",
    );
    assert_eq!(
        parse(prefixed.as_bytes(), &limits)
            .expect("bound root prefix")
            .len(),
        1
    );

    let escaped = document(&package("name&amp;suffix"));
    let records = parse(escaped.as_bytes(), &limits).expect("predefined XML entity");
    assert_eq!(records[0].package, "name&suffix");
}

#[test]
fn primary_rejects_incomplete_misnested_and_ambiguous_documents() {
    let valid = document(&package("valid"));
    let cases = [
        valid.replace("</package>", ""),
        valid.replace("</metadata>", ""),
        valid.replace("</name>", "</arch>"),
        format!("{valid}{valid}"),
        format!("{valid}garbage"),
        format!("<wrapper>{valid}</wrapper>"),
        document(&format!("<wrapper>{}</wrapper>", package("hidden"))),
        document(&package("valid").replace("<name>", "<name xmlns=\"urn:foreign\">")),
        document(
            &package("valid")
                .replace("<name>", "<x:name>")
                .replace("</name>", "</x:name>"),
        ),
        document(&package("valid").replace("valid</name>", "bad&undefined;</name>")),
        format!("<!DOCTYPE metadata [<!ENTITY x 'value'>]>{valid}"),
    ];
    for invalid in cases {
        for bytes in [
            invalid.as_bytes().to_vec(),
            gzip(invalid.as_bytes()),
            raw_frame(invalid.as_bytes()),
        ] {
            assert!(
                parse(&bytes, &ParseLimits::default()).is_err(),
                "accepted {invalid}"
            );
        }
    }
    for field in ["name", "arch", "version", "checksum", "size", "location"] {
        let stanza = package("duplicate");
        let opening = format!("<{field}");
        let start = stanza.find(&opening).expect("fixture field");
        let end = if matches!(field, "version" | "size" | "location") {
            start + stanza[start..].find("/>").expect("empty field end") + 2
        } else {
            let closing = format!("</{field}>");
            start + stanza[start..].find(&closing).expect("field end") + closing.len()
        };
        let duplicate = stanza.replace("</package>", &format!("{}</package>", &stanza[start..end]));
        assert!(
            parse(document(&duplicate).as_bytes(), &ParseLimits::default()).is_err(),
            "accepted duplicate {field}"
        );
    }
    let duplicate_attribute =
        document(&package("valid").replace("package=\"123\"", "package=\"123\" package=\"456\""));
    assert!(parse(duplicate_attribute.as_bytes(), &ParseLimits::default()).is_err());
    let expanded_duplicate = document(&package("valid").replace(
        "package=\"123\"",
        "package=\"123\" xmlns:a=\"urn:attrs\" xmlns:b=\"urn:attrs\" a:x=\"1\" b:x=\"2\"",
    ));
    assert!(parse(expanded_duplicate.as_bytes(), &ParseLimits::default()).is_err());
}

#[test]
fn primary_decodes_every_zstd_frame_and_checks_the_final_frame() {
    let first = format!("<metadata>{}", package("first"));
    let second = format!("{}</metadata>", package("second"));
    let mut bytes = skippable_frame(b"before");
    bytes.extend(raw_frame(first.as_bytes()));
    bytes.extend(skippable_frame(b"between"));
    bytes.extend(raw_frame(second.as_bytes()));
    bytes.extend(skippable_frame(b"after"));
    let records = parse(&bytes, &ParseLimits::default()).expect("concatenated Zstandard frames");
    assert_eq!(
        records
            .iter()
            .map(|record| record.package.as_str())
            .collect::<Vec<_>>(),
        ["first", "second"]
    );
    for removed in [1, 4, 12] {
        assert!(parse(&bytes[..bytes.len() - removed], &ParseLimits::default()).is_err());
    }
    bytes.extend_from_slice(b"not another frame");
    assert!(parse(&bytes, &ParseLimits::default()).is_err());
}

#[test]
fn primary_checks_all_compression_trailers_and_stanza_bounds() {
    let xml = document(&package("valid"));
    let mut xz = xz2::write::XzEncoder::new(Vec::new(), 1);
    xz.write_all(xml.as_bytes()).expect("encode xz");
    let mut bz = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
    bz.write_all(xml.as_bytes()).expect("encode bzip2");
    for bytes in [
        gzip(xml.as_bytes()),
        raw_frame(xml.as_bytes()),
        xz.finish().expect("finish xz"),
        bz.finish().expect("finish bzip2"),
    ] {
        assert_eq!(
            parse(&bytes, &ParseLimits::default())
                .expect("valid compression")
                .len(),
            1
        );
        assert!(parse(&bytes[..bytes.len() - 1], &ParseLimits::default()).is_err());
    }
    let limits = ParseLimits {
        max_stanza: 128,
        ..ParseLimits::default()
    };
    assert!(parse(xml.as_bytes(), &limits).is_err());
    let limits = ParseLimits {
        max_line: 32,
        ..ParseLimits::default()
    };
    assert!(parse(xml.as_bytes(), &limits).is_err());
    let excessive_depth = document(&format!(
        "{}{}{}",
        "<x>".repeat(65),
        package("deep"),
        "</x>".repeat(65)
    ));
    assert!(parse(excessive_depth.as_bytes(), &ParseLimits::default()).is_err());
    let namespaces = (0..33)
        .map(|number| format!(" xmlns:n{number}=\"urn:{number}\""))
        .collect::<String>();
    let excessive_namespaces = format!("<metadata{namespaces}/>");
    assert!(parse(excessive_namespaces.as_bytes(), &ParseLimits::default()).is_err());
}

fn repomd() -> String {
    format!(
        "<repomd xmlns=\"http://linux.duke.edu/metadata/repo\"><data type=\"primary\">\
        <checksum type=\"sha256\">{}</checksum><location href=\"repodata/primary.xml.gz\"/>\
        <size>123</size><timestamp>123456</timestamp></data></repomd>",
        "a".repeat(64)
    )
}

#[test]
fn repomd_requires_a_complete_structured_unambiguous_document() {
    let parse = |xml: &str| {
        parse_repomd_xml(
            xml.as_bytes(),
            "9/BaseOS/x86_64/os",
            &ParseLimits::default(),
        )
    };
    let valid = repomd();
    assert_eq!(
        parse(&valid.replace("</data>", "</data >"))
            .expect("legal whitespace")
            .data
            .len(),
        1
    );
    let comment = valid.replace(
        "<data type=\"primary\">",
        "<!--<data type=\"primary\">fake</data>--><data type=\"primary\">",
    );
    assert_eq!(parse(&comment).expect("comment ignored").data.len(), 1);
    for invalid in [
        valid.replace("</repomd>", ""),
        valid.replace("</data>", ""),
        valid.replace("</size>", "</timestamp>"),
        format!("<wrapper>{valid}</wrapper>"),
        format!("{valid}{valid}"),
        valid.replace("<size>123</size>", "<size>123</size><size>456</size>"),
        valid.replace("<timestamp>123456</timestamp>", "<timestamp>1</timestamp><timestamp>2</timestamp>"),
        valid.replace("</checksum>", &format!("</checksum><checksum type=\"sha256\">{}</checksum>", "b".repeat(64))),
        valid.replace("<location href=\"repodata/primary.xml.gz\"/>", "<location href=\"repodata/primary.xml.gz\"/><location href=\"repodata/other-primary.xml.gz\"/>"),
        valid.replace("<data ", "<wrapper><data ").replace("</data>", "</data></wrapper>"),
        valid.replace("<checksum ", "<checksum xmlns=\"urn:foreign\" "),
    ] {
        assert!(parse(&invalid).is_err(), "accepted {invalid}");
    }
}
