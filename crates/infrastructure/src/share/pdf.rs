//! Branded visitor-pass PDF card: org name, visitor name, pass number, its
//! QR payload rendered as an actual scannable QR code, and the validity
//! window.
//!
//! Not a `ShareChannel` -- a PDF is a document to download/attach, not a
//! delivery channel. Direct `printpdf::Op` drawing calls only (no
//! templating engine): the QR code is drawn as plain filled rectangles (one
//! per dark module) rather than rasterized to an image and embedded, so
//! this needs no image-decoding feature/dependency at all. Text uses one of
//! printpdf's built-in base-14 fonts (`BuiltinFont::Helvetica*`/`Courier`)
//! rather than an embedded font file, so nothing needs to be bundled with
//! the binary or ship as a compile-time asset.

use chrono::{DateTime, Utc};
use printpdf::*;
use qrcode::{Color as QrModuleColor, QrCode};
use visitorpass_domain::DomainError;

const CARD_W_MM: f32 = 100.0;
const CARD_H_MM: f32 = 150.0;
const MARGIN_MM: f32 = 8.0;
const HEADER_H_MM: f32 = 26.0;
const QR_BOX_MM: f32 = 55.0;
const QR_QUIET_ZONE_MODULES: usize = 4;

const BRAND_NAVY: (f32, f32, f32) = (0.11, 0.25, 0.53);
const BRAND_NAVY_LIGHT: (f32, f32, f32) = (0.85, 0.89, 0.97);
const LABEL_GREY: (f32, f32, f32) = (0.45, 0.45, 0.45);
const INK: (f32, f32, f32) = (0.05, 0.05, 0.05);
const WHITE: (f32, f32, f32) = (1.0, 1.0, 1.0);
const BLACK: (f32, f32, f32) = (0.0, 0.0, 0.0);

fn rgb((r, g, b): (f32, f32, f32)) -> Color {
    Color::Rgb(Rgb::new(r, g, b, None))
}

/// Truncates to at most `max` characters (by Unicode scalar, good enough
/// for a fixed-width card label), appending an ellipsis when cut. This is
/// the extent of "layout" here on purpose -- true text measurement would
/// need font-metrics plumbing this v1 deliberately skips.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut t: String = s.chars().take(max.saturating_sub(1)).collect();
    t.push('…');
    t
}

fn fill_rect_mm(ops: &mut Vec<Op>, x: f32, y: f32, w: f32, h: f32, color: (f32, f32, f32)) {
    ops.push(Op::SetFillColor { col: rgb(color) });
    ops.push(Op::DrawPolygon {
        polygon: Rect::from_xywh(Mm(x).into(), Mm(y).into(), Mm(w).into(), Mm(h).into()).to_polygon(),
    });
}

/// One self-contained text run. Each call brackets its own
/// `StartTextSection`/`EndTextSection` pair: `BT` resets the PDF text
/// matrix to identity, which is what makes `SetTextCursor`'s `Td` operator
/// (a *relative* move) behave as an absolute `(x, y)` position here --
/// without a fresh `BT` per line, successive `Td` calls would accumulate
/// instead of each placing text at the given card coordinate.
fn text_line(ops: &mut Vec<Op>, x: f32, y: f32, text: &str, font: BuiltinFont, size_pt: f32, color: (f32, f32, f32)) {
    ops.push(Op::StartTextSection);
    ops.push(Op::SetFillColor { col: rgb(color) });
    ops.push(Op::SetFont { font: PdfFontHandle::Builtin(font), size: Pt(size_pt) });
    ops.push(Op::SetTextCursor { pos: Point::new(Mm(x), Mm(y)) });
    ops.push(Op::ShowText { items: vec![TextItem::Text(text.to_string())] });
    ops.push(Op::EndTextSection);
}

/// Draws `qr` module-by-module as filled black squares inside a
/// `box_size`-mm square whose lower-left corner is `(box_x, box_y)`,
/// including the crate-omitted quiet zone (`QrCode::width()` excludes it,
/// but scanners rely on it being present).
fn draw_qr(ops: &mut Vec<Op>, qr: &QrCode, box_x: f32, box_y: f32, box_size: f32) {
    let modules = qr.width();
    let total_modules = modules + QR_QUIET_ZONE_MODULES * 2;
    let cell = box_size / total_modules as f32;

    // White backing (quiet zone + contrast base) behind the dark modules.
    fill_rect_mm(ops, box_x, box_y, box_size, box_size, WHITE);

    let colors = qr.to_colors();
    ops.push(Op::SetFillColor { col: rgb(BLACK) });
    for qy in 0..modules {
        for qx in 0..modules {
            // `to_colors()` is row-major top-to-bottom (matches `QrCode`'s
            // `Index<(x, y)>`); PDF's y axis increases upward, so row 0
            // (the QR's top row) must land at the highest y.
            if colors[qy * modules + qx] == QrModuleColor::Dark {
                let row_from_bottom = modules - 1 - qy;
                let x = box_x + (QR_QUIET_ZONE_MODULES + qx) as f32 * cell;
                let y = box_y + (QR_QUIET_ZONE_MODULES + row_from_bottom) as f32 * cell;
                ops.push(Op::DrawPolygon {
                    polygon: Rect::from_xywh(Mm(x).into(), Mm(y).into(), Mm(cell).into(), Mm(cell).into())
                        .to_polygon(),
                });
            }
        }
    }
}

/// Generates a simple branded pass card as PDF bytes: org name, visitor
/// name, pass number, a scannable QR code of `qr_payload`, and the
/// validity window. Fixed single-page, fixed layout (100mm x 150mm) -- no
/// templating, no pagination.
pub fn generate_pass_pdf(
    org_name: &str,
    visitor_name: &str,
    pass_number: &str,
    qr_payload: &str,
    valid_from: DateTime<Utc>,
    valid_until: DateTime<Utc>,
) -> Result<Vec<u8>, DomainError> {
    let qr = QrCode::new(qr_payload.as_bytes())
        .map_err(|e| DomainError::ExternalServiceError(format!("QR encode failed: {e}")))?;

    let mut ops: Vec<Op> = Vec::new();

    // ── Header band ──────────────────────────────────────────────────────
    fill_rect_mm(&mut ops, 0.0, CARD_H_MM - HEADER_H_MM, CARD_W_MM, HEADER_H_MM, BRAND_NAVY);
    text_line(&mut ops, MARGIN_MM, CARD_H_MM - 12.0, &truncate(org_name, 28), BuiltinFont::HelveticaBold, 15.0, WHITE);
    text_line(&mut ops, MARGIN_MM, CARD_H_MM - 20.0, "VISITOR PASS", BuiltinFont::Helvetica, 9.0, BRAND_NAVY_LIGHT);

    // ── Body: labeled fields ─────────────────────────────────────────────
    let mut y = CARD_H_MM - HEADER_H_MM - 14.0;

    text_line(&mut ops, MARGIN_MM, y, "VISITOR", BuiltinFont::Helvetica, 8.0, LABEL_GREY);
    y -= 6.5;
    text_line(&mut ops, MARGIN_MM, y, &truncate(visitor_name, 32), BuiltinFont::HelveticaBold, 14.0, INK);
    y -= 11.0;

    text_line(&mut ops, MARGIN_MM, y, "PASS NUMBER", BuiltinFont::Helvetica, 8.0, LABEL_GREY);
    y -= 6.5;
    text_line(&mut ops, MARGIN_MM, y, pass_number, BuiltinFont::Courier, 13.0, INK);
    y -= 11.0;

    text_line(&mut ops, MARGIN_MM, y, "VALID", BuiltinFont::Helvetica, 8.0, LABEL_GREY);
    y -= 6.5;
    let validity = format!(
        "{} - {}",
        valid_from.format("%d %b %Y %H:%M"),
        valid_until.format("%d %b %Y %H:%M UTC"),
    );
    text_line(&mut ops, MARGIN_MM, y, &validity, BuiltinFont::Helvetica, 10.0, INK);

    // ── QR code, centered near the bottom ────────────────────────────────
    let qr_x = (CARD_W_MM - QR_BOX_MM) / 2.0;
    let qr_y = MARGIN_MM;
    draw_qr(&mut ops, &qr, qr_x, qr_y, QR_BOX_MM);

    let page = PdfPage::new(Mm(CARD_W_MM), Mm(CARD_H_MM), ops);
    let mut doc = PdfDocument::new("VisitorPass Share Card");
    let mut warnings = Vec::new();
    let bytes = doc.with_pages(vec![page]).save(&PdfSaveOptions::default(), &mut warnings);

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone};

    use super::*;

    fn sample_pdf() -> Vec<u8> {
        generate_pass_pdf(
            "Skyline Towers",
            "Asha Verma",
            "VP-DEADBEEF",
            "vp1.some-signed-payload-blob-not-real-cbor",
            Utc.with_ymd_and_hms(2026, 7, 16, 9, 0, 0).unwrap(),
            Utc.with_ymd_and_hms(2026, 7, 16, 18, 0, 0).unwrap(),
        )
        .expect("pdf generation must succeed for a normal short payload")
    }

    #[test]
    fn produces_a_valid_nonempty_pdf_with_magic_bytes() {
        let bytes = sample_pdf();
        assert!(!bytes.is_empty());
        assert!(
            bytes.starts_with(b"%PDF-"),
            "generated PDF must start with the %PDF- magic bytes"
        );
    }

    #[test]
    fn pass_number_and_card_details_are_recoverable_from_the_pdf_content_stream() {
        let bytes = sample_pdf();

        // Deliberately independent of printpdf's own `extract_text()` (which
        // has a real gap for builtin/non-embedded fonts after a parse
        // round-trip -- see the doc comment on `generate_pass_pdf`). Instead,
        // parse with `lopdf` directly and pull the *decompressed* page
        // content stream: proving the pass number survives real PDF
        // structure (xref table, object streams, FlateDecode) and appears as
        // an actual text-showing operator's string operand, not just
        // somewhere in the raw file bytes by coincidence.
        let doc = lopdf::Document::load_mem(&bytes).expect("lopdf must be able to parse the generated PDF");
        let (_, page_id) = doc.get_pages().into_iter().next().expect("generated PDF must have one page");
        let content = doc.get_page_content(page_id);
        let content_text = String::from_utf8_lossy(&content);

        assert!(
            content_text.contains("VP-DEADBEEF"),
            "pass number must appear as literal text in the content stream, got: {content_text:?}"
        );
        assert!(
            content_text.contains("Asha Verma"),
            "visitor name must appear as literal text in the content stream, got: {content_text:?}"
        );
        assert!(
            content_text.contains("Skyline Towers"),
            "org name must appear as literal text in the content stream, got: {content_text:?}"
        );
    }

    #[test]
    fn handles_long_and_accented_names_without_failing() {
        let bytes = generate_pass_pdf(
            "Société Générale Résidences & Co.",
            "O'Connor-Müller, José Antonio Third-Name-Here",
            "VP-ABCDEF12",
            "vp1.payload",
            Utc::now(),
            Utc::now() + Duration::hours(4),
        )
        .expect("long/accented names must not fail generation");
        assert!(bytes.starts_with(b"%PDF-"));
    }

    #[test]
    fn rejects_a_qr_payload_that_cannot_be_encoded_rather_than_panicking() {
        // Larger than a QR code can hold at any version/error-correction
        // level -- must surface as a DomainError, not panic.
        let huge_payload = "x".repeat(10_000);
        let result = generate_pass_pdf(
            "Org",
            "Visitor",
            "VP-00000000",
            &huge_payload,
            Utc::now(),
            Utc::now() + Duration::hours(1),
        );
        assert!(matches!(result, Err(DomainError::ExternalServiceError(_))));
    }
}
