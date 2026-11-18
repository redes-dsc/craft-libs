//! Legacy Vietnamese 8-bit encoding detection and transcoding to Unicode NFC.
//!
//! # Source Attribution & Standard References
//! The character mapping tables and heuristic classification logic in this module
//! are based on published public domain conventions, national standards, and
//! cross-verified open-source reference implementations:
//!
//! 1. **TCVN3 (ABC) Encoding:**
//!    - **TCVN 5712:1993**: *Information technology – 8-bit coded character set for Vietnamese*.
//!      Standardized by the Directorate for Standards, Metrology and Quality (STAMEQ),
//!      Ministry of Science, Technology and Environment of Vietnam (1993).
//!    - Variant implementation: TCVN 5712-3 (commonly known as TCVN3 / ABC lower & upper font pairs).
//!    - Cross-verified with GNU C Library (`glibc`) official charmap specification:
//!      `localedata/charmaps/TCVN5712-1`.
//!
//! 2. **VNI-Windows Encoding (2-byte composite & single-byte):**
//!    - **De facto Industry Convention**: Established by VNI Software Company
//!      (founded by Hồ Thành Việt, c. 1991–1995) for Vietnamese typography on Microsoft
//!      Windows 3.x/95 and Autodesk AutoCAD in Vietnam.
//!    - Encoding characteristics: Pairing base ASCII Latin vowels with high-byte (0x80..=0xFF)
//!      Latin-1 accent codes, with specific single-byte assignments for complex composite vowels.
//!    - Cross-verified with established open-source reference implementations:
//!      - UniKey core engine (`vnconv` / `vni.tab`) by Phạm Kim Long.
//!      - CPAN standard encoding tables (`Encode::Vietnamese` / `Encode::VN::VNI`).
//!
//! # Target Representation
//! All transcoding pipelines in this module deterministically emit standard
//! precomposed Unicode (NFC), adhering to Vietnamese National Standard TCVN 6909:2001
//! (*Information technology – 16-bit Vietnamese coded character set*).

use std::borrow::Cow;

pub mod detect;
pub mod tcvn3;
pub mod vni;
pub mod windows1258;

#[cfg(test)]
mod tests;

pub use detect::{
    DetectionResult, EncodingEvidence, EncodingMetadata, detect_encoding, detect_encoding_from_str, detect_vietnamese_encoding,
    is_already_unicode_vietnamese, is_vietnamese_font,
};
pub use tcvn3::{WINDOWS_1252_PUNCTUATION, decode_tcvn3, transcode_tcvn3, transcode_tcvn3_h};
pub use vni::{VniDecoder, decode_vni, transcode_vni};
pub use windows1258::{decode_windows1258, transcode_windows1258};

/// Decoding mode: Strict specification adherence vs Practical real-world legacy document ingestion.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DecodeMode {
    /// Strict specification mode: only canonical standard bytes are mapped.
    /// Unofficial byte positions (such as CP1252 punctuation in TCVN3/VNI) return `DecodeError::UnmappedByte`.
    Strict,
    /// Practical mode (default): enables CP1252 punctuation fallback (0x80..=0x9F), VNI CapsLock handling,
    /// and standalone/orphan diacritic fallback to preserve real-world legacy documents (Word, Excel, AutoCAD).
    #[default]
    Practical,
}

/// Detected or specified legacy Vietnamese encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LegacyEncoding {
    /// TCVN3 (ABC) single-byte lowercase / composite uppercase encoding.
    Tcvn3,
    /// TCVN3H all-uppercase font encoding (where lowercase byte slots display capital letters).
    Tcvn3H,
    /// VNI Windows composite and extended byte encoding.
    Vni,
    /// Windows-1258 (CP1258) Vietnamese code page with combining diacritics.
    Windows1258,
}

/// Backwards-compatible alias matching CADCraft's `VietnameseEncoding`.
pub type VietnameseEncoding = LegacyEncoding;

impl LegacyEncoding {
    /// Returns a human-readable display name for logs, status bars, and audit summaries.
    pub const fn display_name(&self) -> &'static str {
        match self {
            Self::Tcvn3 => "TCVN3 (ABC)",
            Self::Tcvn3H => "TCVN3 All-Caps",
            Self::Vni => "VNI-Windows",
            Self::Windows1258 => "Windows-1258",
        }
    }
}

/// Errors that can occur during 8-bit legacy decoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// Invalid UTF-8 sequence encountered at byte offset.
    InvalidUtf8 {
        /// Byte offset in the input where invalid UTF-8 sequence begins.
        offset: usize,
    },
    /// Unmapped byte in legacy encoding table encountered at byte offset.
    UnmappedByte {
        /// Raw byte value that could not be mapped.
        byte: u8,
        /// Byte offset in the input where unmapped byte occurred.
        offset: usize,
        /// Legacy encoding table being used for decoding.
        encoding: LegacyEncoding,
    },
    /// Malformed composite byte sequence encountered at byte offset.
    MalformedSequence {
        /// Byte offset where malformed composite sequence began.
        offset: usize,
        /// Legacy encoding table being used for decoding.
        encoding: LegacyEncoding,
    },
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidUtf8 { offset } => {
                write!(f, "invalid UTF-8 byte sequence encountered at byte offset {offset}")
            }
            Self::UnmappedByte { byte, offset, encoding } => {
                write!(f, "unmapped byte 0x{byte:02X} encountered at byte offset {offset} for encoding {:?}", encoding)
            }
            Self::MalformedSequence { offset, encoding } => {
                write!(f, "malformed composite byte sequence encountered at byte offset {offset} for encoding {:?}", encoding)
            }
        }
    }
}

impl std::error::Error for DecodeError {}

/// Result of a transcoding operation, preserving whether the text was modified and which encoding was used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TranscodeResult<'a> {
    /// Transcoded or original text.
    pub text: Cow<'a, str>,
    /// Matched or detected legacy encoding, if any.
    pub encoding: Option<LegacyEncoding>,
    /// Whether transcoding actually modified the input text.
    pub was_transcoded: bool,
}

/// Return the first candidate in `candidates` (e.g. `&[&style.font, &style.name]`)
/// that matches a recognized legacy font naming pattern.
pub fn font_hint<'a>(candidates: &[&'a str]) -> Option<&'a str> {
    for &c in candidates {
        let trimmed = c.trim();
        if !trimmed.is_empty() && is_vietnamese_font(trimmed).is_some() {
            return Some(c);
        }
    }
    None
}

/// Heuristic detection or font hint inspection for legacy Vietnamese text.
#[inline]
pub fn detect_legacy_encoding(text: &str, font_hint: Option<&str>) -> Option<LegacyEncoding> {
    font_hint.and_then(is_vietnamese_font).or_else(|| detect_vietnamese_encoding(text))
}

/// Return true if `text` contains legacy-encoded characters that would be transcoded under `font_hint`.
#[inline]
pub fn is_legacy_text(text: &str, font_hint: Option<&str>) -> bool {
    transcode_vietnamese(text, font_hint) != text
}

/// Return a human-readable summary of the matched legacy encoding family.
pub fn transcode_summary(hint: Option<&str>) -> &'static str {
    match hint.and_then(is_vietnamese_font) {
        Some(LegacyEncoding::Vni) => "VNI Windows",
        Some(LegacyEncoding::Tcvn3 | LegacyEncoding::Tcvn3H) => "TCVN3",
        Some(LegacyEncoding::Windows1258) => "Windows-1258",
        None => "legacy 8-bit",
    }
}

#[inline]
fn transcode_str_inner<'a>(s: &'a str, font_hint: Option<&str>) -> TranscodeResult<'a> {
    let Some(encoding) = detect_legacy_encoding(s, font_hint) else {
        return TranscodeResult { text: Cow::Borrowed(s), encoding: None, was_transcoded: false };
    };

    let bypass_unicode_guard = match encoding {
        LegacyEncoding::Tcvn3 => tcvn3::should_bypass_unicode_guard_for_tcvn3(s, false),
        LegacyEncoding::Tcvn3H => tcvn3::should_bypass_unicode_guard_for_tcvn3(s, true),
        LegacyEncoding::Vni | LegacyEncoding::Windows1258 => false,
    };
    if (s.is_ascii() && encoding != LegacyEncoding::Tcvn3H) || (!bypass_unicode_guard && is_already_unicode_vietnamese(s)) {
        return TranscodeResult { text: Cow::Borrowed(s), encoding: Some(encoding), was_transcoded: false };
    }

    let text = match encoding {
        LegacyEncoding::Tcvn3 => transcode_tcvn3(s),
        LegacyEncoding::Tcvn3H => transcode_tcvn3_h(s),
        LegacyEncoding::Vni => transcode_vni(s),
        LegacyEncoding::Windows1258 => transcode_windows1258(s),
    };

    let was_transcoded = matches!(&text, Cow::Owned(_)) || (text.as_ref() != s);
    TranscodeResult { text, encoding: Some(encoding), was_transcoded }
}

/// Transcode legacy 8-bit Vietnamese text to Unicode NFC using an optional font hint or detection heuristics.
///
/// `font_hint` is advisory evidence: if `s` is already recognized as Unicode Vietnamese (without
/// unambiguous legacy markers), `s` is preserved unchanged; callers that know the exact source
/// encoding should call [`transcode_explicit`] instead.
///
/// Returns `Cow::Borrowed(s)` with zero allocations when `s` is unchanged (including pure ASCII
/// for non-`Tcvn3H` hints; a `Tcvn3H` hint allocates `Cow::Owned` when uppercasing lowercase ASCII).
pub fn transcode_vietnamese<'a>(s: &'a str, font_hint: Option<&str>) -> Cow<'a, str> {
    transcode_str_inner(s, font_hint).text
}

/// Drop-in alias for [`transcode_vietnamese`] matching downstream caller conventions.
pub use transcode_vietnamese as transcode;

/// Pure decoding primitive: maps bytes strictly to Unicode codepoints without hidden normalization.
///
/// Uses [`DecodeMode::Practical`] by default to preserve typography and diacritics in legacy documents.
pub fn decode(input: &[u8], encoding: LegacyEncoding) -> Result<Cow<'_, str>, DecodeError> {
    decode_with_mode(input, encoding, DecodeMode::Practical)
}

/// Pure decoding primitive with explicit [`DecodeMode`] selection.
pub fn decode_with_mode(input: &[u8], encoding: LegacyEncoding, mode: DecodeMode) -> Result<Cow<'_, str>, DecodeError> {
    match encoding {
        LegacyEncoding::Windows1258 => decode_windows1258(input),
        LegacyEncoding::Tcvn3 => decode_tcvn3(input, false, mode),
        LegacyEncoding::Tcvn3H => decode_tcvn3(input, true, mode),
        LegacyEncoding::Vni => decode_vni(input, mode),
    }
}

/// Configuration options for the [`decode_text`] composite facade.
#[derive(Clone, Copy, Debug)]
pub struct DecodeOptions<'a> {
    /// Explicitly forced encoding, bypassing heuristic detection.
    pub force_encoding: Option<LegacyEncoding>,
    /// Metadata hints (e.g. font name, codepage) from document containers.
    pub metadata: Option<&'a EncodingMetadata<'a>>,
    /// Whether to canonically compose the output into Unicode NFC (default: true).
    pub normalize_nfc: bool,
    /// Decoding mode: Strict specification vs Practical legacy tolerance (default: Practical).
    pub mode: DecodeMode,
}

impl Default for DecodeOptions<'_> {
    fn default() -> Self {
        Self { force_encoding: None, metadata: None, normalize_nfc: true, mode: DecodeMode::Practical }
    }
}

/// Unified decoding facade combining detection, decoding, and canonical NFC normalization.
///
/// Invariants:
/// - If `force_encoding` is `None` and `input` is valid UTF-8, heuristic transcoding is never executed.
/// - If `normalize_nfc` is true, output is guaranteed canonical Unicode Normalization Form C.
/// - Returns `Cow::Borrowed` with zero allocations on pure ASCII or already-canonical UTF-8 inputs.
pub fn decode_text<'a>(input: &'a [u8], options: &DecodeOptions<'a>) -> Result<Cow<'a, str>, DecodeError> {
    // 1. Explicit forced encoding
    if let Some(enc) = options.force_encoding {
        let decoded = decode_with_mode(input, enc, options.mode)?;
        if options.normalize_nfc {
            return Ok(apply_nfc_cow_for(decoded, enc));
        }
        return Ok(decoded);
    }

    // 2. Fast path: check valid UTF-8
    // Genuine UTF-8: never apply heuristic or metadata legacy decoding to valid UTF-8
    // when force_encoding is None. This preserves modern UTF-8 text from accidental corruption.
    if let Ok(s) = std::str::from_utf8(input) {
        if options.normalize_nfc {
            return Ok(normalize_nfc(s));
        }
        return Ok(Cow::Borrowed(s));
    }

    // 3. Non-UTF8 bytes: detect encoding via content heuristics or metadata
    let detection = detect_encoding(input, options.metadata);
    if let Some(enc) = detection.encoding() {
        let decoded = decode_with_mode(input, enc, options.mode)?;
        if options.normalize_nfc {
            return Ok(apply_nfc_cow_for(decoded, enc));
        }
        return Ok(decoded);
    }

    // 4. Neither valid UTF-8 nor a recognized Vietnamese legacy encoding
    let valid_up_to = match std::str::from_utf8(input) {
        Ok(_) => 0,
        Err(e) => e.valid_up_to(),
    };
    Err(DecodeError::InvalidUtf8 { offset: valid_up_to })
}

/// Canonical Unicode Normalization Form C (NFC) helper preserving borrowed Cow where possible.
#[inline]
fn apply_nfc_cow_with<'a>(cow: Cow<'a, str>, normalizer: fn(&str) -> Cow<'_, str>) -> Cow<'a, str> {
    match cow {
        Cow::Borrowed(b) => match normalizer(b) {
            Cow::Borrowed(_) => Cow::Borrowed(b),
            Cow::Owned(composed) => Cow::Owned(composed),
        },
        Cow::Owned(o) => match normalizer(&o) {
            Cow::Borrowed(_) => Cow::Owned(o),
            Cow::Owned(composed) => Cow::Owned(composed),
        },
    }
}

#[inline]
pub(crate) fn apply_cp1258_nfc_cow<'a>(cow: Cow<'a, str>) -> Cow<'a, str> {
    apply_nfc_cow_with(cow, normalize_cp1258_nfc)
}

#[inline]
fn apply_nfc_cow_for<'a>(cow: Cow<'a, str>, enc: LegacyEncoding) -> Cow<'a, str> {
    match enc {
        LegacyEncoding::Windows1258 => apply_cp1258_nfc_cow(cow),
        _ => apply_nfc_cow_with(cow, normalize_nfc),
    }
}

/// Transcode using an explicitly known encoding, skipping heuristic detection.
///
/// Use this in `pdfcraft` or strict pipelines when metadata (such as a known PDF font name)
/// guarantees the encoding, eliminating heuristic detection false positives.
pub fn transcode_explicit<'a>(text: &'a str, encoding: LegacyEncoding) -> Cow<'a, str> {
    let mut bytes = Vec::with_capacity(text.len());
    for ch in text.chars() {
        let code = ch as u32;
        if code > 0xFF {
            return Cow::Borrowed(text);
        }
        bytes.push(code as u8);
    }

    match decode_with_mode(&bytes, encoding, DecodeMode::Practical) {
        Ok(decoded) => {
            let nfc = normalize_nfc(&decoded);
            if nfc.as_ref() == text { Cow::Borrowed(text) } else { Cow::Owned(nfc.into_owned()) }
        }
        Err(_) => Cow::Borrowed(text),
    }
}

/// Transcode legacy text to Unicode NFC and return detailed status.
pub fn transcode_to_unicode<'a>(s: &'a str, font_hint: Option<&str>) -> TranscodeResult<'a> {
    transcode_str_inner(s, font_hint)
}

/// One-shot transcode facade returning a tuple for lightweight callers.
///
/// Returns `(normalized_text, detected_encoding_if_any)`.
#[inline]
pub fn transcode_with_summary<'a>(text: &'a str, font_hint: Option<&str>) -> (Cow<'a, str>, Option<LegacyEncoding>) {
    let result = transcode_to_unicode(text, font_hint);
    (result.text, result.encoding)
}

/// Strict normalization and validation. Returns `Err` with the detected encoding display name
/// if a legacy Vietnamese encoding is detected in the text, preventing silent data corruption.
/// Returns `Ok` with the NFC-normalized text when no legacy encoding is detected. This does not
/// confirm that the text is Unicode. Legacy text that detection does not match, such as `B¶n`, is returned as `Ok`.
///
/// Use this in `pdfcraft` or strict pipelines to reject text that contains a detected legacy encoding.
pub fn validate_and_normalize(text: &str) -> Result<Cow<'_, str>, &'static str> {
    if let Some(enc) = detect_legacy_encoding(text, None) {
        return Err(enc.display_name());
    }
    Ok(normalize_nfc(text))
}

/// Check whether a legacy font name suggests a Serif typeface (vs Sans-Serif).
#[inline]
pub fn is_serif_legacy_font(font: &str) -> bool {
    let lower = font.trim().to_ascii_lowercase();
    lower.contains("time")
        || lower.contains("century")
        || lower.contains("roman")
        || lower.contains("book")
        || lower.contains("cambria")
        || lower.contains("palatin")
}

#[inline]
const fn is_vietnamese_combining_mark(c: char) -> bool {
    matches!(c, '\u{0300}' | '\u{0301}' | '\u{0302}' | '\u{0303}' | '\u{0306}' | '\u{0309}' | '\u{031B}' | '\u{0323}')
}

/// Zero-dependency canonical pair composition for Vietnamese vowels and combining diacritics.
///
/// Covers all 132 precomposed Vietnamese vowel+diacritic combinations (structural marks
/// `\u{0302}`, `\u{0306}`, `\u{031B}` and tone marks `\u{0300}`, `\u{0301}`, `\u{0309}`,
/// `\u{0303}`, `\u{0323}`), including both CP1258 sequences and NFD canonical ordering
/// (where `U+0323` dot-below precedes circumflex/breve).
#[inline]
pub const fn compose_vietnamese_pair(base: char, mark: char) -> Option<char> {
    Some(match (base, mark) {
        // Structural marks (circumflex, breve, horn)
        ('a', '\u{0302}') => 'â',
        ('A', '\u{0302}') => 'Â',
        ('a', '\u{0306}') => 'ă',
        ('A', '\u{0306}') => 'Ă',
        ('e', '\u{0302}') => 'ê',
        ('E', '\u{0302}') => 'Ê',
        ('o', '\u{0302}') => 'ô',
        ('O', '\u{0302}') => 'Ô',
        ('o', '\u{031B}') => 'ơ',
        ('O', '\u{031B}') => 'Ơ',
        ('u', '\u{031B}') => 'ư',
        ('U', '\u{031B}') => 'Ư',
        // NFD canonical order: dot-below (ccc=220) before circumflex/breve/horn (ccc=230)
        ('ạ', '\u{0302}') => 'ậ',
        ('Ạ', '\u{0302}') => 'Ậ',
        ('ạ', '\u{0306}') => 'ặ',
        ('Ạ', '\u{0306}') => 'Ặ',
        ('ẹ', '\u{0302}') => 'ệ',
        ('Ẹ', '\u{0302}') => 'Ệ',
        ('ọ', '\u{0302}') => 'ộ',
        ('Ọ', '\u{0302}') => 'Ộ',
        ('ọ', '\u{031B}') => 'ợ',
        ('Ọ', '\u{031B}') => 'Ợ',
        ('ụ', '\u{031B}') => 'ự',
        ('Ụ', '\u{031B}') => 'Ự',
        // a / A
        ('a', '\u{0300}') => 'à',
        ('a', '\u{0301}') => 'á',
        ('a', '\u{0309}') => 'ả',
        ('a', '\u{0303}') => 'ã',
        ('a', '\u{0323}') => 'ạ',
        ('A', '\u{0300}') => 'À',
        ('A', '\u{0301}') => 'Á',
        ('A', '\u{0309}') => 'Ả',
        ('A', '\u{0303}') => 'Ã',
        ('A', '\u{0323}') => 'Ạ',
        // ă / Ă
        ('ă', '\u{0300}') => 'ằ',
        ('ă', '\u{0301}') => 'ắ',
        ('ă', '\u{0309}') => 'ẳ',
        ('ă', '\u{0303}') => 'ẵ',
        ('ă', '\u{0323}') => 'ặ',
        ('Ă', '\u{0300}') => 'Ằ',
        ('Ă', '\u{0301}') => 'Ắ',
        ('Ă', '\u{0309}') => 'Ẳ',
        ('Ă', '\u{0303}') => 'Ẵ',
        ('Ă', '\u{0323}') => 'Ặ',
        // â / Â
        ('â', '\u{0300}') => 'ầ',
        ('â', '\u{0301}') => 'ấ',
        ('â', '\u{0309}') => 'ẩ',
        ('â', '\u{0303}') => 'ẫ',
        ('â', '\u{0323}') => 'ậ',
        ('Â', '\u{0300}') => 'Ầ',
        ('Â', '\u{0301}') => 'Ấ',
        ('Â', '\u{0309}') => 'Ẩ',
        ('Â', '\u{0303}') => 'Ẫ',
        ('Â', '\u{0323}') => 'Ậ',
        // e / E
        ('e', '\u{0300}') => 'è',
        ('e', '\u{0301}') => 'é',
        ('e', '\u{0309}') => 'ẻ',
        ('e', '\u{0303}') => 'ẽ',
        ('e', '\u{0323}') => 'ẹ',
        ('E', '\u{0300}') => 'È',
        ('E', '\u{0301}') => 'É',
        ('E', '\u{0309}') => 'Ẻ',
        ('E', '\u{0303}') => 'Ẽ',
        ('E', '\u{0323}') => 'Ẹ',
        // ê / Ê
        ('ê', '\u{0300}') => 'ề',
        ('ê', '\u{0301}') => 'ế',
        ('ê', '\u{0309}') => 'ể',
        ('ê', '\u{0303}') => 'ễ',
        ('ê', '\u{0323}') => 'ệ',
        ('Ê', '\u{0300}') => 'Ề',
        ('Ê', '\u{0301}') => 'Ế',
        ('Ê', '\u{0309}') => 'Ể',
        ('Ê', '\u{0303}') => 'Ễ',
        ('Ê', '\u{0323}') => 'Ệ',
        // i / I
        ('i', '\u{0300}') => 'ì',
        ('i', '\u{0301}') => 'í',
        ('i', '\u{0309}') => 'ỉ',
        ('i', '\u{0303}') => 'ĩ',
        ('i', '\u{0323}') => 'ị',
        ('I', '\u{0300}') => 'Ì',
        ('I', '\u{0301}') => 'Í',
        ('I', '\u{0309}') => 'Ỉ',
        ('I', '\u{0303}') => 'Ĩ',
        ('I', '\u{0323}') => 'Ị',
        // o / O
        ('o', '\u{0300}') => 'ò',
        ('o', '\u{0301}') => 'ó',
        ('o', '\u{0309}') => 'ỏ',
        ('o', '\u{0303}') => 'õ',
        ('o', '\u{0323}') => 'ọ',
        ('O', '\u{0300}') => 'Ò',
        ('O', '\u{0301}') => 'Ó',
        ('O', '\u{0309}') => 'Ỏ',
        ('O', '\u{0303}') => 'Õ',
        ('O', '\u{0323}') => 'Ọ',
        // ô / Ô
        ('ô', '\u{0300}') => 'ồ',
        ('ô', '\u{0301}') => 'ố',
        ('ô', '\u{0309}') => 'ổ',
        ('ô', '\u{0303}') => 'ỗ',
        ('ô', '\u{0323}') => 'ộ',
        ('Ô', '\u{0300}') => 'Ồ',
        ('Ô', '\u{0301}') => 'Ố',
        ('Ô', '\u{0309}') => 'Ổ',
        ('Ô', '\u{0303}') => 'Ỗ',
        ('Ô', '\u{0323}') => 'Ộ',
        // ơ / Ơ
        ('ơ', '\u{0300}') => 'ờ',
        ('ơ', '\u{0301}') => 'ớ',
        ('ơ', '\u{0309}') => 'ở',
        ('ơ', '\u{0303}') => 'ỡ',
        ('ơ', '\u{0323}') => 'ợ',
        ('Ơ', '\u{0300}') => 'Ờ',
        ('Ơ', '\u{0301}') => 'Ớ',
        ('Ơ', '\u{0309}') => 'Ở',
        ('Ơ', '\u{0303}') => 'Ỡ',
        ('Ơ', '\u{0323}') => 'Ợ',
        // u / U
        ('u', '\u{0300}') => 'ù',
        ('u', '\u{0301}') => 'ú',
        ('u', '\u{0309}') => 'ủ',
        ('u', '\u{0303}') => 'ũ',
        ('u', '\u{0323}') => 'ụ',
        ('U', '\u{0300}') => 'Ù',
        ('U', '\u{0301}') => 'Ú',
        ('U', '\u{0309}') => 'Ủ',
        ('U', '\u{0303}') => 'Ũ',
        ('U', '\u{0323}') => 'Ụ',
        // ư / Ư
        ('ư', '\u{0300}') => 'ừ',
        ('ư', '\u{0301}') => 'ứ',
        ('ư', '\u{0309}') => 'ử',
        ('ư', '\u{0303}') => 'ữ',
        ('ư', '\u{0323}') => 'ự',
        ('Ư', '\u{0300}') => 'Ừ',
        ('Ư', '\u{0301}') => 'Ứ',
        ('Ư', '\u{0309}') => 'Ử',
        ('Ư', '\u{0303}') => 'Ữ',
        ('Ư', '\u{0323}') => 'Ự',
        // y / Y
        ('y', '\u{0300}') => 'ỳ',
        ('y', '\u{0301}') => 'ý',
        ('y', '\u{0309}') => 'ỷ',
        ('y', '\u{0303}') => 'ỹ',
        ('y', '\u{0323}') => 'ỵ',
        ('Y', '\u{0300}') => 'Ỳ',
        ('Y', '\u{0301}') => 'Ý',
        ('Y', '\u{0309}') => 'Ỷ',
        ('Y', '\u{0303}') => 'Ỹ',
        ('Y', '\u{0323}') => 'Ỵ',
        _ => return None,
    })
}

/// Zero-dependency canonical pair composition for the full Windows-1258 character repertoire.
///
/// Extends [`compose_vietnamese_pair`] with the 48 non-Vietnamese Latin base + CP1258 combining
/// mark (`U+0300`, `U+0301`, `U+0303`, `U+0323`) pairs that have precomposed Unicode NFC forms
/// (such as `n + \u{0303} -> ñ` and `ç + \u{0301} -> ḉ`).
#[inline]
pub const fn compose_cp1258_pair(base: char, mark: char) -> Option<char> {
    if let Some(ch) = compose_vietnamese_pair(base, mark) {
        return Some(ch);
    }
    Some(match (base, mark) {
        // U+0300 COMBINING GRAVE ACCENT
        ('N', '\u{0300}') => '\u{01F8}', // Ǹ
        ('n', '\u{0300}') => '\u{01F9}', // ǹ
        ('W', '\u{0300}') => '\u{1E80}', // Ẁ
        ('w', '\u{0300}') => '\u{1E81}', // ẁ
        // U+0301 COMBINING ACUTE ACCENT
        ('C', '\u{0301}') => '\u{0106}',        // Ć
        ('c', '\u{0301}') => '\u{0107}',        // ć
        ('\u{00C7}', '\u{0301}') => '\u{1E08}', // Ḉ
        ('\u{00E7}', '\u{0301}') => '\u{1E09}', // ḉ
        ('G', '\u{0301}') => '\u{01F4}',        // Ǵ
        ('g', '\u{0301}') => '\u{01F5}',        // ǵ
        ('K', '\u{0301}') => '\u{1E30}',        // Ḱ
        ('k', '\u{0301}') => '\u{1E31}',        // ḱ
        ('L', '\u{0301}') => '\u{0139}',        // Ĺ
        ('l', '\u{0301}') => '\u{013A}',        // ĺ
        ('M', '\u{0301}') => '\u{1E3E}',        // Ḿ
        ('m', '\u{0301}') => '\u{1E3F}',        // ḿ
        ('N', '\u{0301}') => '\u{0143}',        // Ń
        ('n', '\u{0301}') => '\u{0144}',        // ń
        ('P', '\u{0301}') => '\u{1E54}',        // Ṕ
        ('p', '\u{0301}') => '\u{1E55}',        // ṕ
        ('R', '\u{0301}') => '\u{0154}',        // Ŕ
        ('r', '\u{0301}') => '\u{0155}',        // ŕ
        ('S', '\u{0301}') => '\u{015A}',        // Ś
        ('s', '\u{0301}') => '\u{015B}',        // ś
        ('W', '\u{0301}') => '\u{1E82}',        // Ẃ
        ('w', '\u{0301}') => '\u{1E83}',        // ẃ
        ('Z', '\u{0301}') => '\u{0179}',        // Ź
        ('z', '\u{0301}') => '\u{017A}',        // ź
        // U+0303 COMBINING TILDE
        ('N', '\u{0303}') => '\u{00D1}', // Ñ
        ('n', '\u{0303}') => '\u{00F1}', // ñ
        ('V', '\u{0303}') => '\u{1E7C}', // Ṽ
        ('v', '\u{0303}') => '\u{1E7D}', // ṽ
        // U+0323 COMBINING DOT BELOW
        ('B', '\u{0323}') => '\u{1E04}', // Ḅ
        ('b', '\u{0323}') => '\u{1E05}', // ḅ
        ('D', '\u{0323}') => '\u{1E0C}', // Ḍ
        ('d', '\u{0323}') => '\u{1E0D}', // ḍ
        ('H', '\u{0323}') => '\u{1E24}', // Ḥ
        ('h', '\u{0323}') => '\u{1E25}', // ḥ
        ('K', '\u{0323}') => '\u{1E32}', // Ḳ
        ('k', '\u{0323}') => '\u{1E33}', // ḳ
        ('L', '\u{0323}') => '\u{1E36}', // Ḷ
        ('l', '\u{0323}') => '\u{1E37}', // ḷ
        ('M', '\u{0323}') => '\u{1E42}', // Ṃ
        ('m', '\u{0323}') => '\u{1E43}', // ṃ
        ('N', '\u{0323}') => '\u{1E46}', // Ṇ
        ('n', '\u{0323}') => '\u{1E47}', // ṇ
        ('R', '\u{0323}') => '\u{1E5A}', // Ṛ
        ('r', '\u{0323}') => '\u{1E5B}', // ṛ
        ('S', '\u{0323}') => '\u{1E62}', // Ṣ
        ('s', '\u{0323}') => '\u{1E63}', // ṣ
        ('T', '\u{0323}') => '\u{1E6C}', // Ṭ
        ('t', '\u{0323}') => '\u{1E6D}', // ṭ
        ('V', '\u{0323}') => '\u{1E7E}', // Ṿ
        ('v', '\u{0323}') => '\u{1E7F}', // ṿ
        ('W', '\u{0323}') => '\u{1E88}', // Ẉ
        ('w', '\u{0323}') => '\u{1E89}', // ẉ
        ('Z', '\u{0323}') => '\u{1E92}', // Ẓ
        ('z', '\u{0323}') => '\u{1E93}', // ẓ
        _ => return None,
    })
}

#[inline]
fn normalize_with<'a>(s: &'a str, composer: fn(char, char) -> Option<char>) -> Cow<'a, str> {
    if s.is_ascii() || !s.chars().any(is_vietnamese_combining_mark) {
        return Cow::Borrowed(s);
    }

    let mut out: Option<String> = None;
    let mut prev: Option<(usize, char)> = None;

    for (idx, c) in s.char_indices() {
        if let Some((prev_idx, prev_ch)) = prev {
            if let Some(composed) = composer(prev_ch, c) {
                let _ = out.get_or_insert_with(|| {
                    let mut buf = String::with_capacity(s.len());
                    buf.push_str(&s[..prev_idx]);
                    buf
                });
                prev = Some((prev_idx, composed));
                continue;
            }
            if let Some(buf) = out.as_mut() {
                buf.push(prev_ch);
            }
        }
        prev = Some((idx, c));
    }

    match (out, prev) {
        (Some(mut buf), Some((_, last))) => {
            buf.push(last);
            Cow::Owned(buf)
        }
        (Some(buf), None) => Cow::Owned(buf),
        (None, _) => Cow::Borrowed(s),
    }
}

/// Normalize a Vietnamese string to precomposed Unicode Normalization Form C (NFC)
/// using zero runtime dependencies.
///
/// Returns `Cow::Borrowed` with zero allocations when the string is ASCII or already composed.
pub fn normalize_nfc<'a>(s: &'a str) -> Cow<'a, str> {
    normalize_with(s, compose_vietnamese_pair)
}

/// Normalize a Windows-1258 decoded string to Unicode Normalization Form C (NFC),
/// composing both Vietnamese vowels and the 48 non-Vietnamese CP1258 consonant+mark pairs.
pub fn normalize_cp1258_nfc<'a>(s: &'a str) -> Cow<'a, str> {
    normalize_with(s, compose_cp1258_pair)
}
