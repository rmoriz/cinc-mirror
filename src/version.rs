//! Version parsing, ordering and segment glob matching.
//!
//! CINC versions are dot-separated numeric segments such as `19.4.46`.
//! Ordering is numeric per segment, so `19.10.0` sorts above `19.4.46`, and
//! missing trailing segments compare as zero, so `19.4` equals `19.4.0`.
//!
//! Glob patterns select whole segments only: `18.8.*` matches `18.8.11` but not
//! `18.9.1`, and `?` matches a single-digit segment. A pattern may be shorter
//! than the version; the remaining version segments are then unconstrained, so
//! `19.*` selects every 19.x version.

use std::cmp::Ordering;
use std::fmt;
use std::str::FromStr;

use thiserror::Error;

/// A parsed version: one or more numeric segments.
///
/// Equality and ordering ignore missing trailing zero segments, matching how
/// version bounds are compared during configuration validation.
#[derive(Debug, Clone)]
pub struct Version {
    segments: Vec<u64>,
}

impl Version {
    /// The parsed segments in order.
    #[must_use]
    pub fn segments(&self) -> &[u64] {
        &self.segments
    }

    /// A segment, or zero when the version has fewer segments.
    fn segment(&self, index: usize) -> u64 {
        self.segments.get(index).copied().unwrap_or(0)
    }
}

impl fmt::Display for Version {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, segment) in self.segments.iter().enumerate() {
            if index > 0 {
                formatter.write_str(".")?;
            }
            write!(formatter, "{segment}")?;
        }
        Ok(())
    }
}

impl FromStr for Version {
    type Err = VersionError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.is_empty() {
            return Err(VersionError::Empty {
                value: value.to_string(),
            });
        }

        let mut segments = Vec::new();
        for segment in value.split('.') {
            if segment.is_empty() {
                return Err(VersionError::EmptySegment {
                    value: value.to_string(),
                });
            }
            if !segment.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(VersionError::InvalidSegment {
                    value: value.to_string(),
                    segment: segment.to_string(),
                });
            }
            let parsed = segment
                .parse::<u64>()
                .map_err(|_| VersionError::SegmentOverflow {
                    value: value.to_string(),
                    segment: segment.to_string(),
                })?;
            segments.push(parsed);
        }

        Ok(Self { segments })
    }
}

impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Version {}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        let length = self.segments.len().max(other.segments.len());
        for index in 0..length {
            let ordering = self.segment(index).cmp(&other.segment(index));
            if ordering != Ordering::Equal {
                return ordering;
            }
        }
        Ordering::Equal
    }
}

/// Why a version could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum VersionError {
    #[error("version `{value}` is empty")]
    Empty { value: String },

    #[error("version `{value}` has an empty segment")]
    EmptySegment { value: String },

    #[error("version `{value}` has non-numeric segment `{segment}`")]
    InvalidSegment { value: String, segment: String },

    #[error("version `{value}` has segment `{segment}` larger than 64 bits")]
    SegmentOverflow { value: String, segment: String },
}

/// One segment of a [`VersionGlob`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Segment {
    /// An exact numeric segment.
    Literal(u64),
    /// `*`: any single segment.
    Wildcard,
    /// `?`: exactly one digit.
    SingleDigit,
}

/// A whole-segment version pattern such as `18.8.*`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionGlob {
    pattern: String,
    segments: Vec<Segment>,
}

impl VersionGlob {
    /// The parsed pattern segments.
    #[must_use]
    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }

    /// Whether `version` matches every segment of the pattern.
    ///
    /// A version shorter than the pattern is padded with zero segments. A
    /// version longer than the pattern matches when its leading segments match;
    /// the extra segments are unconstrained, so `19.*` selects every `19.x`
    /// version. This keeps globs consistent with version equality (`18.8`
    /// equals `18.8.0`).
    #[must_use]
    pub fn matches(&self, version: &Version) -> bool {
        for (index, segment) in self.segments.iter().enumerate() {
            let value = version.segment(index);
            match segment {
                Segment::Wildcard => {}
                Segment::SingleDigit => {
                    if value > 9 {
                        return false;
                    }
                }
                Segment::Literal(expected) => {
                    if value != *expected {
                        return false;
                    }
                }
            }
        }
        true
    }
}

impl fmt::Display for VersionGlob {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.pattern)
    }
}

impl FromStr for VersionGlob {
    type Err = VersionGlobError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.is_empty() {
            return Err(VersionGlobError::Empty {
                value: value.to_string(),
            });
        }

        let mut segments = Vec::new();
        for segment in value.split('.') {
            if segment.is_empty() {
                return Err(VersionGlobError::EmptySegment {
                    value: value.to_string(),
                });
            }

            let parsed = match segment {
                "*" => Segment::Wildcard,
                "?" => Segment::SingleDigit,
                _ if segment.bytes().all(|byte| byte.is_ascii_digit()) => {
                    Segment::Literal(segment.parse::<u64>().map_err(|_| {
                        VersionGlobError::SegmentOverflow {
                            value: value.to_string(),
                            segment: segment.to_string(),
                        }
                    })?)
                }
                _ => {
                    return Err(VersionGlobError::InvalidSegment {
                        value: value.to_string(),
                        segment: segment.to_string(),
                    });
                }
            };
            segments.push(parsed);
        }

        Ok(Self {
            pattern: value.to_string(),
            segments,
        })
    }
}

/// Why a version glob could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum VersionGlobError {
    #[error("version glob `{value}` is empty")]
    Empty { value: String },

    #[error("version glob `{value}` has an empty segment")]
    EmptySegment { value: String },

    #[error(
        "version glob `{value}` has invalid segment `{segment}`: \
         expected digits, `*` or `?`"
    )]
    InvalidSegment { value: String, segment: String },

    #[error("version glob `{value}` has segment `{segment}` larger than 64 bits")]
    SegmentOverflow { value: String, segment: String },
}
