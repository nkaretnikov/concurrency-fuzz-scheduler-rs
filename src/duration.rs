// Duration parsing and formatting, ported from DurationConverter.java and
// DurationRangeConverter.java. Everything is kept in nanoseconds, which is the
// unit the BPF scheduler works in.

use std::fmt;

use anyhow::{bail, Result};

/// Parse a duration string such as "10ms", "1.5s", "200us" or "500ns" into
/// nanoseconds. Fractions are allowed. The accepted grammar is
/// `[0-9]+(\.[0-9]+)?(ms|us|ns|s)`, matching the original Java converter.
pub fn parse_to_nanoseconds(text: &str) -> Result<u64> {
    let (unit, unit_len): (f64, usize) = if let Some(_) = text.strip_suffix("ms") {
        (1_000_000.0, 2)
    } else if text.ends_with("us") {
        (1_000.0, 2)
    } else if text.ends_with("ns") {
        (1.0, 2)
    } else if text.ends_with('s') {
        (1_000_000_000.0, 1)
    } else {
        bail!("invalid duration string: {text}");
    };

    let number = &text[..text.len() - unit_len];
    if number.is_empty() || !is_valid_number(number) {
        bail!("invalid duration string: {text}");
    }

    let value: f64 = number
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid duration string: {text}"))?;

    Ok((value * unit) as u64)
}

// Accept only digits with at most a single decimal point and digits on both
// sides, mirroring the regex used by the Java version.
fn is_valid_number(s: &str) -> bool {
    let mut parts = s.split('.');
    let int_part = parts.next().unwrap_or("");
    let frac_part = parts.next();
    if parts.next().is_some() {
        return false;
    }
    let digits = |p: &str| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit());
    match frac_part {
        None => digits(int_part),
        Some(frac) => digits(int_part) && digits(frac),
    }
}

/// Render a nanosecond count using the largest unit that keeps the number
/// readable, with the requested number of decimals.
pub fn nanoseconds_to_string(nanoseconds: u64, decimals: usize) -> String {
    if nanoseconds < 1_000 {
        format!("{nanoseconds}ns")
    } else if nanoseconds < 1_000_000 {
        format!("{:.*}us", decimals, nanoseconds as f64 / 1_000.0)
    } else if nanoseconds < 1_000_000_000 {
        format!("{:.*}ms", decimals, nanoseconds as f64 / 1_000_000.0)
    } else {
        format!("{:.*}s", decimals, nanoseconds as f64 / 1_000_000_000.0)
    }
}

/// A closed-open range of durations in nanoseconds.
#[derive(Clone, Copy, Debug)]
pub struct DurationRange {
    pub min_ns: u64,
    pub max_ns: u64,
}

impl DurationRange {
    pub fn new(min_ns: u64, max_ns: u64) -> Result<Self> {
        if min_ns > max_ns {
            bail!("min_ns must be less than or equal to max_ns");
        }
        Ok(Self { min_ns, max_ns })
    }

    /// Parse "a,b" as a range or "a" as a degenerate single value range.
    pub fn parse(text: &str) -> Result<Self> {
        let parts: Vec<&str> = text.split(',').collect();
        match parts.as_slice() {
            [single] => {
                let ns = parse_to_nanoseconds(single.trim())?;
                Self::new(ns, ns)
            }
            [min, max] => {
                Self::new(parse_to_nanoseconds(min.trim())?, parse_to_nanoseconds(max.trim())?)
            }
            _ => bail!("invalid duration range: {text}"),
        }
    }
}

impl fmt::Display for DurationRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} - {}",
            nanoseconds_to_string(self.min_ns, 3),
            nanoseconds_to_string(self.max_ns, 3)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_units() {
        assert_eq!(parse_to_nanoseconds("5ns").unwrap(), 5);
        assert_eq!(parse_to_nanoseconds("2us").unwrap(), 2_000);
        assert_eq!(parse_to_nanoseconds("3ms").unwrap(), 3_000_000);
        assert_eq!(parse_to_nanoseconds("1s").unwrap(), 1_000_000_000);
        assert_eq!(parse_to_nanoseconds("1.5s").unwrap(), 1_500_000_000);
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_to_nanoseconds("10").is_err());
        assert!(parse_to_nanoseconds("ms").is_err());
        assert!(parse_to_nanoseconds("1.2.3s").is_err());
        assert!(parse_to_nanoseconds("abcms").is_err());
    }

    #[test]
    fn parses_ranges() {
        let r = DurationRange::parse("10ms,2000ms").unwrap();
        assert_eq!(r.min_ns, 10_000_000);
        assert_eq!(r.max_ns, 2_000_000_000);

        let single = DurationRange::parse("5ms").unwrap();
        assert_eq!(single.min_ns, single.max_ns);
        assert_eq!(single.min_ns, 5_000_000);
    }

    #[test]
    fn formats_durations() {
        assert_eq!(nanoseconds_to_string(500, 3), "500ns");
        assert_eq!(nanoseconds_to_string(1_500, 3), "1.500us");
        assert_eq!(nanoseconds_to_string(2_000_000, 3), "2.000ms");
        assert_eq!(nanoseconds_to_string(3_000_000_000, 1), "3.0s");
    }
}
