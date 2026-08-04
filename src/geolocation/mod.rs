//! Country lookup from per-country CIDR files (ipdeny.com `.zone` format).
//!
//! No MaxMind licence required: we reuse the per-country IP block lists that
//! the server already downloads weekly. Each `<cc>.zone` file (e.g. `fr.zone`)
//! holds one CIDR per line. They are loaded once at startup into a pair of
//! range tables (IPv4 as `u32`, IPv6 as `u128`), sorted by start address, and
//! queried with a binary search — O(log n) per request over ~200k ranges,
//! roughly 2 MB of memory, zero external dependency.
//!
//! Country codes are interned to a `u16` id to keep the tables compact.

use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::Path;

/// Inclusive address range tagged with an interned country id.
type V4Range = (u32, u32, u16);
type V6Range = (u128, u128, u16);

/// IP → ISO-3166 alpha-2 country resolver backed by CIDR range tables.
#[derive(Debug, Default)]
pub struct CountryDb {
    v4: Vec<V4Range>,
    v6: Vec<V6Range>,
    names: Vec<String>,
}

enum Parsed {
    V4(u32, u32),
    V6(u128, u128),
}

/// Parse a single CIDR line (`1.2.3.0/24`, `2001:db8::/32`) into an inclusive
/// range. A bare address (no `/`) is treated as a single host.
fn parse_cidr(line: &str) -> Option<Parsed> {
    let (addr_str, prefix_str) = match line.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (line, None),
    };
    match addr_str.parse::<IpAddr>().ok()? {
        IpAddr::V4(a) => {
            let base = u32::from(a);
            let p: u8 = prefix_str.map_or(Some(32), |s| s.parse().ok())?;
            if p > 32 {
                return None;
            }
            let mask = if p == 0 { 0 } else { u32::MAX << (32 - p) };
            let start = base & mask;
            Some(Parsed::V4(start, start | !mask))
        }
        IpAddr::V6(a) => {
            let base = u128::from(a);
            let p: u8 = prefix_str.map_or(Some(128), |s| s.parse().ok())?;
            if p > 128 {
                return None;
            }
            let mask = if p == 0 { 0 } else { u128::MAX << (128 - p) };
            let start = base & mask;
            Some(Parsed::V6(start, start | !mask))
        }
    }
}

/// Binary-search a sorted, disjoint range table for the one containing `ip`.
fn lookup_range<T: Copy + Ord>(ranges: &[(T, T, u16)], ip: T) -> Option<u16> {
    // Greatest start <= ip.
    let idx = ranges.partition_point(|r| r.0 <= ip);
    if idx == 0 {
        return None;
    }
    let (start, end, id) = ranges[idx - 1];
    if ip >= start && ip <= end {
        Some(id)
    } else {
        None
    }
}

impl CountryDb {
    /// An empty database — resolves every IP to `None` (geo lookups inert).
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    fn intern(names: &mut Vec<String>, idx: &mut HashMap<String, u16>, cc: &str) -> u16 {
        if let Some(id) = idx.get(cc) {
            return *id;
        }
        let id = u16::try_from(names.len()).unwrap_or(u16::MAX);
        names.push(cc.to_string());
        idx.insert(cc.to_string(), id);
        id
    }

    fn ingest(&mut self, idx: &mut HashMap<String, u16>, cc: &str, cidrs: &str) {
        let id = Self::intern(&mut self.names, idx, cc);
        for line in cidrs.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            match parse_cidr(line) {
                Some(Parsed::V4(s, e)) => self.v4.push((s, e, id)),
                Some(Parsed::V6(s, e)) => self.v6.push((s, e, id)),
                None => {}
            }
        }
    }

    fn finalize(&mut self) {
        self.v4.sort_unstable_by_key(|r| r.0);
        self.v6.sort_unstable_by_key(|r| r.0);
    }

    /// Load every `<cc>.zone` file from `dir`. The file stem is the ISO country
    /// code (upper-cased). Missing directory → an empty database (not an error),
    /// so geo policy degrades to "no country data" instead of failing startup.
    pub fn load_dir<P: AsRef<Path>>(dir: P) -> std::io::Result<Self> {
        let mut db = Self::empty();
        let mut idx = HashMap::new();
        let dir = dir.as_ref();
        if !dir.exists() {
            return Ok(db);
        }
        for entry in fs::read_dir(dir)? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("zone") {
                continue;
            }
            let cc = match path.file_stem().and_then(|s| s.to_str()) {
                Some(s) if s.len() == 2 => s.to_ascii_uppercase(),
                _ => continue,
            };
            let content = fs::read_to_string(&path)?;
            db.ingest(&mut idx, &cc, &content);
        }
        db.finalize();
        Ok(db)
    }

    /// Resolve an IP to its ISO country code, or `None` if unknown.
    ///
    /// IPv4-mapped IPv6 (`::ffff:a.b.c.d`) is resolved against the IPv4 table.
    #[must_use]
    pub fn lookup(&self, ip: IpAddr) -> Option<&str> {
        let id = match ip {
            IpAddr::V4(a) => lookup_range(&self.v4, u32::from(a)),
            IpAddr::V6(a) => match a.to_ipv4_mapped() {
                Some(v4) => lookup_range(&self.v4, u32::from(v4)),
                None => lookup_range(&self.v6, u128::from(a)),
            },
        }?;
        self.names.get(id as usize).map(String::as_str)
    }

    /// Total number of CIDR ranges loaded (v4 + v6).
    #[must_use]
    pub fn range_count(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    /// Number of distinct countries loaded.
    #[must_use]
    pub fn country_count(&self) -> usize {
        self.names.len()
    }

    /// Whether a country code (case-insensitive) has ranges loaded — i.e. the
    /// geo engine can actually identify visitors from that country.
    #[must_use]
    pub fn knows_country(&self, cc: &str) -> bool {
        let cc = cc.trim().to_ascii_uppercase();
        self.names.iter().any(|n| *n == cc)
    }

    /// True when no ranges are loaded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    /// Build a database directly from `(country, cidr)` pairs — for tests and
    /// programmatic construction.
    #[must_use]
    pub fn from_pairs(pairs: &[(&str, &str)]) -> Self {
        let mut db = Self::empty();
        let mut idx = HashMap::new();
        for (cc, cidr) in pairs {
            db.ingest(&mut idx, &cc.to_ascii_uppercase(), cidr);
        }
        db.finalize();
        db
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> CountryDb {
        CountryDb::from_pairs(&[
            ("fr", "90.114.0.0/16\n2001:863::/32"),
            ("us", "8.8.8.0/24"),
            ("cn", "1.0.0.0/8"),
        ])
    }

    #[test]
    fn resolves_ipv4_country() {
        let db = db();
        assert_eq!(db.lookup("90.114.131.138".parse().unwrap()), Some("FR"));
        assert_eq!(db.lookup("8.8.8.8".parse().unwrap()), Some("US"));
        assert_eq!(db.lookup("1.2.3.4".parse().unwrap()), Some("CN"));
    }

    #[test]
    fn unknown_ip_is_none() {
        assert_eq!(db().lookup("203.0.113.7".parse().unwrap()), None);
    }

    #[test]
    fn resolves_ipv6_and_mapped() {
        let db = db();
        assert_eq!(db.lookup("2001:863:21d::1".parse().unwrap()), Some("FR"));
        // v4-mapped resolves via the v4 table
        assert_eq!(db.lookup("::ffff:8.8.8.8".parse().unwrap()), Some("US"));
    }

    #[test]
    fn knows_country_is_case_insensitive() {
        let db = db();
        assert!(db.knows_country("fr"));
        assert!(db.knows_country("FR"));
        assert!(db.knows_country(" us "));
        assert!(!db.knows_country("QQ"));
        assert!(!CountryDb::empty().knows_country("FR"));
    }

    #[test]
    fn counts_and_empty() {
        let db = db();
        assert_eq!(db.country_count(), 3);
        assert_eq!(db.range_count(), 4);
        assert!(CountryDb::empty().is_empty());
        assert_eq!(CountryDb::empty().lookup("8.8.8.8".parse().unwrap()), None);
    }
}
