//! MaxMind-format (GeoLite2 / DB-IP Lite) lookups.

use std::{
    net::IpAddr,
    path::{Path, PathBuf},
    time::SystemTime,
};

use maxminddb::{Reader, geoip2};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GeoInfo {
    pub country_code: Option<String>,
    pub country: Option<String>,
    pub city: Option<String>,
    pub lat: Option<f64>,
    pub lon: Option<f64>,
    pub asn: Option<u32>,
    pub as_org: Option<String>,
}

impl GeoInfo {
    pub fn short(&self) -> String {
        let cc = self.country_code.as_deref().unwrap_or("--");
        match (self.asn, self.as_org.as_deref()) {
            (Some(asn), Some(org)) => format!("{cc} AS{asn} {org}"),
            (Some(asn), None) => format!("{cc} AS{asn}"),
            _ => cc.to_string(),
        }
    }
}

struct Db {
    path: PathBuf,
    mtime: Option<SystemTime>,
    reader: Option<Reader<Vec<u8>>>,
}

impl Db {
    fn open(path: &Path) -> Self {
        let mut db = Self {
            path: path.to_path_buf(),
            mtime: None,
            reader: None,
        };
        db.reload();
        db
    }

    fn reload(&mut self) {
        self.mtime = std::fs::metadata(&self.path)
            .and_then(|m| m.modified())
            .ok();
        match Reader::open_readfile(&self.path) {
            Ok(r) => {
                log::info!(
                    "geo database {} ({})",
                    self.path.display(),
                    r.metadata().database_type
                );
                self.reader = Some(r);
            }
            Err(e) => {
                log::warn!("geo database {} unavailable: {e}", self.path.display());
                self.reader = None;
            }
        }
    }

    fn changed(&self) -> bool {
        std::fs::metadata(&self.path)
            .and_then(|m| m.modified())
            .ok()
            != self.mtime
    }
}

pub struct Geo {
    city: Db,
    asn: Db,
}

impl Geo {
    pub fn open(city: &Path, asn: &Path) -> Self {
        Self {
            city: Db::open(city),
            asn: Db::open(asn),
        }
    }

    /// Picks up databases replaced on disk by the update script; true when
    /// one was.
    pub fn reload_if_changed(&mut self) -> bool {
        let mut reloaded = false;
        for db in [&mut self.city, &mut self.asn] {
            if db.changed() {
                db.reload();
                reloaded = true;
            }
        }
        reloaded
    }

    pub fn available(&self) -> bool {
        self.city.reader.is_some() || self.asn.reader.is_some()
    }

    pub fn lookup(&self, ip: IpAddr) -> GeoInfo {
        let mut info = GeoInfo::default();
        if let Some(r) = &self.city.reader
            && let Ok(Some(c)) = r.lookup(ip).and_then(|res| res.decode::<geoip2::City>())
        {
            info.country_code = c.country.iso_code.map(str::to_string);
            info.country = c.country.names.english.map(str::to_string);
            info.city = c.city.names.english.map(str::to_string);
            info.lat = c.location.latitude;
            info.lon = c.location.longitude;
        }
        if let Some(r) = &self.asn.reader
            && let Ok(Some(a)) = r.lookup(ip).and_then(|res| res.decode::<geoip2::Asn>())
        {
            info.asn = a.autonomous_system_number;
            info.as_org = a.autonomous_system_organization.map(str::to_string);
        }
        info
    }
}
