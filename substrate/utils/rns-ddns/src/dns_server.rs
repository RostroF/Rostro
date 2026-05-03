use std::collections::HashMap;

use crate::authority::DnsRecord;
use rns_types::ddns::codec_type::RecordType;

pub struct DnsStore {
    records: HashMap<Vec<u8>, Vec<DnsRecord>>,
}

impl DnsStore {
    pub fn new() -> Self {
        Self {
            records: HashMap::new(),
        }
    }

    pub fn insert(&mut self, name: Vec<u8>, record: DnsRecord) {
        self.records.entry(name).or_default().push(record);
    }

    pub fn lookup(&self, name: &[u8], record_type: Option<RecordType>) -> Vec<&DnsRecord> {
        match self.records.get(name) {
            Some(entries) => match record_type {
                Some(rt) => entries.iter().filter(|r| r.record_type == rt).collect(),
                None => entries.iter().collect(),
            },
            None => Vec::new(),
        }
    }

    pub fn remove(&mut self, name: &[u8], record_type: RecordType) {
        if let Some(entries) = self.records.get_mut(name) {
            entries.retain(|r| r.record_type != record_type);
            if entries.is_empty() {
                self.records.remove(name);
            }
        }
    }

    pub fn remove_all(&mut self, name: &[u8]) {
        self.records.remove(name);
    }

    pub fn names(&self) -> impl Iterator<Item = &Vec<u8>> {
        self.records.keys()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }
}

impl Default for DnsStore {
    fn default() -> Self {
        Self::new()
    }
}
