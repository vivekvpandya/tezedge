// Copyright (c) SimpleStaking and Tezos-RS Contributors
// SPDX-License-Identifier: MIT

use std::sync::Arc;

use rocksdb::{ColumnFamilyDescriptor, MergeOperands, Options};

use tezos_encoding::hash::BlockHash;

use crate::{BlockHeaderWithHash, StorageError};
use crate::persistent::{Codec, DatabaseWithSchema, Schema, SchemaError};
use crate::persistent::database::{IteratorMode, IteratorWithSchema};

pub type BlockMetaStorageDatabase = dyn DatabaseWithSchema<BlockMetaStorage> + Sync + Send;

/// Structure for representing in-memory db for - just for demo purposes.
#[derive(Clone)]
pub struct BlockMetaStorage {
    db: Arc<BlockMetaStorageDatabase>
}

impl BlockMetaStorage {

    pub fn new(db: Arc<BlockMetaStorageDatabase>) -> Self {
        BlockMetaStorage { db }
    }

    pub fn insert(&mut self, block_header: &BlockHeaderWithHash) -> Result<(), StorageError> {
        // create/update record for block
        match self.get(&block_header.hash)?.as_mut() {
            Some(meta) => {
                meta.predecessor = Some(block_header.header.predecessor.clone());
                self.put(&block_header.hash, &meta)?;
            },
            None => {
                let meta = Meta {
                    is_processed: false,
                    predecessor: Some(block_header.header.predecessor.clone()),
                    successor: None
                };
                self.put(&block_header.hash, &meta)?;
            }
        }

        // create/update record for block predecessor
        match self.get(&block_header.header.predecessor)?.as_mut() {
            Some(meta) => {
                meta.successor = Some(block_header.hash.clone());
                self.put(&block_header.header.predecessor, &meta)?;
            },
            None => {
                let meta = Meta {
                    is_processed: false,
                    predecessor: None,
                    successor: Some(block_header.hash.clone())
                };
                self.put(&block_header.header.predecessor, &meta)?;
            }
        }

        Ok(())
    }

    pub fn put(&mut self, block_hash: &BlockHash, meta: &Meta) -> Result<(), StorageError> {
        self.db.put(block_hash, meta)
            .map_err(StorageError::from)
    }

    pub fn get(&self, block_hash: &BlockHash) -> Result<Option<Meta>, StorageError> {
        self.db.get(block_hash)
            .map_err(StorageError::from)
    }

    pub fn iter(&self, mode: IteratorMode<Self>) -> Result<IteratorWithSchema<Self>, StorageError> {
        self.db.iterator(mode)
            .map_err(StorageError::from)
    }
}

const BLOCK_LEN: usize = 32;

const MASK_IS_PROCESSED: u8    = 0b0000_0001;
const MASK_HAS_SUCCESSOR: u8   = 0b0000_0010;
const MASK_HAS_PREDECESSOR: u8 = 0b0000_0100;

const IDX_MASK: usize = 0;
const IDX_PREDECESSOR: usize = IDX_MASK + 1;
const IDX_SUCCESSOR: usize = IDX_PREDECESSOR + BLOCK_LEN;

const BLANK_BLOCK_HASH: [u8; BLOCK_LEN] = [0; BLOCK_LEN];
const META_LEN: usize = 1 + BLOCK_LEN + BLOCK_LEN;

macro_rules! is_processed {
    ($mask:expr) => {{ ($mask & MASK_IS_PROCESSED) != 0 }}
}
macro_rules! has_predecessor {
    ($mask:expr) => {{ ($mask & MASK_HAS_PREDECESSOR) != 0 }}
}
macro_rules! has_successor {
    ($mask:expr) => {{ ($mask & MASK_HAS_SUCCESSOR) != 0 }}
}

/// Meta information for the block
#[derive(Clone, PartialEq, Debug)]
pub struct Meta {
    pub predecessor: Option<BlockHash>,
    pub successor: Option<BlockHash>,
    pub is_processed: bool,
}

/// Codec for `Meta`
///
/// * bytes layout: `[mask(1)][predecessor(32)][successor(32)]`
impl Codec for Meta {
    fn decode(bytes: &[u8]) -> Result<Self, SchemaError> {
        if META_LEN == bytes.len() {
            let mask = bytes[IDX_MASK];
            let is_processed = is_processed!(mask);
            let predecessor = if has_predecessor!(mask) { Some(bytes[IDX_PREDECESSOR..IDX_SUCCESSOR].to_vec()) } else { None };
            let successor = if has_successor!(mask) { Some(bytes[IDX_SUCCESSOR..META_LEN].to_vec()) } else { None };

            Ok(Meta { predecessor, successor, is_processed })
        } else {
            Err(SchemaError::DecodeError)
        }
    }

    fn encode(&self) -> Result<Vec<u8>, SchemaError> {
        let mut mask = 0u8;
        if self.is_processed {
            mask |= MASK_IS_PROCESSED;
        }
        if self.predecessor.is_some() {
            mask |= MASK_HAS_PREDECESSOR;
        }
        if self.successor.is_some() {
            mask |= MASK_HAS_SUCCESSOR;
        }

        let mut value = Vec::with_capacity(META_LEN);
        value.push(mask);
        match &self.predecessor {
            Some(predecessor) =>  value.extend(predecessor),
            None => value.extend(&BLANK_BLOCK_HASH)
        }
        match &self.successor {
            Some(successor) =>  value.extend(successor),
            None => value.extend(&BLANK_BLOCK_HASH)
        }

        Ok(value)
    }
}

impl Schema for BlockMetaStorage {
    const COLUMN_FAMILY_NAME: &'static str = "block_meta_storage";
    type Key = BlockHash;
    type Value = Meta;

    fn cf_descriptor() -> ColumnFamilyDescriptor {
        let mut cf_opts = Options::default();
        cf_opts.set_merge_operator("block_meta_storage_merge_operator", merge_meta_value, None);
        ColumnFamilyDescriptor::new(Self::COLUMN_FAMILY_NAME, cf_opts)
    }
}

fn merge_meta_value(_new_key: &[u8], existing_val: Option<&[u8]>, operands: &mut MergeOperands) -> Option<Vec<u8>> {
    let mut result = existing_val.map(|v| v.to_vec());

    for op in operands {
        match result {
            Some(ref mut val) => {
                assert_eq!(META_LEN, val.len(), "Value length is incorrect");

                let mask_val = val[IDX_MASK];
                let mask_op = op[IDX_MASK];

                // merge `mask(1)`
                val[IDX_MASK] = mask_val | mask_op;

                // if op has predecessor and val has not, copy it from op to val
                if has_predecessor!(mask_op) && !has_predecessor!(mask_val) {
                    val.splice(IDX_PREDECESSOR..IDX_SUCCESSOR, op[IDX_PREDECESSOR..IDX_SUCCESSOR].iter().cloned());
                }
                // if op has successor and val has not, copy it from op to val
                if has_successor!(mask_op) && !has_successor!(mask_val) {
                    val.splice(IDX_SUCCESSOR..META_LEN, op[IDX_SUCCESSOR..META_LEN].iter().cloned());
                }
            },
            None => result = Some(op.to_vec())
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use failure::Error;

    use super::*;

    #[test]
    fn block_meta_encoded_equals_decoded() -> Result<(), Error> {
        let expected = Meta {
            is_processed: false,
            predecessor: Some(vec![98; 32]),
            successor: Some(vec![21; 32])
        };
        let encoded_bytes = expected.encode()?;
        let decoded = Meta::decode(&encoded_bytes)?;
        Ok(assert_eq!(expected, decoded))
    }


    #[test]
    fn merge_meta_value_test() {
        use rocksdb::{Options, DB};

        let path = "__blockmeta_mergetest";
        if Path::new(path).exists() {
            std::fs::remove_dir_all(path).unwrap();
        }
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        opts.set_merge_operator("test operator", merge_meta_value, None);
        {
            let db = DB::open_cf_descriptors(&opts, path, vec![BlockMetaStorage::cf_descriptor()]).unwrap();
            let k = vec![44; 32];
            let mut v = Meta {
                is_processed: false,
                predecessor: None,
                successor: None
            };
            let p = BlockMetaStorageDatabase::merge(&db, &k, &v);
            assert!(p.is_ok(), "p: {:?}", p.unwrap_err());
            v.is_processed = true;
            v.successor = Some(vec![21; 32]);
            let _ = BlockMetaStorageDatabase::merge(&db, &k, &v);
            v.is_processed = false;
            v.predecessor = Some(vec![98; 32]);
            v.successor = None;
            let _ = BlockMetaStorageDatabase::merge(&db, &k, &v);
            v.predecessor = None;
            let m = BlockMetaStorageDatabase::merge(&db, &k, &v);
            assert!(m.is_ok());
            match BlockMetaStorageDatabase::get(&db, &k) {
                Ok(Some(value)) => {
                    let expected = Meta {
                        is_processed: true,
                        predecessor: Some(vec![98; 32]),
                        successor: Some(vec![21; 32])
                    };
                    assert_eq!(expected, value);
                },
                Err(_) => println!("error reading value"),
                _ => panic!("value not present"),
            }
        }
        assert!(DB::destroy(&opts, path).is_ok());
    }
}