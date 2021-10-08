use codec::Encode;
pub use sp_core::hashing::twox_128;
pub use std::fmt::Write;

pub enum StorageHasher {
    Identity,
    Blake2_128,
    Blake2_128Concat,
    Blake2_256,
    Twox128,
    Twox256,
    Twox64Concat,
}

pub fn key_hash<K: Encode>(key: &K, hasher: &StorageHasher) -> Vec<u8> {
    let encoded_key = key.encode();
    match hasher {
        StorageHasher::Identity => encoded_key.to_vec(),
        StorageHasher::Blake2_128 => sp_core::blake2_128(&encoded_key).to_vec(),
        StorageHasher::Blake2_128Concat => {
            let x: &[u8] = encoded_key.as_slice();
            sp_core::blake2_128(x)
                .iter()
                .chain(x.iter())
                .cloned()
                .collect::<Vec<_>>()
        }
        StorageHasher::Blake2_256 => sp_core::blake2_256(&encoded_key).to_vec(),
        StorageHasher::Twox128 => sp_core::twox_128(&encoded_key).to_vec(),
        StorageHasher::Twox256 => sp_core::twox_256(&encoded_key).to_vec(),
        StorageHasher::Twox64Concat => sp_core::twox_64(&encoded_key)
            .iter()
            .chain(&encoded_key)
            .cloned()
            .collect(),
    }
}

//TODO: Proper error handling
pub fn generate_key(key: Vec<u8>) -> String {
    let mut storage_key = String::with_capacity(2 * key.len());
    write!(storage_key, "0x").unwrap();
    for byte in key {
        write!(storage_key, "{:02X}", byte).unwrap();
    }
    storage_key.to_lowercase()
}

#[macro_export]
macro_rules! storage_key {
    ( $module:expr, $storage:expr ) => {
        {
        let mut key = $crate::twox_128($module.as_bytes()).to_vec();
        key.extend(&$crate::twox_128($storage.as_bytes()));
        $crate::generate_key(key)
        }
    };
    ( $module:expr, $storage:expr, $( ($hasher:expr, $content:expr ) ),* ) => {
        {
    let mut key = $crate::twox_128($module.as_bytes()).to_vec();
    key.extend(&$crate::twox_128($storage.as_bytes()));

    $(
        key.extend($crate::key_hash(&$content , &$hasher));
    )*
        $crate::generate_key(key)
}
    };
}

pub mod utils {
    use base58::{FromBase58, ToBase58};
    use sp_core::crypto::{AccountId32, Ss58AddressFormat};
    use std::convert::TryInto;

    pub fn address_to_accountid(s: &str) -> Result<(AccountId32, Ss58AddressFormat), String> {
        const CHECKSUM_LEN: usize = 2;
        let mut res: AccountId32 = AccountId32::default();

        let body_len: &mut [u8; 32] = res.as_mut();
        let body_len = body_len.len();

        let data = s.from_base58().map_err(|_| String::from("error"))?;
        if data.len() < 2 {
            return Err(String::from("error"));
        }
        let (prefix_len, ident) = match data[0] {
            0..=63 => (1, data[0] as u16),
            64..=127 => {
                let lower = (data[0] << 2) | (data[1] >> 6);
                let upper = data[1] & 0b00111111;
                (2, (lower as u16) | ((upper as u16) << 8))
            }
            _ => return Err(String::from("error")),
        };
        if data.len() != prefix_len + body_len + CHECKSUM_LEN {
            return Err(String::from("error"));
        }
        let format = ident.try_into().map_err(|_: ()| String::from("error"))?;

        let hash = ss58hash(&data[0..body_len + prefix_len]);
        let checksum = &hash.as_bytes()[0..CHECKSUM_LEN];
        if data[body_len + prefix_len..body_len + prefix_len + CHECKSUM_LEN] != *checksum {
            return Err(String::from("error"));
        }
        let this: &mut [u8; 32] = res.as_mut();
        this.copy_from_slice(&data[prefix_len..body_len + prefix_len]);
        Ok((res, format))
    }

    pub fn accountid_to_address(acc: AccountId32, version: Ss58AddressFormat) -> String {
        let ident: u16 = u16::from(version) & 0b0011_1111_1111_1111;
        let mut v: Vec<u8> = match ident {
            0..=63 => vec![ident as u8],
            64..=16_383 => {
                let first = ((ident & 0b0000_0000_1111_1100) as u8) >> 2;
                let second = ((ident >> 8) as u8) | ((ident & 0b0000_0000_0000_0011) as u8) << 6;
                vec![first | 0b01000000, second]
            }
            _ => unreachable!("masked out the upper two bits; qed"),
        };
        let acc: &[u8; 32] = acc.as_ref();
        v.extend(acc);
        let r = ss58hash(&v);
        v.extend(&r.as_bytes()[0..2]);
        v.to_base58()
    }

    pub fn ss58hash(data: &[u8]) -> blake2_rfc::blake2b::Blake2bResult {
        let mut context = blake2_rfc::blake2b::Blake2b::new(64);
        context.update(b"SS58PRE");
        context.update(data);
        context.finalize()
    }
}

//TODO: Finish writing test cases
#[cfg(test)]
mod tests {
    use super::{storage_key, StorageHasher};
    use sp_core::crypto::AccountId32;

    #[test]
    fn test_storage_value() {
        assert_eq!(
            storage_key!("Timestamp", "Now"),
            "0xf0c365c3cf59d671eb72da0e7a4113c49f1f0515f462cdcf84e0f1d6045dfcbb"
        )
    }

    #[test]
    fn test_storage_double_map() {
        assert_eq!(
            storage_key!(
                "Staking",
                "ErasStakers",
                (StorageHasher::Twox64Concat, 10),
                (
                    StorageHasher::Twox64Concat,
                    AccountId32::new([
                        230, 59, 173, 51, 212, 29, 35, 224, 73, 212, 249, 239, 234, 57, 228, 244,
                        68, 38, 179, 248, 33, 4, 128, 14, 246, 169, 242, 159, 186, 161, 134, 103
                    ])
                )
            ),
            "0x5f3e4907f716ac89b6347d15ececedca8bde0a0ea8864605e3b68ed9cb2da01ba6b274250e6753f00a000000e669931fb1d70de1e63bad33d41d23e049d4f9efea39e4f44426b3f82104800ef6a9f29fbaa18667"
        )
    }
}
