# Substate
100% no-std/wasm compatible Substrate storage key generator

A simple macro is all you need to generate keys, check usage below.

```rust
// Storage Value
storage_key!("Session", "Validators");
// -> 0xcec5070d609dd3497f72bde07fc96ba088dcde934c658227ee1dfafcd6e16903

// Storage Map
storage_key!(
    "Staking",
    "ErasRewardPoints",
    (StorageHasher::Twox64Concat, 10)
);
// -> 0x5f3e4907f716ac89b6347d15ececedca80cc6574281671b299c1727d7ac68cabef8763d79d01484e0c000000

// Storage Double Map
storage_key!(
    "ImOnline",
    "AuthoredBlocks",
    (StorageHasher::Twox64Concat, 68),
    (StorageHasher::Twox64Concat, address_to_accountid("esqyGXvN7eezFoGtXAiLvXNnai2KFWkt7VfWwywHNBdwb8dUh").unwrap().0)
);
// -> 0x2b06af9719ac64d755623cda8ddd9b94b1c371ded9e9c565e89ba783c4d5f5f94e9f0caa17b4771b4b000000e669931fb1d70de1e63bad33d41d23e049d4f9efea39e4f44426b3f82104800ef6a9f29fbaa18667
```

Also comes with a set of string to AccountId and AccountId to string functions in the utils module, because the implementation in sp_core requires std

```rust
let (accountid: AccountId32, format: Ss58AddressFormat) = address_to_accountid("esqyGXvN7eezFoGtXAiLvXNnai2KFWkt7VfWwywHNBdwb8dUh").unwrap();

let account: String = accountid_to_address(accountid, format);
```
