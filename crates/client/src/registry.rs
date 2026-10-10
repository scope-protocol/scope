//! The on-chain registry (docs/protocol.md): sRFC-42 v1 entries in our program.
//! Lookups fetch every entry in one query and pick locally, so the query does not name
//! the wallet looked up (docs/privacy.md, Registration).

use crate::{
    address::{meta_entry_address, program_id},
    chain::{ChainError, RecipientChain},
};
use scope_interface::state::{META_SCHEME_V1, META_VERSION, MetaAddressEntry};
use solana_address::Address;
use std::collections::HashMap;
use stealth_keygen::RecipientPublicKeys;

/// The meta-address each wallet published, if any. Entries whose address, scheme or
/// keys do not check out are ignored.
pub fn lookup<C: RecipientChain>(
    chain: &C,
    wallets: &[Address],
) -> Result<Vec<(Address, Option<RecipientPublicKeys>)>, ChainError> {
    let mut published: HashMap<Address, RecipientPublicKeys> = HashMap::new();
    for (address, account) in chain.registry_entries()? {
        if account.owner != program_id() {
            continue;
        }
        let Ok(entry) = MetaAddressEntry::from_bytes(&account.data) else {
            continue;
        };
        let registrant = Address::new_from_array(entry.registrant);
        if entry.scheme_id != META_SCHEME_V1
            || entry.version != META_VERSION
            || entry.flags != 0
            || meta_entry_address(&registrant).0 != address
        {
            continue;
        }
        if let Ok(keys) = RecipientPublicKeys::from_bytes(entry.spend, entry.scan) {
            published.insert(registrant, keys);
        }
    }
    Ok(wallets
        .iter()
        .map(|w| (*w, published.get(w).cloned()))
        .collect())
}
