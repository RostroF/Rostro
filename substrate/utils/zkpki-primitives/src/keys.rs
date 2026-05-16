//! Newtype wrappers for composite storage keys.
//! Named field access prevents silent breakage from field reordering in storage migrations.

use codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;

/// Composite key for the UserIssuerIndex storage map.
/// Semantics: "which cert does this user hold from this issuer?"
#[derive(Encode, Decode, Clone, PartialEq, Eq, Hash, TypeInfo, MaxEncodedLen)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct UserIssuerKey<AccountId> {
    pub user: AccountId,
    pub issuer: AccountId,
}

impl<AccountId> UserIssuerKey<AccountId> {
    pub fn new(user: AccountId, issuer: AccountId) -> Self {
        Self { user, issuer }
    }
}

/// Composite key for the OfferIndex storage map.
/// Semantics: "which offer has this issuer made to this user?"
/// Distinct type from UserIssuerKey to prevent field assignment mixups
/// — compiler catches any confusion between the two.
#[derive(Encode, Decode, Clone, PartialEq, Eq, Hash, TypeInfo, MaxEncodedLen)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct IssuerUserKey<AccountId> {
    pub issuer: AccountId,
    pub user: AccountId,
}

impl<AccountId> IssuerUserKey<AccountId> {
    pub fn new(issuer: AccountId, user: AccountId) -> Self {
        Self { issuer, user }
    }
}
