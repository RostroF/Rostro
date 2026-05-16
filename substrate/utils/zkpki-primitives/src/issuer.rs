use codec::{Decode, Encode, MaxEncodedLen};
use frame_support::{traits::ConstU32, BoundedVec};
use scale_info::TypeInfo;

use crate::cert::Thumbprint;
use crate::eku::Eku;

/// Maximum number of capability EKUs per root / issuer record.
/// A single entity rarely needs more than a handful; the cap keeps
/// the record's MaxEncodedLen bounded.
pub const MAX_CAPABILITY_EKUS: u32 = 8;

/// State machine for root and issuer lifecycle.
///
/// Precedence order: compromised → challenge → deactivated → retired → active.
///
/// State transition rules (enforced by `transition()`):
/// - `Active → Retired` — renewal
/// - `Active → Compromised` — flagged by governance/root
/// - `Active → Deactivated` — parent root deregistered (clean exit)
/// - `Retired → Compromised` — compromise overrides everything
/// - `Retired → Deactivated` — parent root deregistered
/// - `Compromised → Challenge` — entity contests (one shot only, checked externally)
/// - `Challenge → Active` — successful challenge resolution
/// - `Challenge → Compromised` — failed challenge / timeout
/// - `Deactivated → Compromised` — compromise discovered after deactivation
#[derive(Encode, Decode, Clone, PartialEq, Eq, TypeInfo, MaxEncodedLen)]
#[cfg_attr(feature = "std", derive(Debug, serde::Serialize, serde::Deserialize))]
pub enum EntityState<BlockNumber> {
    /// Normal operating state.
    Active,
    /// Legacy state during renewal. No new issuance.
    /// Existing end-user certs remain valid until their own NotAfter.
    Retired {
        successor: Thumbprint,
    },
    /// 45-day contest window. Reputation unchanged. No issuance.
    Challenge {
        challenged_at: BlockNumber,
        deadline: BlockNumber,
    },
    /// Permanent. Entire issuance history suspect.
    Compromised {
        at_block: BlockNumber,
    },
    /// Clean deactivation from parent root deregistration.
    /// Cannot issue new certs. Existing certs valid until NotAfter.
    /// Can re-register under a new root without permanent taint.
    Deactivated {
        at_block: BlockNumber,
    },
}

/// Error returned when an illegal state transition is attempted.
#[derive(Debug, PartialEq, Eq)]
pub enum StateTransitionError {
    CompromisedIsPermanent,
    IllegalTransition,
}

// Simple query methods.
impl<BlockNumber> EntityState<BlockNumber> {
    pub fn can_issue(&self) -> bool {
        matches!(self, EntityState::Active)
    }

    pub fn is_compromised(&self) -> bool {
        matches!(self, EntityState::Compromised { .. })
    }

    pub fn is_challenged(&self) -> bool {
        matches!(self, EntityState::Challenge { .. })
    }

    pub fn is_retired(&self) -> bool {
        matches!(self, EntityState::Retired { .. })
    }

    pub fn is_deactivated(&self) -> bool {
        matches!(self, EntityState::Deactivated { .. })
    }
}

impl<BlockNumber: PartialOrd + Clone> EntityState<BlockNumber> {
    pub fn transition(
        &mut self,
        new: EntityState<BlockNumber>,
    ) -> Result<(), StateTransitionError> {
        match (&*self, &new) {
            (EntityState::Active, EntityState::Retired { .. }) => {},
            (EntityState::Active, EntityState::Compromised { .. }) => {},
            (EntityState::Active, EntityState::Deactivated { .. }) => {},

            (EntityState::Retired { .. }, EntityState::Compromised { .. }) => {},
            (EntityState::Retired { .. }, EntityState::Deactivated { .. }) => {},

            // Compromised → Challenge: one-shot, checked externally via challenge_used
            (EntityState::Compromised { .. }, EntityState::Challenge { .. }) => {},

            (EntityState::Challenge { .. }, EntityState::Active) => {},
            (EntityState::Challenge { .. }, EntityState::Compromised { .. }) => {},

            (EntityState::Deactivated { .. }, EntityState::Compromised { .. }) => {},

            (EntityState::Compromised { .. }, _) => {
                return Err(StateTransitionError::CompromisedIsPermanent);
            },
            _ => {
                return Err(StateTransitionError::IllegalTransition);
            },
        }
        *self = new;
        Ok(())
    }

    pub fn is_deadline_passed(&self, now: &BlockNumber) -> bool {
        match self {
            EntityState::Challenge { deadline, .. } => now >= deadline,
            _ => false,
        }
    }
}

/// On-chain record for a registered issuer.
#[derive(Encode, Decode, Clone, PartialEq, Eq, TypeInfo, MaxEncodedLen)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct IssuerRecord<AccountId, BlockNumber> {
    pub root: AccountId,
    pub proxy: AccountId,
    pub cert_thumbprint: Thumbprint,
    pub registered_at: BlockNumber,
    pub state: EntityState<BlockNumber>,
    /// One-shot. Set permanently when a challenge resolves to Compromised.
    /// Prevents repeated challenge cycling.
    pub challenge_used: bool,
    /// Capability EKUs granted at `issue_issuer_cert` time. Must be a
    /// subset of the root's own `capability_ekus` for any entry that
    /// returns `true` from `Eku::requires_issuer_capability()`.
    /// Templates created by this issuer can only attach EKUs that
    /// appear here (for hierarchical EKUs) or are freely assignable
    /// standard EKUs.
    pub capability_ekus: BoundedVec<Eku, ConstU32<MAX_CAPABILITY_EKUS>>,
}

impl<AccountId, BlockNumber> IssuerRecord<AccountId, BlockNumber> {
    pub fn can_issue(&self) -> bool {
        self.state.can_issue()
    }

    pub fn is_compromised(&self) -> bool {
        self.state.is_compromised()
    }
}

/// On-chain record for a registered root.
#[derive(Encode, Decode, Clone, PartialEq, Eq, TypeInfo, MaxEncodedLen)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct RootRecord<AccountId, BlockNumber> {
    pub proxy: AccountId,
    pub cert_thumbprint: Thumbprint,
    pub registered_at: BlockNumber,
    pub state: EntityState<BlockNumber>,
    /// One-shot. Set permanently when a challenge resolves to Compromised.
    pub challenge_used: bool,
    /// Capability EKUs declared at `register_root` time. Limits what
    /// hierarchical EKUs issuers chartered under this root can hold
    /// or grant. Must pass `Eku::valid_for_root()` for every entry.
    pub capability_ekus: BoundedVec<Eku, ConstU32<MAX_CAPABILITY_EKUS>>,
}

impl<AccountId, BlockNumber> RootRecord<AccountId, BlockNumber> {
    pub fn can_issue(&self) -> bool {
        self.state.can_issue()
    }

    pub fn is_compromised(&self) -> bool {
        self.state.is_compromised()
    }
}

/// Record stored in the `DeregisteredRoots` append-only set.
#[derive(Encode, Decode, Clone, PartialEq, Eq, TypeInfo, MaxEncodedLen)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct DeregistrationRecord<BlockNumber> {
    pub at_block: BlockNumber,
    /// Write-once. If true, re-registration permanently blocked.
    pub tainted: bool,
}
