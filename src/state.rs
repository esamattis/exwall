use crate::{config::Config, rules::RuleSet};
use arc_swap::ArcSwap;
use std::sync::Arc;

/// One atomic snapshot of runtime settings and compiled allow rules.
pub struct Policy {
    pub config: Config,
    pub rules: RuleSet,
}
pub type SharedPolicy = Arc<ArcSwap<Policy>>;
