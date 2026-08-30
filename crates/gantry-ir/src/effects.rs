//! Canonically ordered inferred effect sets.

use crate::generated::Effect;

/// All effects in the normative Gantry v1 order.
pub const EFFECT_ORDER: [Effect; 10] = [
    Effect::Prompt,
    Effect::Decide,
    Effect::ActionReadOnly,
    Effect::ActionIdempotent,
    Effect::ActionNonIdempotent,
    Effect::Spawn,
    Effect::Join,
    Effect::Background,
    Effect::Session,
    Effect::Attempt,
];

/// One finite canonical inferred effect set.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct EffectSet(u16);

impl EffectSet {
    /// Inserts one effect and returns whether the set changed.
    pub fn insert(&mut self, effect: Effect) -> bool {
        let bit = effect_bit(effect);
        let changed = self.0 & bit == 0;
        self.0 |= bit;
        changed
    }

    /// Returns whether one effect is present.
    #[must_use]
    pub fn contains(self, effect: Effect) -> bool {
        self.0 & effect_bit(effect) != 0
    }

    /// Returns effects in the normative canonical order.
    pub fn iter(self) -> impl Iterator<Item = Effect> {
        EFFECT_ORDER
            .into_iter()
            .filter(move |effect| self.contains(*effect))
    }

    /// Returns the union of two summaries.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Returns whether the inferred effect set is empty.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

fn effect_bit(effect: Effect) -> u16 {
    let index = EFFECT_ORDER
        .iter()
        .position(|candidate| *candidate == effect)
        .unwrap_or_else(|| unreachable!("closed effect vocabulary"));
    1_u16 << index
}

#[cfg(test)]
mod tests {
    use super::EffectSet;
    use crate::generated::Effect;

    #[test]
    fn effects_iterate_in_normative_order() {
        let mut effects = EffectSet::default();
        assert!(effects.insert(Effect::Attempt));
        assert!(effects.insert(Effect::Prompt));
        assert!(effects.insert(Effect::ActionReadOnly));
        assert!(!effects.insert(Effect::Prompt));
        assert_eq!(
            effects.iter().collect::<Vec<_>>(),
            [Effect::Prompt, Effect::ActionReadOnly, Effect::Attempt]
        );
    }
}
