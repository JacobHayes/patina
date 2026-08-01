//! Ordinary application logic under test.
//!
//! This module deliberately imports no Patina crates. In a real service it would
//! live in the checkout/payment library. The simulator in `main.rs` calls it
//! from virtual actors and checks the user-facing invariant: retrying the
//! same checkout request must not charge the customer twice.

use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Idempotency {
    Enforced,
    Missing,
}

#[derive(Clone, Debug)]
pub struct Reservation {
    pub receipt: String,
    pub duplicate_request: bool,
}

#[derive(Debug, Default)]
pub struct CheckoutLedger {
    orders_by_key: BTreeMap<String, OrderState>,
    next_receipt: u64,
}

#[derive(Clone, Debug)]
struct OrderState {
    order_id: String,
    receipt: String,
    charges: u64,
}

impl CheckoutLedger {
    pub fn reserve(
        &mut self,
        order_id: &str,
        idempotency_key: &str,
        idempotency: Idempotency,
    ) -> Reservation {
        if let Some(existing) = self.orders_by_key.get_mut(idempotency_key) {
            assert_eq!(
                existing.order_id, order_id,
                "one idempotency key must describe one logical order"
            );
            match idempotency {
                Idempotency::Enforced => Reservation {
                    receipt: existing.receipt.clone(),
                    duplicate_request: true,
                },
                Idempotency::Missing => {
                    // The planted bug: the service recognizes the retry but still
                    // performs the non-idempotent side effect again.
                    existing.charges += 1;
                    self.next_receipt += 1;
                    existing.receipt = format!("receipt-{}", self.next_receipt);
                    Reservation {
                        receipt: existing.receipt.clone(),
                        duplicate_request: true,
                    }
                }
            }
        } else {
            self.next_receipt += 1;
            let receipt = format!("receipt-{}", self.next_receipt);
            self.orders_by_key.insert(
                idempotency_key.to_string(),
                OrderState {
                    order_id: order_id.to_string(),
                    receipt: receipt.clone(),
                    charges: 1,
                },
            );
            Reservation {
                receipt,
                duplicate_request: false,
            }
        }
    }

    pub fn charges_for_key(&self, idempotency_key: &str) -> u64 {
        self.orders_by_key
            .get(idempotency_key)
            .map_or(0, |order| order.charges)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforced_idempotency_returns_cached_receipt_without_new_charge() {
        let mut ledger = CheckoutLedger::default();
        let first = ledger.reserve("order-42", "key-1", Idempotency::Enforced);
        let retry = ledger.reserve("order-42", "key-1", Idempotency::Enforced);

        assert!(!first.duplicate_request);
        assert!(retry.duplicate_request);
        assert_eq!(retry.receipt, first.receipt);
        assert_eq!(ledger.charges_for_key("key-1"), 1);
    }

    #[test]
    fn missing_idempotency_charges_a_retry_twice() {
        let mut ledger = CheckoutLedger::default();
        let first = ledger.reserve("order-42", "key-1", Idempotency::Missing);
        let retry = ledger.reserve("order-42", "key-1", Idempotency::Missing);

        assert!(!first.duplicate_request);
        assert!(retry.duplicate_request);
        assert_ne!(retry.receipt, first.receipt);
        assert_eq!(ledger.charges_for_key("key-1"), 2);
    }
}
