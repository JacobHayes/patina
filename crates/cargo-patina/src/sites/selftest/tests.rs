//! Regression tests for selftest.

use super::*;

#[test]
fn selftest_fixture_proves_recognizers() {
    run_selftest_inner().expect("sites selftest fixture should pass");
}
