//   Copyright 2026 The Tari Project
//   SPDX-License-Identifier: BSD-3-Clause

use tari_ootle_transaction::args;
use tari_template_lib::types::ComponentAddress;
use tari_template_test_tooling::TemplateTest;

const CRATE_PATH: &str = env!("CARGO_MANIFEST_DIR");

/// A `rule!(component(addr))` method access rule allows the component whose address is `addr` to
/// invoke the method.
///
/// The callee's `bar` method is gated with `rule!(component(caller_address))`. This test invokes
/// `bar` from exactly that caller component and asserts the call succeeds.
#[test]
fn component_rule_on_method_allows_the_caller() {
    let mut test = TemplateTest::new(CRATE_PATH, [
        "tests/templates/component_rule_caller",
        "tests/templates/component_rule_callee",
    ]);

    // Create the caller component, then the callee gated on the caller's address.
    let caller: ComponentAddress = test.call_function("Caller", "new", args![], vec![test.owner_proof()]);
    let callee: ComponentAddress = test.call_function("Callee", "new", args![caller], vec![test.owner_proof()]);

    // Control: the caller can invoke the callee's unrestricted method cross-component.
    let cross_ping: u64 = test.call_method(caller, "call_ping", args![callee], vec![test.owner_proof()]);
    assert_eq!(cross_ping, 42);

    // The caller is allowed because `bar` is restricted to exactly this caller's address.
    test.execute_expect_success(
        test.transaction()
            .call_method(caller, "call_bar", args![callee])
            .build_and_seal(test.secret_key()),
        vec![test.owner_proof()],
    );
}
