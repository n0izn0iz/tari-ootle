//   Copyright 2026 The Tari Project
//   SPDX-License-Identifier: BSD-3-Clause

use tari_ootle_transaction::args;
use tari_template_lib::types::ComponentAddress;
use tari_template_test_tooling::TemplateTest;

const CRATE_PATH: &str = env!("CARGO_MANIFEST_DIR");

/// Regression test for the `component(addr)` access-rule bug on *component method* rules.
///
/// The callee's `bar` method is configured with `rule!(component(caller_address))`, documented as
/// "only callable from this component". We then perform the call from exactly that caller component.
/// Per the engine implementation this is currently *denied*: the `ScopedToComponent` rule is compared
/// against the callee's own address (the top call frame), never the caller's.
///
/// This test asserts the documented behavior (the caller is allowed), so it currently FAILS. It should
/// pass once the engine evaluates the rule against the caller.
#[test]
fn component_rule_on_method_is_checked_against_the_callee_not_the_caller() {
    let mut test = TemplateTest::new(
        CRATE_PATH,
        ["tests/templates/repro_caller", "tests/templates/repro_callee"],
    );

    // Create the caller component, then the callee gated on the caller's address.
    let caller: ComponentAddress = test.call_function("Caller", "new", args![], vec![test.owner_proof()]);
    let callee: ComponentAddress = test.call_function("Callee", "new", args![caller], vec![test.owner_proof()]);

    // Control: the caller can invoke the callee's unrestricted method cross-component.
    let cross_ping: u64 = test.call_method(caller, "call_ping", args![callee], vec![test.owner_proof()]);
    assert_eq!(cross_ping, 42);

    // Expected: the caller is allowed because `bar` is restricted to exactly this caller's address.
    // Currently fails: the engine compares the rule against the callee, not the caller.
    test.execute_expect_success(
        test.transaction()
            .call_method(caller, "call_bar", args![callee])
            .build_and_seal(test.secret_key()),
        vec![test.owner_proof()],
    );
}
