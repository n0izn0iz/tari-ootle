//   Copyright 2026 The Tari Project
//   SPDX-License-Identifier: BSD-3-Clause

use tari_ootle_transaction::args;
use tari_template_lib::types::{ComponentAddress, TemplateAddress};
use tari_template_test_tooling::TemplateTest;

const CRATE_PATH: &str = env!("CARGO_MANIFEST_DIR");

/// Regression test for the `template(addr)` access-rule bug on *component method* rules.
///
/// The callee's `bar` method is configured with `rule!(template(caller_template))`, documented as
/// "only callable from this template". We perform the call from two kinds of callers, both belonging to
/// `caller_template`:
///
/// 1. a **component** of that template (`TemplateCaller::call_bar`), and
/// 2. a **static function** of that template (`TemplateCaller::call_bar_static`).
///
/// Per the engine implementation both are currently *denied*: the `ScopedToTemplate` rule is compared against
/// the callee's own template (the top call frame), never the caller's. Both tests assert the documented behavior
/// (the caller is allowed), so they currently FAIL and should pass once the engine evaluates the rule against the
/// caller.
#[test]
fn template_rule_on_method_is_checked_against_the_callee_not_the_caller() {
    let mut test = TemplateTest::new(CRATE_PATH, [
        "tests/templates/repro_template_caller",
        "tests/templates/repro_template_callee",
    ]);

    // Create the caller component, then the callee gated on the caller's *template* address.
    let caller: ComponentAddress = test.call_function("TemplateCaller", "new", args![], vec![test.owner_proof()]);
    let caller_template: TemplateAddress = test.get_template_address("TemplateCaller");
    let callee: ComponentAddress = test.call_function("TemplateCallee", "new", args![caller_template], vec![
        test.owner_proof(),
    ]);

    // Control: the caller component can invoke the callee's unrestricted method cross-component.
    let cross_ping: u64 = test.call_method(caller, "call_ping", args![callee], vec![test.owner_proof()]);
    assert_eq!(cross_ping, 42);

    // Expected: a component of `caller_template` is allowed.
    // Currently fails: the engine compares the rule against the callee, not the caller.
    test.execute_expect_success(
        test.transaction()
            .call_method(caller, "call_bar", args![callee])
            .build_and_seal(test.secret_key()),
        vec![test.owner_proof()],
    );
}

#[test]
fn template_rule_on_method_from_static_function_is_checked_against_the_callee_not_the_caller() {
    let mut test = TemplateTest::new(CRATE_PATH, [
        "tests/templates/repro_template_caller",
        "tests/templates/repro_template_callee",
    ]);

    // Gate the callee's `bar` on the caller's *template* address.
    let caller_template: TemplateAddress = test.get_template_address("TemplateCaller");
    let callee: ComponentAddress = test.call_function("TemplateCallee", "new", args![caller_template], vec![
        test.owner_proof(),
    ]);

    // Control: a static function of `caller_template` can invoke the callee's unrestricted method.
    let cross_ping: u64 = test.call_function("TemplateCaller", "call_ping_static", args![callee], vec![
        test.owner_proof(),
    ]);
    assert_eq!(cross_ping, 42);

    // Expected: a static function of `caller_template` is allowed (its template matches the gate).
    // Currently fails: the engine compares the rule against the callee, not the caller.
    test.execute_expect_success(
        test.transaction()
            .call_function(caller_template, "call_bar_static", args![callee])
            .build_and_seal(test.secret_key()),
        vec![test.owner_proof()],
    );
}
