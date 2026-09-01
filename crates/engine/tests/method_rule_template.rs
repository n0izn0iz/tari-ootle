//   Copyright 2026 The Tari Project
//   SPDX-License-Identifier: BSD-3-Clause

use tari_engine::runtime::{ActionIdent, RuntimeError};
use tari_ootle_transaction::args;
use tari_template_lib::types::{ComponentAddress, TemplateAddress};
use tari_template_test_tooling::{TemplateTest, support::assert_error::assert_reject_reason};

const CRATE_PATH: &str = env!("CARGO_MANIFEST_DIR");

/// A `rule!(template(addr))` method access rule allows callers from the template whose address is
/// `addr`, whether they are a component instance of that template or a static function of it.
///
/// The callee's `bar` method is gated with `rule!(template(caller_template))`. These tests invoke
/// `bar` from (1) a component of the caller template and (2) a static function of the caller
/// template, and assert both succeed.
#[test]
fn template_rule_on_method_allows_a_component_caller() {
    let mut test = TemplateTest::new(CRATE_PATH, [
        "tests/templates/template_rule_caller",
        "tests/templates/template_rule_callee",
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

    // A component of `caller_template` is allowed.
    test.execute_expect_success(
        test.transaction()
            .call_method(caller, "call_bar", args![callee])
            .build_and_seal(test.secret_key()),
        vec![test.owner_proof()],
    );
}

/// A static function of the gated template is allowed (its template matches the gate).
#[test]
fn template_rule_on_method_allows_a_static_function_caller() {
    let mut test = TemplateTest::new(CRATE_PATH, [
        "tests/templates/template_rule_caller",
        "tests/templates/template_rule_callee",
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

    // A static function of `caller_template` is allowed (its template matches the gate).
    test.execute_expect_success(
        test.transaction()
            .call_function(caller_template, "call_bar_static", args![callee])
            .build_and_seal(test.secret_key()),
        vec![test.owner_proof()],
    );
}

/// A caller from a different template must be denied.
#[test]
fn template_rule_on_method_denies_a_component_of_another_template() {
    let mut test = TemplateTest::new(CRATE_PATH, [
        "tests/templates/component_rule_caller",
        "tests/templates/template_rule_caller",
        "tests/templates/template_rule_callee",
    ]);

    // The callee's `bar` is gated on the `TemplateCaller` template.
    let caller_template: TemplateAddress = test.get_template_address("TemplateCaller");
    let callee: ComponentAddress = test.call_function("TemplateCallee", "new", args![caller_template], vec![
        test.owner_proof(),
    ]);

    // `Caller` belongs to a different template, so it must be denied.
    let intruder: ComponentAddress = test.call_function("Caller", "new", args![], vec![test.owner_proof()]);
    let reason = test.execute_expect_failure(
        test.transaction()
            .call_method(intruder, "call_bar", args![callee])
            .build_and_seal(test.secret_key()),
        vec![test.owner_proof()],
    );
    assert_reject_reason(reason, RuntimeError::AccessDenied {
        action_ident: ActionIdent::ComponentCallMethod {
            component_address: callee,
            method: "bar".to_string(),
        },
    });
}
