//   Copyright 2026 The Tari Project
//   SPDX-License-Identifier: BSD-3-Clause

use tari_engine::runtime::{ActionIdent, RuntimeError};
use tari_ootle_transaction::args;
use tari_template_lib::types::{ComponentAddress, TemplateAddress};
use tari_template_test_tooling::{TemplateTest, support::assert_error::assert_reject_reason};

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

/// A component whose address is not the gated address must be denied.
#[test]
fn component_rule_on_method_denies_an_unrelated_component() {
    let mut test = TemplateTest::new(CRATE_PATH, [
        "tests/templates/component_rule_caller",
        "tests/templates/component_rule_callee",
    ]);

    // Two distinct caller components; the callee is gated on only the first.
    let allowed: ComponentAddress = test.call_function("Caller", "new", args![], vec![test.owner_proof()]);
    let intruder: ComponentAddress = test.call_function("Caller", "new", args![], vec![test.owner_proof()]);
    let callee: ComponentAddress = test.call_function("Callee", "new", args![allowed], vec![test.owner_proof()]);

    // Sanity: the allowed caller can invoke `bar`.
    test.execute_expect_success(
        test.transaction()
            .call_method(allowed, "call_bar", args![callee])
            .build_and_seal(test.secret_key()),
        vec![test.owner_proof()],
    );

    // The intruder is a different component instance, so it must be denied.
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

/// A static function has no component identity, so it must never satisfy `rule!(component(addr))`.
#[test]
fn component_rule_on_method_denies_a_static_function() {
    let mut test = TemplateTest::new(CRATE_PATH, [
        "tests/templates/component_rule_callee",
        "tests/templates/template_rule_caller",
    ]);

    // A concrete component address is used as the gate; the static caller still has no component to match.
    let gate: ComponentAddress = test.call_function("TemplateCaller", "new", args![], vec![test.owner_proof()]);
    let callee: ComponentAddress = test.call_function("Callee", "new", args![gate], vec![test.owner_proof()]);

    let caller_template: TemplateAddress = test.get_template_address("TemplateCaller");
    let reason = test.execute_expect_failure(
        test.transaction()
            .call_function(caller_template, "call_bar_static", args![callee])
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

/// A method gated on the component's own address is still restricted to that component: an intruder
/// (a different component) must be denied, rather than the gate matching every caller.
#[test]
fn component_rule_on_method_denies_an_intruder_when_gated_on_own_address() {
    let mut test = TemplateTest::new(CRATE_PATH, [
        "tests/templates/component_rule_caller",
        "tests/templates/component_rule_callee",
    ]);

    let callee: ComponentAddress = test.call_function("Callee", "new_self_gated", args![], vec![test.owner_proof()]);
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
