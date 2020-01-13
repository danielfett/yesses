"""A number of functions that generate functions that compare
elements in the global findings list and the module output.

These functions are used by the expect function parser.

"""

from .alerts import Alert


def get_function_equals_expr(rule, quantifier, list1, list2, severity):
    def expect_fn(step):
        _, extra1, equals = step.findings.get_common_and_missing_items(list1, list2)
        if (quantifier == "not") == equals:
            findings = {}
            if len(extra1):
                findings[f"extra items in {list1}"] = extra1

            _, extra2, _ = step.findings.get_common_and_missing_items(list2, list1)
            if len(extra2):
                findings[f"extra items in {list2}"] = extra2

            yield Alert(
                severity=severity, violated_rule=rule, findings=findings, step=step
            )

    return expect_fn


def get_function_in_expr(rule, quantifier, list1, list2, severity):
    def expect_fn(step):
        common_items, missing_items, _ = step.findings.get_common_and_missing_items(
            list1, list2
        )

        if quantifier == "no" and common_items:
            yield Alert(
                severity=severity,
                violated_rule=rule,
                findings={"extra items": items_from_1_in_2},
                step=step,
            )

        elif quantifier == "some" and not common_items:
            yield Alert(severity=severity, violated_rule=rule, findings={}, step=step)
        elif quantifier == "all" and missing_items:
            yield Alert(
                severity=severity,
                violated_rule=rule,
                findings={"missing items": missing_items},
                step=step,
            )

    return expect_fn


def get_function_default_expr(rule, quantifier, new, subject, severity):
    def expect_fn(step):
        if new:
            items = step.findings.get_added_items(subject)
        else:
            items = step.findings.get(subject)

        if quantifier == "no" and items:
            yield Alert(
                severity=severity,
                violated_rule=rule,
                findings={"extra items": items},
                step=step,
            )
        elif quantifier == "some" and not items:
            yield Alert(severity=severity, violated_rule=rule, findings={}, step=step)

    return expect_fn
