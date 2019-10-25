from pyparsing import Word, alphas, Keyword, Optional, Or, ParseException, Group, Suppress, ZeroOrMore, Combine, OneOrMore

from .alerts import Alert

class Parser:
    FINDINGS_IDENTIFIER = Word(alphas+"-")

    @classmethod
    def parse(cls, string):
        return cls.FULL_EXPR.parseString(string)

class UseParser(Parser):
    GROUP = Group(Parser.FINDINGS_IDENTIFIER('subject')('key'))
    FULL_EXPR = Suppress(Keyword('use')) - GROUP - ZeroOrMore(Suppress(Keyword('and')) - GROUP)
    
class FindParser(Parser):
    FULL_EXPR = Parser.FINDINGS_IDENTIFIER('subject') - Optional(Keyword('as') - Parser.FINDINGS_IDENTIFIER('alias'))

    @classmethod
    def parse_find_mapping(cls, list_of_find_strings):
        mapping = {}
        for fstring in list_of_find_strings:
            res = cls.parse(fstring)
            subject = res.get('subject')
            alias = res.get('alias', subject)
            if subject in mapping:
                raise Exception(f"Duplicate find expression for {subject}.")
            mapping[subject] = alias
        return mapping
            

class ExpectParser(Parser):
    QUANTIFIER = Keyword('no') ^ Keyword('some')
    QUANTIFIER_WITH_ALL = QUANTIFIER ^ Keyword('all')

    DEFAULT_EXPR = QUANTIFIER('quantifier') - Optional(Keyword("new")("new")) - Parser.FINDINGS_IDENTIFIER("subject")

    IN_EXPR = QUANTIFIER_WITH_ALL('quantifier') - Parser.FINDINGS_IDENTIFIER("list1") - Keyword('in')('in') - Parser.FINDINGS_IDENTIFIER("list2")
    
    ALERT_SUBEXPR = Optional(",")  - Keyword("otherwise") - Keyword("alert") - OneOrMore(Word(alphas))("alert_action_args")
    

    FULL_EXPR = (DEFAULT_EXPR("default_expr") ^ IN_EXPR("in_expr")) - ALERT_SUBEXPR

    @classmethod
    def parse_expect(cls, expect_rules):
        expect_fns = []
        for rule in expect_rules:
            parsed = cls.parse(rule)
            alert_severity = Alert.Severity.parse(' '.join(parsed.alert_action_args))
            if parsed.get('in', False):
                expect_fns.append(cls.get_function_in_expr(rule, parsed.quantifier, parsed.list1, parsed.list2, alert_severity))
            else:
                expect_fns.append(cls.get_function_default_expr(rule, parsed.quantifier, parsed.new, parsed.subject, alert_severity))
        return expect_fns

    @classmethod
    def get_function_in_expr(cls, rule, quantifier, list1, list2, severity):
        def expect_fn(step):
            common_items, missing_items = step.findings.get_common_and_missing_items(list1, list2)
            
            if quantifier == 'no' and common_items:
                yield Alert(
                    severity=severity,
                    violated_rule=rule,
                    findings={'extra items': items_from_1_in_2},
                    step=step
                )
                
            elif quantifier == 'some' and not common_items:
                yield Alert(
                    severity=severity,
                    violated_rule=rule,
                    findings={},
                    step=step
                )
            elif quantifier == 'all' and missing_items:
                yield Alert(
                    severity=severity,
                    violated_rule=rule,
                    findings={'missing items': missing_items},
                    step=step
                )
        expect_fn.required_fields = [list1, list2]
        expect_fn.rule = rule
        return expect_fn

    @classmethod
    def get_function_default_expr(cls, rule, quantifier, new, subject, severity):
        def expect_fn(step):
            if new:
                items = step.findings.get_added_items(subject)
            else:
                items = step.findings.get(subject)

            if quantifier == 'no' and items:
                yield Alert(
                    severity=severity,
                    violated_rule=rule,
                    findings={'extra items': items},
                    step=step
                )
            elif quantifier == 'some' and not items:
                yield Alert(
                    severity=severity,
                    violated_rule=rule,
                    findings={},
                    step=step
                )
        expect_fn.required_fields = [subject]
        expect_fn.rule = rule
        return expect_fn
