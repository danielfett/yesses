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

    EQUALS_EXPR = Parser.FINDINGS_IDENTIFIER("list1") - Optional(Keyword("not")("quantifier")) - Keyword('equals')('equals') - Parser.FINDINGS_IDENTIFIER("list2")
    
    ALERT_SUBEXPR = Optional(",")  - Keyword("otherwise") - Keyword("alert") - OneOrMore(Word(alphas))("alert_action_args")
    

    FULL_EXPR = (DEFAULT_EXPR("default_expr") ^ IN_EXPR("in_expr") ^ EQUALS_EXPR("equals_expr")) - ALERT_SUBEXPR

    @classmethod
    def parse_expect(cls, expect_rules):
        expect_fns = []
        for rule in expect_rules:
            parsed = cls.parse(rule)
            alert_severity = Alert.Severity.parse(' '.join(parsed.alert_action_args))
            if parsed.get('in_expr', False):
                expect_fns.append(cls.get_function_in_expr(rule, parsed.quantifier, parsed.list1, parsed.list2, alert_severity))
            elif parsed.get('equals_expr', False):
                expect_fns.append(cls.get_function_equals_expr(rule, parsed.list1, parsed.list2, alert_severity))
            else:
                expect_fns.append(cls.get_function_default_expr(rule, parsed.quantifier, parsed.new, parsed.subject, alert_severity))
        return expect_fns

    @classmethod
    def get_function_equals_expr(cls, rule, list1, list2, severity):
        def expect_fn(step):
            _, extra1, equals = step.findings.get_common_and_missing_items(list1, list2)
            if (quantifier != 'no') == equals:
                findings = {}
                if len(extra1):
                    findings[f'extra items in {list1}'] = extra1
                
                _, extra2, _ = step.findings.get_common_and_missing_items(list2, list1)
                if len(extra2):
                    findings[f'extra items in {list2}'] = extra2
                    
                yield Alert(
                    severity=severity,
                    violated_rule=rule,
                    findings=findings,
                    step=step
                )    
        return expect_fn
        

    @classmethod
    def get_function_in_expr(cls, rule, quantifier, list1, list2, severity):
        def expect_fn(step):
            common_items, missing_items, _ = step.findings.get_common_and_missing_items(list1, list2)
            
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
        return expect_fn
