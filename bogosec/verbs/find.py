from bogosec.utils import clean_expression

def find(step_contents, temp_findings, final_findings):
    for finding_key_or_key_with_alias in step_contents:
        finding_key_or_key_with_alias = clean_expression(finding_key_or_key_with_alias)
        if ' as ' in finding_key_or_key_with_alias:
            finding_key, alias_key = finding_key_or_key_with_alias.split(' as ')
        else:
            alias_key = finding_key_or_key_with_alias
            finding_key = finding_key_or_key_with_alias
            
        if not finding_key in temp_findings:
            raise Exception(f"Did not find key {finding_key} in output of {action}.")

        final_findings.set(alias_key, temp_findings[finding_key])
