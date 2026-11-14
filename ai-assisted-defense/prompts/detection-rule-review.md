# Prompt: detection rule review

Use this for a second review of a new or changed rule before it goes to `experimental`.

```text
Review the detection rule below as a senior detection engineer.

<rule format="{sigma|yara|yara-l|spl}">
{rule_text}
</rule>

<environment>
Log sources available: {log_sources}
Known noisy software: {noisy_software}
</environment>

Report:
1. Intent: in one sentence, what behavior this rule actually detects (which
   may differ from its title).
2. Bypasses: concrete ways an attacker doing the same thing would avoid a
   match (renamed binary, different parent, encoding, alternative tool),
   ranked by how likely they are.
3. False positives: concrete benign activity that would match, given the
   environment above.
4. Logic errors: wrong field names for the log source, case-sensitivity
   problems, operator precedence, overly broad wildcards.
5. Suggested revision: a corrected rule, with each change explained in one
   line.
6. Test cases: one command or event that should match and one that should not.

Only suggest field names that exist for the stated log source. If you are
not sure a field exists, say so.
```

Every suggested revision still goes through the [detection engineering lifecycle](../../soc-operations/detection-engineering-lifecycle.md): CI validation, a positive test, and a negative test over production data.
