"""Tests for SECRET_ASSIGNMENT_PATTERNS: NAME=value credential redaction.

Covers the gap that let a bash command print `NAME=value` API keys straight
to stdout unredacted: SECRET_PATTERNS is prefix-anchored on known vendor
token shapes only, so a non-vendor-prefixed credential (a plain
`ACME_STAGING_API_KEY=...` assignment) passed through untouched even on
events that WERE scrubbed. These patterns close that gap by matching on the
assignment's NAME (segment-anchored, case-insensitive on the word only) and
masking ONLY the value, preserving the name.

All secret-shaped values below are assembled from fragments (never one
contiguous literal in source) so they can't be flagged by source-level
secret scanners / push-protection, while the runtime-assembled value still
matches the pattern exactly the same -- mirrors the existing convention in
tests/test_token_patterns.py.
"""

import re
import time

import pytest

from redaction import RedactionConfig
from redaction import Redactor
from redaction import mask_text
from redaction import secret_assignment_pattern

FAKE = "Zx9QpL" + "4mNvR2tYw8"  # 16 chars, no vendor prefix
SECRET = "[REDACTED:SECRET]"


class TestCodeAwareAssignments:
    """Independently authored public source examples; never execute their text."""

    COMPUTATIONS = (
        'key = json.dumps(payload, sort_keys=True, separators=(",", ":"))\n',
        'key = (record["major"], record["minor"])\n',
        "field_key = next(iter(mapping))\n",
        "{key: mapping[key] for key in reversed(mapping)}\n",
        "sorted(rows, key=operator.itemgetter(1))\n",
    )

    @staticmethod
    def numbered(text):
        return "".join(
            f"  {index}\t{line}"
            for index, line in enumerate(text.splitlines(keepends=True), 41)
        )

    @staticmethod
    def baseline(text):
        import redaction

        for pattern in redaction.SECRET_PATTERNS:
            text = pattern.sub(SECRET, text)
        for pattern in redaction.SECRET_ASSIGNMENT_PATTERNS:
            text = pattern.sub(redaction._mask_assignment, text)
        return text

    @pytest.mark.parametrize("text", COMPUTATIONS)
    @pytest.mark.parametrize("numbered", [False, True])
    def test_computations_exact(self, text, numbered):
        if numbered:
            text = self.numbered(text)
        assert mask_text(text, rules=("secrets",)) == text

    @pytest.mark.parametrize("name", ["password", "api_key", "key", "token"])
    @pytest.mark.parametrize("argument", ["tiny", "SyntheticBareValue"])
    @pytest.mark.parametrize("slot", ["{} = {}", "outer({}={})", "{{'{}': {}}}"])
    def test_simple_calls_stay_conservative(self, name, argument, slot):
        text = slot.format(name, f"identity({argument})")
        assert SECRET in mask_text(text, rules=("secrets",))
        assert "identity(" not in mask_text(text, rules=("secrets",))

    @pytest.mark.parametrize(
        "expression",
        [
            '"SyntheticOnlyValue"',
            "'SyntheticOnlyValue'",
            'identity("SyntheticOnlyValue")',
            'ns.identity("SyntheticOnlyValue")',
            'ns.identity(extra="SyntheticOnlyValue")',
            '"SyntheticOnlyValue" if flag else "SyntheticOtherValue"',
            '["SyntheticOnlyValue", {"x": ("SyntheticOtherValue",)}]',
            '("Synt" + ("heti" "cOnlyValue"))',
            '("Synt" "heticOnlyValue")',
            'r"SyntheticOnlyValue"',
            'b"SyntheticOnlyValue"',
            'f"SyntheticOnlyValue{item}"',
            '"""SyntheticOnlyValue"""',
            "'''SyntheticOnlyValue'''",
            'ns.identity(["SyntheticOnlyValue"], extra={"x": "SyntheticOtherValue"})',
        ],
    )
    def test_literal_obligations_even_without_relief(self, expression):
        text = "api_key = " + expression
        out = mask_text(text, rules=("secrets",))
        assert "SyntheticOnlyValue" not in out
        assert "SyntheticOtherValue" not in out
        assert '"Synt"' not in out
        assert '"heti"' not in out
        assert SECRET in out

    @pytest.mark.parametrize(
        "expression",
        [
            "ns.f(SyntheticBareValue)",
            "(rows[0], SyntheticBareValue)",
            "SyntheticBareValue if flag else SyntheticOtherValue",
            '{"x": SyntheticBareValue}',
            "next(iter(SyntheticBareValue))",
            'SyntheticBareValue["description"]',
        ],
    )
    def test_nested_data_names(self, expression):
        out = mask_text("key = " + expression, rules=("secrets",))
        assert "SyntheticBareValue" not in out
        assert "SyntheticOtherValue" not in out
        assert SECRET in out

    @pytest.mark.parametrize("outer", ["wrap", "module.wrap"])
    @pytest.mark.parametrize("quoted", [False, True])
    def test_independent_nested_slots(self, outer, quoted):
        value = '"SyntheticOnlyValue"' if quoted else "SyntheticOnlyValue"
        text = f"key = {outer}(token={value})"
        out = mask_text(text, rules=("secrets",))
        assert "SyntheticOnlyValue" not in out
        if outer == "module.wrap":
            assert out.endswith(")")
        assert SECRET in out

    def test_control_and_reference_roles(self):
        for text in (
            'key = enormous_module.enormous_function(rows["long lookup label"])\n',
            'key = rows["long lookup label"]\n',
            "key = rows[0] if long_condition else rows[1]\n",
            "{key: rows[key] for key in enormous_iterable if long_condition}\n",
        ):
            assert mask_text(text, rules=("secrets",)) == text

    def test_conditional_label_stays_masked(self):
        text = 'row_key = "description" if mode == "detail" else "id"\n'
        assert mask_text(text, rules=("secrets",)) == text.replace(
            "description", SECRET
        )

    def test_vendor_and_ordinary_assignments_in_selectors(self):
        vendor = "ghp_" + "SyntheticOnly123456"
        text = f'key = rows["{vendor}"]\n'
        assert mask_text(text, rules=("secrets",)) == text.replace(vendor, SECRET)
        text = 'key = rows["api_key=SyntheticOnlyValue"]\n'
        assert "SyntheticOnlyValue" not in mask_text(text, rules=("secrets",))

    @pytest.mark.parametrize(
        "text",
        [
            "# key = json.dumps(rows)\n",
            '"""key = json.dumps(rows)\nkey = next(iter(rows))\n"""\n',
            "'key = json.dumps(rows)'\n",
            '{"message": "key = json.dumps(rows)"}\n',
            "password: json.dumps(rows)\n",
            '"password": "SyntheticOnlyValue"\n',
            "[section]\nkey = identity(tiny)\n",
            "export key=json.dumps(rows)\n",
            "```python\nkey = json.dumps(rows)\n```\n",
            "~~~python\nkey = json.dumps(rows)\n~~~\n",
            '"""unfinished\nkey = json.dumps(rows)\n',
            "key = json.dumps(rows)\nunfinished = (\n",
            'message = """  41\\tkey = json.dumps(rows)\n"""\n',
        ],
    )
    def test_ordinary_or_malformed_regions_do_not_gain_relief(self, text):
        assert mask_text(text, rules=("secrets",)) == self.baseline(text)

    @pytest.mark.parametrize("suffix", ["**extra", "lambda: rows", "(x := rows)"])
    def test_unsupported_subtree_retains_whole_slot_baseline(self, suffix):
        text = f"key = module.build(rows, {suffix})\n"
        assert mask_text(text, rules=("secrets",)) == self.baseline(text)

    @pytest.mark.parametrize("numbered", [False, True])
    @pytest.mark.parametrize("ending", ["\n", "\r\n", ""])
    def test_unicode_tabs_and_original_mapping(self, numbered, ending):
        text = '\tlabel = "é"; api_key = ns.wrap("SyntheticOnlyValue")' + ending
        if numbered:
            text = self.numbered(text)
        expected = text.replace("SyntheticOnlyValue", SECRET)
        assert mask_text(text, rules=("secrets",)) == expected

    @pytest.mark.parametrize("numbered", [False, True])
    def test_multiline_literal_prefixes_and_crlf(self, numbered):
        text = 'key = ns.wrap("""Synthetic\r\nOnlyValue""")\r\n'
        expected = f'key = ns.wrap("""{SECRET}\r\n{SECRET}""")\r\n'
        if numbered:
            text, expected = self.numbered(text), self.numbered(expected)
        assert mask_text(text, rules=("secrets",)) == expected

    def test_indented_body_and_multiline_expression(self):
        text = (
            'def example():\n\tkey = json.dumps(\n\t\tpayload, separators=(",", ":"))\n'
        )
        assert mask_text(text, rules=("secrets",)) == text

    @pytest.mark.parametrize(
        "text",
        [
            "  41\tkey = json.dumps(rows)\n  43\tkey = next(iter(rows))\n",
            "  41\tkey = json.dumps(rows)\n  41\tkey = next(iter(rows))\n",
            "  41\tkey = json.dumps(rows)\nkey = next(iter(rows))\n",
        ],
    )
    def test_invalid_numbered_framing(self, text):
        assert mask_text(text, rules=("secrets",)) == self.baseline(text)

    @pytest.mark.parametrize(
        "limit",
        [
            "_SOURCE_MAX_CHARS",
            "_SOURCE_MAX_LINES",
            "_SOURCE_MAX_STATEMENT",
            "_SOURCE_MAX_TOKENS",
            "_SOURCE_MAX_NODES",
            "_SOURCE_MAX_DEPTH",
            "_SOURCE_BUDGET_SECONDS",
        ],
    )
    def test_limits_are_atomic_baseline(self, monkeypatch, limit):
        import redaction

        text = self.COMPUTATIONS[0] + 'api_key = ns.wrap("SyntheticOnlyValue")\n'
        monkeypatch.setattr(redaction, limit, 0)
        assert mask_text(text, rules=("secrets",)) == self.baseline(text)

    def test_late_internal_failure_is_atomic(self, monkeypatch):
        import redaction

        original = redaction.ast.parse
        calls = 0

        def fail_late(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise RuntimeError("synthetic injected planner failure")
            return original(*args, **kwargs)

        text = self.COMPUTATIONS[0] + self.COMPUTATIONS[2]
        monkeypatch.setattr(redaction.ast, "parse", fail_late)
        assert mask_text(text, rules=("secrets",)) == self.baseline(text)
        assert calls == 2

    def test_no_analysis_without_candidate(self, monkeypatch):
        import redaction

        def forbidden(*args, **kwargs):
            pytest.fail("unexpected source analysis")

        monkeypatch.setattr(redaction, "_python_assignment_plan", forbidden)
        for text in ("AUTHOR_" * 4000, "rows = json.dumps(payload)", "key"):
            assert mask_text(text, rules=("secrets",)) == text

    @pytest.mark.parametrize("form", ['"{}" "{}"', '"{}" + "{}"', '("{}" + ("{}"))'])
    def test_short_construction_masks_every_fragment(self, form):
        text = "api_key = " + form.format("abcd", "efgh")
        out = mask_text(text, rules=("secrets",))
        assert "abcd" not in out
        assert "efgh" not in out
        assert out.count(SECRET) == 2

    @pytest.mark.parametrize("raw", [r"a\\bcdef", r"ab\"cdef", r"\x41\x42"])
    def test_raw_payload_floor_does_not_decode(self, raw):
        text = f'api_key = ns.wrap("{raw}")\n'
        expected = text.replace(raw, SECRET) if len(raw) >= 8 else text
        assert mask_text(text, rules=("secrets",)) == expected

    @pytest.mark.parametrize("value", ["12345678", "2026-09-17"])
    def test_individual_numeric_date_literals_unchanged(self, value):
        text = f'key = ns.wrap("{value}")\n'
        assert mask_text(text, rules=("secrets",)) == text

    def test_exact_bare_keyword_value_clips_only_enclosing_punctuation(self):
        text = "module.wrap(token=SyntheticBareValue)\n"
        assert mask_text(text, rules=("secrets",)) == f"module.wrap(token={SECRET})\n"

    def test_all_assignment_forms_and_utf8_slots(self):
        text = (
            'é = "é"; obj.api_key = ns.wrap("SyntheticOnlyValue")\n'
            'api_key: str = ns.wrap("SyntheticOnlyValue")\n'
            'benign = api_key = ns.wrap("SyntheticOnlyValue")\n'
            'labels = {"api_key": ns.wrap("SyntheticOnlyValue")}\n'
        )
        out = mask_text(text, rules=("secrets",))
        assert "SyntheticOnlyValue" not in out
        assert out.startswith('é = "é"; obj.api_key = ns.wrap(')
        assert 'labels = {"api_key": ns.wrap(' in out

    @pytest.mark.parametrize("headroom", [0, 5, 100])
    def test_output_expansion_is_atomic_and_idempotent(self, monkeypatch, headroom):
        import redaction

        text = self.COMPUTATIONS[0] + 'password = ("abcd" "efgh")\n'
        monkeypatch.setattr(redaction, "_SOURCE_MAX_CHARS", len(text) + headroom)
        out = mask_text(text, rules=("secrets",))
        if headroom < 26:
            assert out == self.baseline(text)
        assert mask_text(out, rules=("secrets",)) == out

    def test_statement_output_expansion_uses_baseline(self, monkeypatch):
        import redaction

        text = 'api_key = ns.wrap("abcd" "efgh")\n'
        monkeypatch.setattr(redaction, "_SOURCE_MAX_STATEMENT", len(text))
        assert mask_text(text, rules=("secrets",)) == self.baseline(text)

    def test_markers_are_single_analysis_atoms_at_token_cap(self, monkeypatch):
        import redaction

        text = f"key = ns.wrap({SECRET})\n"
        import io
        import tokenize

        count = len(list(tokenize.generate_tokens(io.StringIO(text).readline)))
        monkeypatch.setattr(redaction, "_SOURCE_MAX_TOKENS", count - 4)
        assert mask_text(text, rules=("secrets",)) == text

    def test_api_parity_idempotence_and_custom_authority(self):
        from redaction import scrub

        text = (
            "".join(self.COMPUTATIONS)
            + 'password = "SyntheticOnlyValue"\n'
            + "outer(token=SyntheticBareValue)\n"
            + f"key = {SECRET}\n"
        )
        out = mask_text(text, rules=("secrets",))
        configured = Redactor(RedactionConfig(rules=("secrets",)))
        assert configured.mask_text(text) == out
        assert configured.scrub({"nested": [text]}) == {"nested": [out]}
        assert scrub({"nested": [text]}, rules=("secrets",)) == {"nested": [out]}
        assert mask_text(out, rules=("secrets",)) == out
        assert mask_text(text, rules=()) == text
        stricter = Redactor(
            RedactionConfig(
                extra_secret_assignment_patterns=(secret_assignment_pattern(["key"]),)
            )
        )
        assert SECRET in stricter.mask_text(self.COMPUTATIONS[0])
        vendor_stricter = Redactor(
            RedactionConfig(
                extra_secret_patterns=(re.compile(r"operator\.itemgetter"),)
            )
        )
        assert SECRET in vendor_stricter.mask_text(self.COMPUTATIONS[4])


class TestCodeAwareReviewCorrections:
    numbered = staticmethod(TestCodeAwareAssignments.numbered)
    baseline = staticmethod(TestCodeAwareAssignments.baseline)

    @pytest.mark.parametrize("numbered", [False, True])
    @pytest.mark.parametrize("ending", ["\n", "\r\n"])
    @pytest.mark.parametrize("trivia", ["comment", "continuation"])
    @pytest.mark.parametrize(
        "slot", ["assignment", "annotation", "keyword", "dictionary"]
    )
    @pytest.mark.parametrize("qualified", [False, True])
    def test_trivia_does_not_disable_literal_obligations(
        self, numbered, ending, trivia, slot, qualified
    ):
        payload = "PublicProbeValue2468"
        value = f'"{payload}"'
        if qualified:
            value = f"ns.wrap({value})"
        prefix = {
            "assignment": "api_key = ",
            "annotation": "api_key: str = ",
            "keyword": "module.wrap(api_key=",
            "dictionary": '{"api_key": ',
        }[slot]
        suffix = {"keyword": ")", "dictionary": "}"}.get(slot, "")
        if trivia == "comment":
            text = prefix + "( # public sample\n    " + value + "\n)" + suffix + "\n"
        else:
            text = prefix + "\\\n    " + value + suffix + "\n"
        text = text.replace("\n", ending)
        if numbered:
            text = self.numbered(text)
        expected = text.replace(payload, SECRET)
        assert mask_text(text, rules=("secrets",)) == expected
        assert mask_text(expected, rules=("secrets",)) == expected

    @pytest.mark.parametrize("numbered", [False, True])
    @pytest.mark.parametrize("prefix", ["r", "b", "u", "f", "fr", "rf"])
    @pytest.mark.parametrize(
        "payload,quote",
        [
            ("PublicProbeValue2468", '"'),
            (r"PublicProbe\"Value2468", '"'),
            (r"PublicProbe\\Value2468", '"'),
            ("PublicProbeValue2468", '"""'),
        ],
    )
    def test_verified_literal_prefix_is_preserved(
        self, numbered, prefix, payload, quote
    ):
        text = f"api_key = ns.wrap({prefix}{quote}{payload}{quote})\r\n"
        expected = text.replace(payload, SECRET)
        if numbered:
            text, expected = self.numbered(text), self.numbered(expected)
        redactor = Redactor(RedactionConfig(rules=("secrets",)))
        assert mask_text(text, rules=("secrets",)) == expected
        assert redactor.mask_text(text) == expected
        assert mask_text(expected, rules=("secrets",)) == expected
        assert redactor.mask_text(expected) == expected

    @pytest.mark.parametrize("prefix", ["f", "fr", "rf"])
    def test_complete_fstring_payload_masks_interpolation(self, prefix):
        text = f'api_key = ns.wrap({prefix}"PublicProbeValue2468{{item}}")\n'
        expected = f'api_key = ns.wrap({prefix}"{SECRET}")\n'
        assert mask_text(text, rules=("secrets",)) == expected
        assert mask_text(expected, rules=("secrets",)) == expected

    @pytest.mark.parametrize("prefix", ["r", "b", "u", "f", "fr", "rf"])
    def test_adjacent_prefixed_literal_parts_mask_exactly(self, prefix):
        text = f'api_key = ns.wrap({prefix}"abcd" {prefix}"efgh")\n'
        expected = f'api_key = ns.wrap({prefix}"{SECRET}" {prefix}"{SECRET}")\n'
        assert mask_text(text, rules=("secrets",)) == expected
        assert mask_text(expected, rules=("secrets",)) == expected

    def test_comment_assignments_still_mask(self):
        payload = "PublicProbeValue2468"
        text = f'api_key = ( # password={payload}\n ns.wrap("{payload}")\n)\n'
        expected = text.replace(payload, SECRET)
        assert mask_text(text, rules=("secrets",)) == expected
        assert mask_text(expected, rules=("secrets",)) == expected

    def test_trivia_does_not_enable_partial_unsupported_obligations(self):
        text = 'api_key = ( # public sample\n ns.wrap("PublicProbeValue2468", **extra)\n)\n'
        assert mask_text(text, rules=("secrets",)) == self.baseline(text)


class TestStatementBindings:
    @pytest.mark.parametrize("numbered", [False, True])
    @pytest.mark.parametrize("ending", ["\n", "\r\n"])
    def test_distinct_statement_coordinates_and_literals(self, numbered, ending):
        text = (
            'label = "λ"; api_key = ns.wrap(r"FreshBindingValue123")\n'
            "key = json.dumps(\n payload, sort_keys=True)\n"
            'obj.token = ns.wrap(("abcd" "efgh"))\n'
            'options = module.wrap(password=ns.wrap("FreshOtherValue456"))\n'
            'def local():\n\tkey = ns.wrap("FreshThirdValue789")\n'
        ).replace("\n", ending)
        expected = text
        for payload in (
            "FreshBindingValue123",
            "FreshOtherValue456",
            "FreshThirdValue789",
            "abcd",
            "efgh",
        ):
            expected = expected.replace(payload, SECRET)
        if numbered:
            text = TestCodeAwareAssignments.numbered(text)
            expected = TestCodeAwareAssignments.numbered(expected)
        assert mask_text(text, rules=("secrets",)) == expected
        assert mask_text(expected, rules=("secrets",)) == expected

    @pytest.mark.parametrize(
        "failure", [TypeError, MemoryError, RecursionError, RuntimeError]
    )
    def test_late_failure_keeps_atomic_silent_fallback(
        self, monkeypatch, capsys, caplog, failure
    ):
        import redaction

        text = 'key = json.dumps(payload)\napi_key = ns.wrap("FreshFaultValue123")\n'
        expected = TestCodeAwareAssignments.baseline(text)
        original = redaction.ast.parse
        calls = 0

        def fail_second(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise failure("FreshFaultValue123")
            return original(*args, **kwargs)

        monkeypatch.setattr(redaction.ast, "parse", fail_second)
        assert mask_text(text, rules=("secrets",)) == expected
        assert calls == 2
        captured = capsys.readouterr()
        assert "FreshFaultValue123" not in captured.out + captured.err + caplog.text


class TestMustMatch:
    """MUST MATCH: assert FAKE not in out and SECRET in out."""

    def test_m1_bare_assignment(self):
        out = mask_text(f"ACME_STAGING_API_KEY={FAKE}")
        assert FAKE not in out
        assert SECRET in out

    def test_m2_export_form(self):
        out = mask_text(f"export ACME_STAGING_API_KEY={FAKE}")
        assert FAKE not in out
        assert SECRET in out

    def test_m3_double_quoted_value(self):
        out = mask_text(f'ACME_API_KEY="{FAKE}"')
        assert FAKE not in out
        assert SECRET in out
        assert out == f'ACME_API_KEY="{SECRET}"'

    def test_m4_single_quoted_value(self):
        out = mask_text(f"ACME_API_KEY='{FAKE}'")
        assert FAKE not in out
        assert SECRET in out
        assert out == f"ACME_API_KEY='{SECRET}'"

    def test_m5_json_form(self):
        out = mask_text(f'"SOME_API_KEY": "{FAKE}"')
        assert FAKE not in out
        assert SECRET in out
        assert out == f'"SOME_API_KEY": "{SECRET}"'

    def test_m6_yaml_form(self):
        out = mask_text(f"api_key: {FAKE}")
        assert FAKE not in out
        assert SECRET in out

    def test_m7_camel_case_name(self):
        out = mask_text(f"apiKey={FAKE}")
        assert FAKE not in out
        assert SECRET in out

    def test_m8_camel_case_second_word(self):
        out = mask_text(f"authToken={FAKE}")
        assert FAKE not in out
        assert SECRET in out

    def test_m9_cli_flag_kebab_case(self):
        out = mask_text(f"--api-key={FAKE}")
        assert FAKE not in out
        assert SECRET in out

    def test_m10_password(self):
        out = mask_text(f"DB_PASSWORD={FAKE}")
        assert FAKE not in out
        assert SECRET in out

    def test_m11_pat_segment(self):
        out = mask_text(f"GITHUB_PAT={FAKE}")
        assert FAKE not in out
        assert SECRET in out

    def test_m12_multi_segment_name(self):
        out = mask_text(f"AWS_SECRET_ACCESS_KEY={FAKE}")
        assert FAKE not in out
        assert SECRET in out

    def test_m13_http_header_scheme_preserved(self):
        out = mask_text(f"Authorization: Bearer {FAKE}")
        assert FAKE not in out
        assert SECRET in out
        assert out == f"Authorization: Bearer {SECRET}"

    def test_m14_credentials(self):
        out = mask_text(f"MY_SERVICE_CREDENTIALS={FAKE}")
        assert FAKE not in out
        assert SECRET in out

    def test_m15_bare_lowercase_name(self):
        out = mask_text(f"passphrase={FAKE}")
        assert FAKE not in out
        assert SECRET in out

    def test_m16_auth_trailing_segment(self):
        out = mask_text(f"CONTEXT_AUTH={FAKE}")
        assert FAKE not in out
        assert SECRET in out


class TestAssignmentValueBoundaries:
    def test_lambda_source_survives_byte_identical(self):
        text = "ranked = sorted(rows, key=lambda item: (-item[1], item[0]))\n"
        assert mask_text(text) == text

    @pytest.mark.parametrize("delimiter", [" ", "\t", ",", ";", "'", '"', "\n", "\r\n"])
    def test_unquoted_value_stops_at_delimiter(self, delimiter):
        text = f"API_KEY={FAKE}{delimiter}ordinary output"
        assert mask_text(text) == f"API_KEY={SECRET}{delimiter}ordinary output"

    @pytest.mark.parametrize("delimiter", [" ", ",", ";"])
    def test_multiple_assignments_preserve_surroundings(self, delimiter):
        text = f"AUTH=none{delimiter}API_KEY={FAKE}{delimiter}TOKEN={FAKE} done"
        expected = f"AUTH=none{delimiter}API_KEY={SECRET}{delimiter}TOKEN={SECRET} done"
        assert mask_text(text) == expected

    @pytest.mark.parametrize("quote", ["'", '"'])
    def test_quoted_spaces_and_separators(self, quote):
        text = f"API_KEY={quote}{FAKE} with spaces,comma;semicolon{quote}, done"
        assert mask_text(text) == f"API_KEY={quote}{SECRET}{quote}, done"

    @pytest.mark.parametrize("quote,opposite", [("'", '"'), ('"', "'")])
    def test_opposite_quote_is_part_of_value(self, quote, opposite):
        text = f"API_KEY={quote}{FAKE}{opposite}credential tail{quote}; done"
        assert mask_text(text) == f"API_KEY={quote}{SECRET}{quote}; done"

    @pytest.mark.parametrize("quote", ["'", '"'])
    def test_escaped_matching_quote_keeps_credential_tail_masked(self, quote):
        text = f"API_KEY={quote}abc\\{quote}{FAKE}{quote}; done"
        assert mask_text(text) == f"API_KEY={quote}{SECRET}{quote}; done"

    @pytest.mark.parametrize("quote", ["'", '"'])
    def test_even_backslashes_do_not_escape_closing_quote(self, quote):
        text = f"API_KEY={quote}{FAKE}\\\\{quote}; ordinary output"
        assert mask_text(text) == f"API_KEY={quote}{SECRET}{quote}; ordinary output"

    @pytest.mark.parametrize("quote", ["'", '"'])
    @pytest.mark.parametrize("ending", ["", "\nordinary output", "\r\nordinary output"])
    @pytest.mark.parametrize("trailing_slash", ["", "\\"])
    def test_unterminated_quote_masks_to_line_end(self, quote, ending, trailing_slash):
        text = f"API_KEY={quote}{FAKE} with spaces,tail{trailing_slash}{ending}"
        assert mask_text(text) == f"API_KEY={quote}{SECRET}{ending}"

    @pytest.mark.parametrize("value", ["none", "include", "12345678", "2026-08-19"])
    @pytest.mark.parametrize("delimiter", [" ", ",", ";"])
    def test_short_numeric_and_date_values_do_not_absorb_suffix(self, value, delimiter):
        text = f"AUTH={value}{delimiter}ordinary output"
        assert mask_text(text, rules=("secrets",)) == text

    @pytest.mark.parametrize("quote", ["", "'", '"'])
    @pytest.mark.parametrize("length", [7, 8])
    def test_length_floor(self, quote, length):
        value = "x" * length
        text = f"KEY={quote}{value}{quote}, ordinary output"
        expected = value if length < 8 else SECRET
        assert mask_text(text) == f"KEY={quote}{expected}{quote}, ordinary output"

    @pytest.mark.parametrize("quote", ["'", '"'])
    @pytest.mark.parametrize(
        "value", ["a\\\\bcde", "a\\\\bcdef", "\\\\" * 3, "\\\\" * 4]
    )
    def test_quoted_length_floor_counts_raw_characters(self, quote, value):
        text = f"KEY={quote}{value}{quote}, ordinary output"
        expected = value if len(value) < 8 else SECRET
        assert mask_text(text) == f"KEY={quote}{expected}{quote}, ordinary output"

    @pytest.mark.parametrize("quote", ["'", '"'])
    @pytest.mark.parametrize("prefix", ["ab", "abc"])
    def test_escaped_quote_does_not_confuse_raw_length_floor(self, quote, prefix):
        value = f"{prefix}\\{quote}def"
        text = f"KEY={quote}{value}{quote}, ordinary output"
        expected = value if len(value) < 8 else SECRET
        assert mask_text(text) == f"KEY={quote}{expected}{quote}, ordinary output"

    def test_source_and_credentials_in_same_stdout(self):
        source = "ranked = sorted(rows, key=lambda item: (-item[1], item[0]))\n"
        vendor = "ghp_" + "SyntheticOnly123456"
        text = (
            source
            + f"API_KEY={FAKE} done\n"
            + f"options = dict(key='{FAKE}')\n"
            + f"example = '{vendor}'\n"
        )
        expected = (
            source
            + f"API_KEY={SECRET} done\n"
            + f"options = dict(key='{SECRET}')\n"
            + f"example = '{SECRET}'\n"
        )
        assert mask_text(text) == expected

    def test_bare_identifier_remains_ambiguous_and_maskable(self):
        """Retired masked assertion retained as inert history, not recovered.
        assert mask_text("sorted(rows, key=pick_rank)") == f"sorted(rows, key={SECRET}"

        """
        value = "AmbiguousBareValue123"
        text = f"module.wrap(token={value})"
        assert mask_text(text, rules=("secrets",)) == f"module.wrap(token={SECRET})"
        assert mask_text(f"token={value}", rules=("secrets",)) == f"token={SECRET}"

    @pytest.mark.parametrize("extend", [False, True])
    def test_boundaries_and_idempotence_with_extension(self, extend):
        redactor = Redactor(
            RedactionConfig(
                extra_secret_assignment_patterns=(
                    [secret_assignment_pattern(["personal"])] if extend else []
                )
            )
        )
        name = "PERSONAL" if extend else "KEY"
        source = "sorted(rows, key=lambda item: (-item[1], item[0]))"
        text = f"{source}\n{name}={FAKE} done\n{name}='{FAKE} with spaces'"
        expected = f"{source}\n{name}={SECRET} done\n{name}='{SECRET}'"
        assert redactor.mask_text(text) == expected
        assert redactor.mask_text(expected) == expected


class TestMustNotMatch:
    """MUST NOT MATCH: assert mask_text(x) == x, byte-identical."""

    def test_n1_path_not_pat_segment(self):
        text = "PATH=/usr/local/bin:/usr/bin:/bin"
        assert mask_text(text) == text

    def test_n2_home_no_sensitive_segment(self):
        text = "HOME=/home/someuser"
        assert mask_text(text) == text

    def test_n3_monkey_key_is_substring_not_segment(self):
        text = "MONKEY=abcdefghij"
        assert mask_text(text) == text

    def test_n4_monkey_mixed_case(self):
        text = "Monkey=abcdefghij"
        assert mask_text(text) == text

    def test_n5_keyboard_requires_trailing_delimiter(self):
        text = "KEYBOARD=abcdefghij"
        assert mask_text(text) == text

    def test_n6_author_is_auth_prefix(self):
        text = "AUTHOR=somebodyelse"
        assert mask_text(text) == text

    def test_n7_author_name_full_segment(self):
        text = "AUTHOR_NAME=somebodyelse"
        assert mask_text(text) == text

    def test_n8_max_tokens_plural_absent(self):
        text = "MAX_TOKENS=4096"
        assert mask_text(text) == text

    def test_n9_max_tokens_lowercase_colon(self):
        text = "max_tokens: 128000"
        assert mask_text(text) == text

    def test_n10_prompt_tokens_llm_telemetry(self):
        text = "prompt_tokens: 45231"
        assert mask_text(text) == text

    def test_n11_token_limit_numeric_value_guard(self):
        text = "TOKEN_LIMIT=80000000"
        assert mask_text(text) == text

    def test_n12_dashless_uuid(self):
        text = "id=550e8400e29b41d4a716446655440000"
        assert mask_text(text) == text

    def test_n13_git_sha_under_benign_name(self):
        text = "commit=9f2c1ab4d5e6f7081923a4b5c6d7e8f90a1b2c3d4"
        assert mask_text(text) == text

    def test_n14_credentials_include_under_length_floor(self):
        text = "credentials=include"
        assert mask_text(text) == text

    def test_n15_datetime_shape_guard(self):
        text = "AUTH_EXPIRES_AT=2026-08-19T12:00:00Z"
        assert mask_text(text) == text

    def test_n16_ls_colors_no_sensitive_segment(self):
        text = "LS_COLORS=rs=0:di=01;34:ln=01;36"
        assert mask_text(text) == text

    def test_n17_base64_under_benign_name(self):
        text = "data: QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5"
        assert mask_text(text) == text

    def test_n18_use_auth_short_boolean(self):
        text = "USE_AUTH=true"
        assert mask_text(text) == text

    def test_n19_auth_short_keyword(self):
        text = "AUTH=none"
        assert mask_text(text) == text

    def test_n20_digest_under_benign_name(self):
        text = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert mask_text(text) == text


M_VECTORS = [
    f"ACME_STAGING_API_KEY={FAKE}",
    f"export ACME_STAGING_API_KEY={FAKE}",
    f'ACME_API_KEY="{FAKE}"',
    f"ACME_API_KEY='{FAKE}'",
    f'"SOME_API_KEY": "{FAKE}"',
    f"api_key: {FAKE}",
    f"apiKey={FAKE}",
    f"authToken={FAKE}",
    f"--api-key={FAKE}",
    f"DB_PASSWORD={FAKE}",
    f"GITHUB_PAT={FAKE}",
    f"AWS_SECRET_ACCESS_KEY={FAKE}",
    f"Authorization: Bearer {FAKE}",
    f"MY_SERVICE_CREDENTIALS={FAKE}",
    f"passphrase={FAKE}",
    f"CONTEXT_AUTH={FAKE}",
]


class TestAdditionalRequired:
    def test_t_idem(self):
        """Every M1-M16 must be idempotent."""
        for text in M_VECTORS:
            once = mask_text(text)
            twice = mask_text(once)
            assert twice == once, f"not idempotent: {text!r} -> {once!r} -> {twice!r}"

    def test_t_gate_off(self):
        """New patterns are gated by the `secrets` rule."""
        out = mask_text(f"API_KEY={FAKE}", rules=("pii-basic",))
        assert SECRET not in out

    def test_t_gate_none(self):
        text = f"API_KEY={FAKE}"
        assert mask_text(text, rules=()) == text

    def test_t_ext_closure_path(self):
        """RedactionConfig.extra_secret_assignment_patterns closes the name-gap."""
        redactor = Redactor(
            RedactionConfig(
                extra_secret_assignment_patterns=[
                    secret_assignment_pattern(["personal"]),
                ]
            )
        )
        out = redactor.mask_text("MY_SVC_PERSONAL=" + FAKE)
        assert FAKE not in out
        assert SECRET in out

        # Bare mask_text (no extension) does not mask it -- proves the
        # extension, not some other rule, did the masking above.
        bare = mask_text("MY_SVC_PERSONAL=" + FAKE)
        assert FAKE in bare

    def test_t_name_gap_regression_lock(self):
        """Explicit regression lock on the accepted limitation (\u00a74.4): the
        default vocabulary is name-anchored, so a credential variable whose
        name carries no conventional sensitive word is NOT matched by
        default. If someone later adds an entropy rule, this test fails and
        forces the \u00a73.4 conversation (value-entropy rules are closed off by
        the dashless-UUID / git-SHA tests above)."""
        text = "MY_SERVICE_PERSONAL=" + FAKE
        assert mask_text(text) == text

    def test_t_perf(self):
        """The assignment pattern alone must stay linear -- deliberately using
        `secrets` only, not the default rules, since PII_PATTERNS[0] (the
        email regex) has a pre-existing, out-of-scope quadratic on this exact
        input (see AGENTS.md / design doc \u00a73.5). Testing with default rules
        would make this a test of someone else's bug."""
        text = "AUTHOR_" * 4000 + "X"
        start = time.monotonic()
        mask_text(text, rules=("secrets",))
        elapsed = time.monotonic() - start
        assert elapsed < 0.05, (
            f"assignment pattern took {elapsed * 1000:.1f}ms, expected < 50ms"
        )


class TestAcceptedFalsePositives:
    """\u00a74.4: these ARE masked, deliberately -- a path-shaped-value exclusion
    or a benign-literal denylist was considered and rejected (see design doc).
    Masking-when-in-doubt is the correct direction for a security bundle."""

    def test_ssh_auth_sock(self):
        out = mask_text("SSH_AUTH_SOCK=/tmp/ssh-ABC123/agent.4567")
        assert SECRET in out

    def test_google_application_credentials(self):
        out = mask_text("GOOGLE_APPLICATION_CREDENTIALS=/etc/gcp/sa.json")
        assert SECRET in out

    def test_auth_mode_disabled(self):
        out = mask_text("AUTH_MODE=disabled")
        assert SECRET in out

    def test_public_key(self):
        out = mask_text("PUBLIC_KEY=ssh-rsa-AAAAB3NzaC1yc2E")
        assert SECRET in out


class TestSecretAssignmentPatternHelper:
    """Direct coverage of the exported `secret_assignment_pattern()` builder."""

    def test_builds_a_compiled_pattern(self):
        pat = secret_assignment_pattern(["widget"])
        assert isinstance(pat, re.Pattern)

    def test_never_applies_global_ignorecase(self):
        """\u00a74.3 rule 2 footgun: case-insensitivity must be scoped to the word
        group only. A global re.IGNORECASE would let `monkey=` start matching
        via the camelCase guard. Guarded by asserting the compiled pattern
        carries no global IGNORECASE flag."""
        pat = secret_assignment_pattern(["widget"])
        assert not (pat.flags & re.IGNORECASE)
