import re

import pytest

from tie.bench import binaries, carriers, strategies
from tie.bench.build import build_binary, build_core, build_gray, build_split, make_sample

ALLOWED_REAL_HOSTS = {
    "api.telegram.org",
    "index.crates.io",
    "api.openai.com",
    "huggingface.co",
    "contoso.example",
    "mx.contoso.example",
    "mail.contoso.example",
}


@pytest.fixture(scope="module")
def test_split():
    return build_split("test")


def test_split_sizes(test_split):
    mal_carriers = [c for c in carriers.ALL_CARRIERS if c.label == "malicious"]
    injected = [s for s in test_split if s.injection]
    assert len(injected) == 28 * len(mal_carriers)
    assert len([s for s in test_split if not s.injection]) == len(carriers.ALL_CARRIERS)
    assert len(build_core()) == 105
    assert len(build_binary()) == 18
    assert len(build_gray()) == 4


def test_ids_unique(test_split):
    ids = [s.id for s in test_split]
    assert len(ids) == len(set(ids))


def test_deterministic():
    a = build_split("test")
    b = build_split("test")
    assert [s.files for s in a] == [s.files for s in b]


def test_spans_point_at_payload(test_split):
    for s in test_split:
        if not s.injection or s.injection.obfuscation != "none":
            continue
        assert s.injection.spans, s.id
        span = s.injection.spans[0]
        body = s.files[span["file"]][span["start"] : span["end"]]
        # some distinctive word of the payload must be inside the span
        words = [w for w in re.findall(r"[A-Za-z]{6,}", s.injection.text)][:3]
        assert any(w in body for w in words), s.id


def test_clean_sample_has_no_markers(test_split):
    for s in test_split:
        for body in s.files.values():
            assert "@@SLOT" not in body


def test_attacker_infrastructure_is_reserved(test_split):
    """Every hostname in malicious artifacts is reserved (.invalid / .example) or a known public service."""
    host_rx = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|ru|cn|xyz|top|invalid|example)\b", re.I)
    for s in test_split:
        if s.label != "malicious":
            continue
        for body in s.files.values():
            for m in host_rx.finditer(body):
                host = m.group(0).lower()
                assert host.endswith((".invalid", ".example")) or host in ALLOWED_REAL_HOSTS, (s.id, host)


def test_ip_addresses_are_documentation_ranges(test_split):
    for s in test_split:
        for body in s.files.values():
            for ip in re.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}\b", body):
                assert ip in ("192.0.2", "198.51.100", "203.0.113"), (s.id, ip)


def test_refusal_bait_only_claims_restricted_content():
    for t in strategies.STRATEGIES["refusal_bait"].templates:
        assert re.search(r"\[(REDACTED|withheld|omitted)", t.text), t.id


def test_every_strategy_has_dev_and_test_templates():
    for name, st in strategies.STRATEGIES.items():
        fams = {t.family for t in st.templates}
        assert fams == {"dev", "test"}, name


def test_binary_sources_compile_and_are_gated(tmp_path):
    if not (binaries.shutil.which("gcc") or binaries.shutil.which("cc")):
        pytest.skip("no C compiler")
    for s in build_binary()[:3]:
        src = s.binary_source
        # every system()/fopen() side effect sits behind the never-set g_armed flag
        for line in src.splitlines():
            if "system(" in line and "static" not in line and "int system" not in line:
                assert "g_armed" in line or "if (g_armed)" in src, line
        elf = binaries.build(src, tmp_path)
        assert elf.exists() and elf.stat().st_size > 1000


def test_carrier_render_without_insertions_is_stable():
    import random

    for c in carriers.ALL_CARRIERS:
        files, spans = carriers.render(c, {}, random.Random(0))
        assert not spans
        assert make_sample(c, None, None).files == files
