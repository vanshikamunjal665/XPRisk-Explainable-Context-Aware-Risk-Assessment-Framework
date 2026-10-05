"""Guards for the claims made in ``docs/api.md`` and ``docs/architecture.md``.

Why this file exists
--------------------
Those two documents state numbers and name specific tests. A number in prose is
the easiest kind of claim to let rot: the code changes, the document does not, and
nothing fails. This project has already been bitten by exactly that — README §17
documented four endpoints that all returned 404.

So every checkable claim in the API and architecture docs is asserted here. What
is *not* asserted is equally deliberate: narrative about why a boundary exists,
and anything already enforced by the test that produced the figure.

The claims under test
---------------------
* ``51.36`` / ``WARNING`` for two Gitleaks findings in production/internet-facing.
* ``base_score`` 32.1, and that the same findings score *lower* in
  development/internal.
* Named test functions actually exist, so a document cannot cite a test that has
  been renamed or deleted.
* Structural claims that are cheap to check and expensive to get wrong: the
  scanners run sequentially, the three writes share no transaction, and the
  dashboard makes no HTTP call.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from backend.app.config import AppSettings
from backend.app.database.database import Base, make_engine, make_session_factory
from backend.app.services.scan_service import ScanRequest, ScanService
from backend.app.services.storage_service import StorageService

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS = REPO_ROOT / "docs"
GITLEAKS_FIXTURE = "fixtures/gitleaks/secrets_detected.json"


@pytest.fixture()
def storage(tmp_path) -> StorageService:
    engine = make_engine(f"sqlite:///{(tmp_path / 'docs.db').as_posix()}")
    Base.metadata.create_all(engine)
    return StorageService(make_session_factory(engine))


def _assess(storage: StorageService, **context) -> object:
    return ScanService(storage=storage).assess(
        ScanRequest(
            gitleaks=True,
            fixtures={"gitleaks": GITLEAKS_FIXTURE},
            **context,
        )
    )


# -- the figures quoted in docs/api.md --------------------------------------


def test_the_response_shape_quoted_in_api_md_is_accurate(storage):
    """The worked example in ``docs/api.md`` is copied from a real response.

    If the model changes, this fails and the document must be regenerated rather
    than left asserting a score nothing produces.
    """

    outcome = _assess(
        storage, environment="production", exposure="internet-facing", change_status="new"
    )

    assert outcome.risk_score == pytest.approx(51.36)
    assert outcome.decision == "WARNING"
    assert outcome.base_score == pytest.approx(32.1)
    assert outcome.total_raw == pytest.approx(22.1)
    assert outcome.finding_count == 2
    assert outcome.statuses == {"gitleaks": "SUCCESS"}
    assert outcome.errors == []
    assert outcome.severity_breakdown == {"HIGH": 1, "CRITICAL": 1}
    assert outcome.explanation.headline == "Risk score 51.4/100 -> WARNING"


def test_the_headline_rounds_but_the_score_does_not(storage):
    """``51.36`` in the JSON and ``51.4`` in the headline are not a contradiction.

    The headline is human-facing and rounds to one decimal; the response field is
    the value itself. Documenting both without this test looks like a bug.
    """

    outcome = _assess(storage, environment="production", exposure="internet-facing")

    assert round(outcome.risk_score, 1) == 51.4
    assert outcome.explanation.headline.startswith("Risk score 51.4/100")


def test_the_context_comparison_quoted_in_api_md_holds(storage):
    """``docs/api.md`` says the same findings score 36.915 in development/internal.

    An earlier draft of both the document and this test said 36.9. That is the
    *displayed* value — the dashboard rounds the headline to one decimal — and
    using it here would have left a claim that looked right and was 0.015 out.
    """

    high = _assess(storage, environment="production", exposure="internet-facing")
    low = _assess(storage, environment="development", exposure="internal")

    assert low.risk_score == pytest.approx(36.915)
    assert round(low.risk_score, 1) == 36.9
    assert low.risk_score < high.risk_score


def test_the_category_breakdown_quoted_in_api_md_holds(storage):
    """Both fixture findings are secrets, so the single category is SECRET.

    The category name is singular, which reads oddly next to a key like
    ``category_breakdown`` and is exactly the kind of thing a document gets
    pluralised by hand. Hence the assertion.
    """

    outcome = _assess(storage, environment="production", exposure="internet-facing")
    assert outcome.category_breakdown == {"SECRET": 2}


# -- cross-references resolve ------------------------------------------------


def _defined_test_names() -> set[str]:
    names: set[str] = set()
    for path in (REPO_ROOT / "tests").glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                names.add(node.name)
    return names


@pytest.mark.parametrize("document", ["api.md", "architecture.md"])
def test_every_test_named_in_the_docs_exists(document):
    """A document must not cite a test that has been renamed or deleted.

    These citations are how a reader finds the guarantee behind a claim. A
    dangling one turns a verifiable statement into decoration.
    """

    text = (DOCS / document).read_text(encoding="utf-8")
    cited = set(re.findall(r"`(test_[a-z0-9_]+)`", text))

    assert cited, "the document cites no tests; the regex or the document changed"
    assert cited <= _defined_test_names(), f"cited but undefined: {sorted(cited - _defined_test_names())}"


@pytest.mark.parametrize("document", ["api.md", "architecture.md"])
def test_every_relative_link_in_the_docs_resolves(document):
    """No dead links in the documentation set."""

    text = (DOCS / document).read_text(encoding="utf-8")
    targets = re.findall(r"\]\((?!https?:)([^)#]+)", text)

    missing = [t for t in targets if not (DOCS / t).exists()]
    assert not missing, f"dead links in docs/{document}: {missing}"


def test_docs_readme_lists_the_documents_that_exist():
    """``docs/README.md`` must not promise a document that was never written."""

    index = (DOCS / "README.md").read_text(encoding="utf-8")
    linked = set(re.findall(r"\]\((?!https?:)([^)#]+\.md)\)", index))

    assert linked
    assert linked <= {p.name for p in DOCS.glob("*.md")}, (
        "docs/README.md links to a document that does not exist"
    )


# -- structural claims -------------------------------------------------------


def test_the_scanners_are_claimed_to_run_sequentially_because_they_do():
    """``docs/architecture.md`` lists sequential execution as a limitation.

    If someone parallelises `collect`, that bullet is wrong and a real cost
    disappears — so the claim is asserted in the direction that catches the
    change.
    """

    source = (REPO_ROOT / "scanners" / "scanner_service.py").read_text(encoding="utf-8")
    assert "ThreadPoolExecutor" not in source and "asyncio" not in source
    assert "Run the selected scanners sequentially" in source


def test_the_three_writes_really_share_no_transaction(storage):
    """``docs/architecture.md`` says a failure on the third write leaves a
    deployment with findings but no contributions.

    This asserts the *absence* of a transaction, which is a documentation claim
    about a limitation rather than a guarantee. If a transaction is ever added,
    the bullet must be deleted.
    """

    source = (REPO_ROOT / "backend" / "app" / "services" / "scan_service.py").read_text(
        encoding="utf-8"
    )
    assert ".begin(" not in source and "session.begin" not in source

    outcome = _assess(storage, environment="production", exposure="internet-facing")
    assert len(storage.get_risk_factors(outcome.deployment_id)) == 2


def test_the_dashboard_still_makes_no_http_call():
    """``docs/architecture.md`` and README §18 gap 4 both claim this.

    The claim is the reason the demo needs no server. If the dashboard starts
    calling the API, both documents are wrong and the demo needs a health check.
    """

    for name in ("service.py", "app.py", "transforms.py"):
        source = (REPO_ROOT / "dashboard" / name).read_text(encoding="utf-8")
        for banned in ("httpx", "requests", "urlopen", "api_client"):
            assert banned not in source, (
                f"dashboard/{name} now references {banned}; the dashboard is "
                "documented as engine-bound and the demo runs with no server"
            )


def test_the_api_docs_admit_what_is_missing():
    """``docs/api.md`` says the write side is done and the read side is not.

    An API document that only lists what works tends to read as a finished API.
    The "What is not here" section is the honesty mechanism, so it is asserted.
    """

    text = (DOCS / "api.md").read_text(encoding="utf-8").lower()
    for admission in ("what is not here", "no read api", "no authentication"):
        assert admission in text, f"docs/api.md no longer states: {admission}"


def test_the_endpoint_count_in_the_docs_is_the_real_one():
    """The tables in ``docs/api.md`` must not drift from the mounted routes.

    Counted from the OpenAPI schema rather than hardcoded, so adding a route
    without documenting it fails here.
    """

    from backend.app.main import create_app

    paths = create_app(AppSettings(app_name="XPRisk", app_env="test", database_url="sqlite:///")).openapi()["paths"]
    implemented = {p for p in paths if p not in {"/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect"}}

    assert implemented == {"/health", "/scan"}

    text = (DOCS / "api.md").read_text(encoding="utf-8")
    done_rows = [line for line in text.splitlines() if line.startswith("| `") and "| done |" in line]
    assert len(done_rows) == 2, (
        f"docs/api.md marks {len(done_rows)} endpoints done but {len(implemented)} "
        f"are implemented: {sorted(implemented)}"
    )