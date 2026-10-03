"""XPRisk finding normalization.

This package defines the single canonical schema that every security finding
must conform to, regardless of which tool produced it, and converts each
tool's native output into it.

Why normalization is a core contribution
----------------------------------------
Trivy, Checkov, Gitleaks and SonarQube disagree about almost everything:

============  ==================  ==============  ==========  ==========
Concern       Trivy               Checkov          Gitleaks    SonarQube
============  ==================  ==============  ==========  ==========
severity      CRITICAL..UNKNOWN   often ``null``  none at all  BLOCKER..
identifier    CVE-2024-1234       CKV_AWS_20      RuleID      rule key
location      target + pkg        file + line     file+line   component
subject       package name        resource addr   match text  message
============  ==================  ==============  ==========  ==========

Without a canonical form, any unified score would have to be computed
directly from four different shapes, and every downstream component (risk
engine, explainability, dashboard, trends) would need four branches. The
canonical schema collapses that into one.

Two properties are deliberate:

**Lossless.** Tool specific fields are never discarded. Anything that does
not map onto a canonical column is preserved verbatim under ``metadata``,
namespaced by tool (for example ``metadata["trivy"]["cvss_score"]``). That
means normalization can be revised later without re-running any scan.

**Honest.** A tool that reports no severity (``Gitleaks``) does not get an
invented severity that looks authoritative. Severity is assigned by an
explicit, documented, configurable *policy* and the finding records which
policy produced it, so the decision remains auditable.

Modules
-------
``models.py``
    The canonical dataclasses and enumerations: severity, category, source
    tool, and :class:`~normalizer.models.NormalizedFinding`.
``normalizer.py``
    The translation logic: one parser per tool, plus severity mapping and
    stable identifier generation.

.. note::
   Public symbols are re-exported here once Phase 9 (normalization) lands.
   Until then this module is intentionally import free, so that the package
   is importable from the moment the repository skeleton exists.
"""

__all__: list[str] = []