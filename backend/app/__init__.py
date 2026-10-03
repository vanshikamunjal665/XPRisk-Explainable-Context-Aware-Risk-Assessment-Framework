"""XPRisk FastAPI application.

Layering
--------
``config.py``
    Typed settings loaded from the environment via ``pydantic-settings``. The
    single place where configuration enters the application.

``api/``
    HTTP routers, one per resource. Routers validate input with Pydantic
    schemas, call a service, and translate the result into an HTTP response.
    Routers contain no business logic.

``schemas/``
    Pydantic request and response models. These are the API contract, and are
    deliberately distinct from the SQLAlchemy models in ``models/`` so that a
    change to the database schema cannot silently alter the public API.

``models/``
    SQLAlchemy ORM models: ``Deployment``, ``Finding`` and ``RiskFactor``.

``services/``
    Application logic that orchestrates the domain packages:
    ``scanner_service`` (run tools), ``normalization_service`` (translate),
    ``storage_service`` (persist), ``risk_service`` (score),
    ``explanation_service`` (explain), ``scan_service`` (tie it together).

``database/``
    Engine, session factory, declarative base and schema initialisation.

Request flow
------------
::

    HTTP request
      -> api router        (validate with a Pydantic schema)
      -> service           (orchestrate)
      -> domain packages   (scanners -> normalizer -> risk_engine -> explainability)
      -> services          (persist via storage_service)
      -> Pydantic response model
    HTTP response

Security properties
-------------------
* No credential is ever returned by any endpoint.
* No user supplied string is ever passed to a shell.
* Scanner output is treated as untrusted input and validated before use.
* ``eval`` and ``exec`` are not used anywhere in the project.
* Logging never records tokens, passwords or matched secret values.
"""