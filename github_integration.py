"""GitHub for OGRL (RFC 0005): repositories, effective default-branch rules, secret scanning alerts.

REST API: https://docs.github.com/en/rest. Branch rules merge two sources:
classic branch protection (`/branches/{branch}/protection`) and every ruleset
that applies to the branch (`/rules/branches/{branch}`), so an organization
using either one, or both, gets one answer per repository.
"""

from urllib.parse import quote

from ogrl_integration import Integration, PermissionDenied, Subject, VendorError, fail, pass_

app = Integration("dev.adversity.github", "0.1.2")

PAGE = 100


def _api(ctx) -> str:
    return (ctx.config.get("api_url") or "https://api.github.com").rstrip("/")


def _headers(ctx) -> dict[str, str]:
    token = ctx.env.get("GITHUB_TOKEN") or ctx.access_token
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def _org(ctx) -> str:
    return ctx.config["organization"]


@app.validate
def validate(ctx):
    me = ctx.http.get(f"{_api(ctx)}/user", headers=_headers(ctx))
    ctx.http.get(f"{_api(ctx)}/orgs/{_org(ctx)}", headers=_headers(ctx))  # can the token see the org?
    scopes = [s.strip() for s in (me.header("x-oauth-scopes") or "").split(",") if s.strip()]
    warnings = []
    if any(s in ("repo", "admin:org", "write:org") for s in scopes):
        warnings.append("the token has write scopes; OGRL only needs read access")
    return ctx.identity(f"{_org(ctx)} as {me.json()['login']}", scopes=scopes, warnings=warnings)


def _repositories(ctx):
    return ctx.http.paginate(
        f"{_api(ctx)}/orgs/{_org(ctx)}/repos",
        params={"type": "all", "per_page": PAGE},
        headers=_headers(ctx),
    )


@app.resource("repositories", version=1)
def repositories(ctx):
    for repo in _repositories(ctx):
        yield {
            "id": str(repo["id"]),
            "name": repo["full_name"],
            "private": repo.get("private", False),
            "visibility": repo.get("visibility"),
            "archived": repo.get("archived", False),
            "fork": repo.get("fork", False),
            "default_branch": repo.get("default_branch"),
            "pushed_at": repo.get("pushed_at"),
            "topics": repo.get("topics", []),
        }


def _classic(ctx, full_name: str, branch: str) -> dict | None:
    """Classic protection, or None when the branch has none (GitHub answers 404)."""
    url = f"{_api(ctx)}/repos/{full_name}/branches/{quote(branch, safe='')}/protection"
    try:
        return ctx.http.get(url, headers=_headers(ctx)).json()
    except VendorError as exc:
        if exc.status == 404:
            return None
        raise
    except PermissionDenied as exc:
        raise PermissionDenied(
            f"{exc.message}: reading branch protection needs Administration (read)",
            permission="administration:read",
        ) from exc


def _effective(classic: dict | None, rules: list[dict]) -> dict:
    approvals, checks, sources = 0, set(), []
    dismiss = code_owner = strict = False
    force_blocked = deletion_blocked = False
    enforce_admins = None
    if classic is not None:
        sources.append("classic")
        reviews = classic.get("required_pull_request_reviews") or {}
        approvals = reviews.get("required_approving_review_count", 0)
        dismiss = reviews.get("dismiss_stale_reviews", False)
        code_owner = reviews.get("require_code_owner_reviews", False)
        status = classic.get("required_status_checks") or {}
        checks |= set(status.get("contexts") or [])
        checks |= {c["context"] for c in status.get("checks") or []}
        strict = status.get("strict", False)
        force_blocked = not (classic.get("allow_force_pushes") or {}).get("enabled", False)
        deletion_blocked = not (classic.get("allow_deletions") or {}).get("enabled", False)
        enforce_admins = (classic.get("enforce_admins") or {}).get("enabled", False)
    for rule in rules:
        source = f"ruleset:{rule['ruleset_id']}" if "ruleset_id" in rule else "ruleset"
        if source not in sources:
            sources.append(source)
        params = rule.get("parameters") or {}
        if rule["type"] == "pull_request":
            approvals = max(approvals, params.get("required_approving_review_count", 0))
            dismiss = dismiss or params.get("dismiss_stale_reviews_on_push", False)
            code_owner = code_owner or params.get("require_code_owner_review", False)
        elif rule["type"] == "required_status_checks":
            checks |= {c["context"] for c in params.get("required_status_checks") or []}
            strict = strict or params.get("strict_required_status_checks_policy", False)
        elif rule["type"] == "non_fast_forward":
            force_blocked = True
        elif rule["type"] == "deletion":
            deletion_blocked = True
    return {
        "protected": bool(sources),
        "required_approvals": approvals,
        "dismiss_stale_reviews": dismiss,
        "code_owner_review": code_owner,
        "status_checks": sorted(checks),
        "strict_status_checks": strict,
        "force_push_blocked": force_blocked if sources else False,
        "deletion_blocked": deletion_blocked if sources else False,
        "enforce_admins": enforce_admins,
        "sources": sources,
    }


@app.resource("branch-rules", version=1)
def branch_rules(ctx):
    """One item per active repository's default branch."""
    for repo in _repositories(ctx):
        branch = repo.get("default_branch")
        if repo.get("archived") or not branch:
            continue
        rules = list(
            ctx.http.paginate(
                f"{_api(ctx)}/repos/{repo['full_name']}/rules/branches/{quote(branch, safe='')}",
                params={"per_page": PAGE},
                headers=_headers(ctx),
            )
        )
        yield {
            "id": str(repo["id"]),
            "name": f"{repo['full_name']}:{branch}",
            "repository": repo["full_name"],
            "branch": branch,
            **_effective(_classic(ctx, repo["full_name"], branch), rules),
        }


@app.resource("secret-scanning-alerts", version=1)
def secret_scanning_alerts(ctx):
    try:
        alerts = list(
            ctx.http.paginate(
                f"{_api(ctx)}/orgs/{_org(ctx)}/secret-scanning/alerts",
                params={"state": "open", "per_page": PAGE},
                headers=_headers(ctx),
            )
        )
    except VendorError as exc:
        if exc.status == 404:
            raise VendorError(
                f"secret scanning is not enabled for {_org(ctx)}, or the token cannot read its alerts"
            ) from exc
        raise
    for alert in alerts:
        repo = (alert.get("repository") or {}).get("full_name", "?")
        kind = alert.get("secret_type_display_name") or alert.get("secret_type") or "secret"
        yield {
            "id": f"{repo}#{alert['number']}",
            "name": f"{repo}: {kind}",
            "state": alert.get("state", "open"),
            "secret_type": alert.get("secret_type"),
            "repository": repo,
            "created": alert.get("created_at"),
            "validity": alert.get("validity"),
            "url": alert.get("html_url"),
        }


@app.check("branch-protection", version=1)
def branch_protection(ctx, repositories, branch_rules):
    """Active repositories' default branches require review, checks, and no force pushes.

    Arguments: `min_approvals` (default 1), `require_status_checks` (default true).
    """
    minimum = int(ctx.args.get("min_approvals", "1"))
    need_checks = ctx.args.get("require_status_checks", "true").lower() == "true"
    rules = {r["id"]: r for r in branch_rules}
    active = [r for r in repositories if not r["archived"] and not r["fork"] and r["default_branch"]]
    failing = []
    for repo in active:
        rule = rules.get(repo["id"])
        gaps = []
        if rule is None:
            gaps.append("no rules collected")
        else:
            if rule["required_approvals"] < minimum:
                gaps.append(f"{rule['required_approvals']} approvals")
            if need_checks and not rule["status_checks"]:
                gaps.append("no required status checks")
            if not rule["force_push_blocked"]:
                gaps.append("force pushes allowed")
        if gaps:
            failing.append((repo, gaps))
    if failing:
        detail = "; ".join(f"{repo['name']} ({', '.join(gaps)})" for repo, gaps in failing[:5])
        more = f" and {len(failing) - 5} more" if len(failing) > 5 else ""
        return fail(
            f"{len(failing)} of {len(active)} repositories fall short: {detail}{more}",
            [Subject.resource(repo["name"], repo["id"]) for repo, _ in failing],
        )
    return pass_(f"{len(active)} repositories require review, status checks, and block force pushes")
