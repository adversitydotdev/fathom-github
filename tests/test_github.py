"""GitHub collection and the branch protection check, against replayed GitHub REST responses.

Cassettes follow GitHub's documented response shapes (https://docs.github.com/en/rest);
they are not recorded from a live organization.
"""

from pathlib import Path

import pytest
from ogrl_integration.http import Request, Response
from ogrl_integration.testing import Cassette, Harness, HarnessError

from github_integration import app

CASSETTES = Path(__file__).parent / "cassettes"
CONFIG = {"organization": "acme"}
TOKEN = {"GITHUB_TOKEN": "github_pat_x"}


def collect(resource: str, cassette: str):
    app.transport = Cassette(CASSETTES / f"{cassette}.json")
    return Harness(app).collect(resource, 1, CONFIG, TOKEN)


def by_id(items):
    return {i["id"]: i for i in items}


def test_repositories_follow_link_pagination():
    repos = collect("repositories", "repositories").items
    assert [r["name"] for r in repos] == [
        "acme/api",
        "acme/web",
        "acme/legacy",
        "acme/tools",
        "acme/forked-lib",
    ]
    assert by_id(repos)["103"]["archived"] is True


def test_branch_rules_merge_classic_protection_and_rulesets():
    rules = by_id(collect("branch-rules", "branch-rules").items)
    assert "103" not in rules  # archived repositories have no live branch to protect

    api = rules["101"]  # classic protection only
    assert (api["required_approvals"], api["status_checks"], api["enforce_admins"]) == (2, ["ci/test"], True)
    assert (api["force_push_blocked"], api["sources"]) == (True, ["classic"])

    web = rules["102"]  # an organization ruleset only
    assert (web["required_approvals"], web["status_checks"], web["sources"]) == (1, ["build"], ["ruleset:42"])
    assert (web["force_push_blocked"], web["deletion_blocked"], web["enforce_admins"]) == (True, True, None)

    tools = rules["104"]  # a ruleset that asks for zero approvals and nothing else
    assert (tools["branch"], tools["required_approvals"], tools["force_push_blocked"]) == ("trunk", 0, False)
    assert rules["105"]["protected"] is False


def test_missing_administration_permission_is_named():
    with pytest.raises(HarnessError) as caught:
        collect("branch-rules", "protection-forbidden")
    assert caught.value.error["data"] == {"kind": "permission_denied", "permission": "administration:read"}


def test_secret_scanning_alerts():
    alerts = collect("secret-scanning-alerts", "secret-alerts").items
    assert [a["id"] for a in alerts] == ["acme/api#3", "acme/web#9"]
    assert alerts[0]["name"] == "acme/api: Amazon AWS Access Key ID"
    with pytest.raises(HarnessError) as caught:
        collect("secret-scanning-alerts", "secret-alerts-disabled")
    assert "not enabled" in caught.value.error["message"]


def test_branch_protection_check():
    repos = collect("repositories", "repositories").items
    rules = collect("branch-rules", "branch-rules").items
    snapshots = {"dev.adversity.github/repositories@1": repos, "dev.adversity.github/branch-rules@1": rules}
    out = Harness(app).check("branch-protection", 1, snapshots, {"min_approvals": "1"})
    assert out["outcome"] == "fail"
    assert out["summary"].startswith("1 of 3 repositories fall short: acme/tools (0 approvals")
    assert out["subjects"] == [{"kind": "resource", "name": "acme/tools", "external_id": "104"}]

    strict = Harness(app).check("branch-protection", 1, snapshots, {"min_approvals": "2"})
    assert [s["name"] for s in strict["subjects"]] == ["acme/web", "acme/tools"]


class Spy:
    def __init__(self, scopes: str = "") -> None:
        self.calls: list[Request] = []
        self.scopes = scopes

    def send(self, request: Request, timeout: float) -> Response:
        self.calls.append(request)
        headers = {"X-OAuth-Scopes": self.scopes} if self.scopes else {}
        return Response(200, headers, b'{"login": "ogrl-bot"}')


def test_validate_reports_identity_and_warns_on_write_scopes():
    app.transport = spy = Spy("read:org, repo")
    out = Harness(app).validate(CONFIG, TOKEN)
    assert out["identity"] == "acme as ogrl-bot"
    assert out["warnings"] == ["the token has write scopes; OGRL only needs read access"]
    assert spy.calls[0].headers["Authorization"] == "Bearer github_pat_x"
    assert [c.url for c in spy.calls] == ["https://api.github.com/user", "https://api.github.com/orgs/acme"]

    app.transport = Spy()
    assert Harness(app).validate(CONFIG, {"OGRL_ACCESS_TOKEN": "ghu_x"})["warnings"] == []
