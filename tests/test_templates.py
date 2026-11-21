from pathlib import Path

from ogrl_integration.testing import Cassette, Harness

from github_integration import app
from tests.rules import evaluate, template


def test_secret_leaks_template_fails_on_every_open_alert():
    app.transport = Cassette(Path(__file__).parent / "cassettes" / "secret-alerts.json")
    alerts = Harness(app).collect(
        "secret-scanning-alerts", 1, {"organization": "acme"}, {"GITHUB_TOKEN": "t"}
    )
    selected, failing, _ = evaluate(template("secret-leaks"), alerts.items)
    assert failing == selected == ["acme/api#3", "acme/web#9"]
    assert evaluate(template("secret-leaks"), []) == ([], [], True)  # allow_empty: no alerts passes
