"""Package analysis entrypoint used by Huginn."""

from __future__ import annotations

import json

from git_warden.package_entry import analyze_package, expose_package_dirs, main


def _pkg(tmp_path, files):
    root = tmp_path / "src"
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return root


def test_payload_in_dist_is_scanned(tmp_path):
    # A repository skips dist/ as build output; a package ships its code there.
    src = _pkg(tmp_path, {
        "package/package.json": json.dumps({"name": "ui-kit", "main": "dist/index.js"}),
        "package/dist/index.js":
            "global['_V']='8-st3';var MDy=(function(a,b){return a})('Cot%3t=shtP',1111436);\n",
    })
    out = analyze_package(src, "ui-kit", "npm", tmp_path)
    assert out["confirmed"] and out["confidence"] == "auto"
    assert {f["rule"] for f in out["confirming_findings"]} == {"polinrider-loader"}
    assert out["confirming_findings"][0]["file"] == "package/pkg_dist/index.js"
    assert out["package"] == {"name": "ui-kit", "ecosystem": "npm",
                              "exposed_dirs": ["package/pkg_dist"]}
    assert (src / "package/dist/index.js").exists()  # the source tree is untouched


def test_install_hook_package_confirms(tmp_path):
    src = _pkg(tmp_path, {"package/package.json": json.dumps(
        {"name": "x", "scripts": {"preinstall": "node setup_bun.js"}})})
    out = analyze_package(src, "x", "npm", tmp_path)
    assert out["confirmed"]
    assert "shai-hulud-ioc" in {f["rule"] for f in out["confirming_findings"]}


def test_clean_package_is_not_confirmed(tmp_path):
    src = _pkg(tmp_path, {
        "package/package.json": json.dumps({"name": "pad", "main": "index.js"}),
        "package/index.js": "module.exports = (s, n) => s.padStart(n);\n",
    })
    out = analyze_package(src, "pad", "npm", tmp_path)
    assert not out["confirmed"] and out["confirming_findings"] == []


def test_nested_generated_dirs_are_all_exposed(tmp_path):
    root = tmp_path / "r"
    (root / "a/build/dist").mkdir(parents=True)
    (root / "out").mkdir()
    assert expose_package_dirs(root) == ["a/pkg_build", "a/pkg_build/pkg_dist", "pkg_out"]


def test_cli_prints_json(tmp_path, capsys):
    src = _pkg(tmp_path, {"pkg/setup.py": "from setuptools import setup\nsetup(name='a')\n"})
    assert main([str(src), "--name", "a", "--ecosystem", "pypi", "--work", str(tmp_path)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["package"]["ecosystem"] == "pypi" and out["confirmed"] is False
    assert main([str(tmp_path / "missing"), "--name", "a", "--ecosystem", "pypi"]) == 2
