"""Language/manifest/build detection tests."""

from pathlib import Path

from builders.maven import MavenBuilder
from detection.build import BuildResolver
from detection.language import LanguageDetector, codeql_language_for
from detection.manifest import ManifestDetector, find_primary_manifest


def _make(tmp_path: Path, files: dict) -> Path:
    for relative, content in files.items():
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return tmp_path


def test_detect_basic_languages(tmp_path):
    _make(
        tmp_path,
        {
            "app.py": "x = 1\ny = 2\n",  # 2 lines
            "app.js": "let x = 1;\n",  # 1 line, trailing newline
            "pkg.go": "package main",  # 1 line, no trailing newline
        },
    )
    languages = {lang.name: lang.loc for lang in LanguageDetector().detect(tmp_path)}
    assert languages["python"] == 2
    assert languages["javascript"] == 1
    assert languages["go"] == 1


def test_detect_multi_project_layout(tmp_path):
    _make(
        tmp_path,
        {
            "backend/pom.xml": "<project/>",
            "backend/App.java": "class App {}\n",
            "api/main.py": "def f():\n    return 1\n",
            "api/app.ts": "let a = 1;\n",
            "api/app.tsx": "const b = () => null;\n",
        },
    )
    detection = LanguageDetector().detect(tmp_path)
    names = set(lang.name for lang in detection)
    assert "java" in names and "python" in names
    assert "typescript" in dict((lang.name, lang.loc) for lang in detection)
    # TypeScript must count both .ts and .tsx
    typescript = [lang for lang in detection if lang.name == "typescript"][0]
    assert typescript.loc == 2


def test_excluded_dirs_are_skipped(tmp_path):
    _make(
        tmp_path,
        {
            "real.py": "x = 1\n",
            ".venv/lib/python/site-packages/fake.py": "y = 2\n",
            "node_modules/lib.js": "let z = 1;\n",
        },
    )
    languages = LanguageDetector().detect(tmp_path)
    assert [lang.name for lang in languages] == ["python"]


def test_manifest_detection(tmp_path):
    _make(
        tmp_path,
        {"backend/pom.xml": "<x/>", "frontend/package.json": "{}", "frontend/app.js": "1;\n"},
    )
    manifests = ManifestDetector().detect(tmp_path)
    ecosystems = {m["ecosystem"] for m in manifests}
    assert "maven" in ecosystems
    assert "npm" in ecosystems


def test_build_plan_maven_uses_wrapper(tmp_path):
    manifest = _make(tmp_path, {"mvnw": "#!/bin/sh\n", "app/Main.java": "class Main {}\n", "pom.xml": "<x/>"}) / "pom.xml"
    resolver = BuildResolver([{"path": str(manifest), "relative": "pom.xml", "ecosystem": "maven"}])
    plan = resolver.plan_for_language("java", tmp_path)
    assert plan.required is True
    assert plan.ecosystem == "maven"
    assert plan.command[0] == str(tmp_path / "mvnw")
    assert all(isinstance(part, str) for part in plan.command)
    assert not any("&&" in part for part in plan.command)


def test_python_never_requires_build(tmp_path):
    manifest = tmp_path / "pyproject.toml"
    manifest.write_text("[project]\nname='x'\n")
    resolver = BuildResolver([{"path": str(manifest), "relative": "pyproject.toml", "ecosystem": "pip"}])
    plan = resolver.plan_for_language("python", tmp_path)
    assert plan.required is False


def test_codeql_language_mapping():
    assert codeql_language_for("typescript") == "javascript-typescript"
    assert codeql_language_for("python") == "python"
    assert codeql_language_for("rust") is None


def test_find_primary_manifest_prefers_root():
    manifests = [
        {"path": "/p/sub/package.json", "relative": "sub/package.json", "ecosystem": "npm"},
        {"path": "/p/package.json", "relative": "package.json", "ecosystem": "npm"},
    ]
    assert find_primary_manifest(manifests, "npm")["relative"] == "package.json"


def test_maven_builder_without_wrapper(tmp_path):
    builder = MavenBuilder()
    plan = builder.plan(tmp_path / "pom.xml", tmp_path)
    assert plan.command[0] == "mvn"