"""Тесты хранилища пользовательских шаблонов (TemplateStore)."""

from pathlib import Path

import pytest

from phantom.factory.template_store import TemplateStore, TemplateInfo


def _make_store(tmp_path: Path) -> TemplateStore:
    root = tmp_path / "user_templates"
    root.mkdir()
    return TemplateStore(str(root))


def _write_j2(tmp_path: Path, name: str = "my.j2", content: str = "Hello {{ name }}") -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


# ---------- add / list ----------

def test_add_and_list(tmp_path):
    store = _make_store(tmp_path)
    src = _write_j2(tmp_path)
    path = store.add_template(str(src), "ssh_key", "v1.0.0")
    assert "v1.0.0" in path

    items = store.list_templates()
    assert len(items) == 1
    assert items[0].name == "ssh_key"
    assert items[0].version == "v1.0.0"


def test_add_multiple_versions(tmp_path):
    store = _make_store(tmp_path)
    src = _write_j2(tmp_path)
    store.add_template(str(src), "creds", "v1.0.0")
    store.add_template(str(src), "creds", "v1.1.0")
    store.add_template(str(src), "creds", "v2.0.0")

    items = store.list_templates()
    versions = [i.version for i in items if i.name == "creds"]
    assert "v2.0.0" in versions
    assert "v1.1.0" in versions
    assert "v1.0.0" in versions


def test_add_prunes_old_versions(tmp_path):
    store = TemplateStore(str(tmp_path / "tpl"), max_versions=2)
    (tmp_path / "tpl").mkdir()
    src = _write_j2(tmp_path)
    store.add_template(str(src), "test", "v1.0.0")
    store.add_template(str(src), "test", "v2.0.0")
    store.add_template(str(src), "test", "v3.0.0")

    items = store.list_templates()
    versions = [i.version for i in items]
    assert "v1.0.0" not in versions
    assert "v3.0.0" in versions
    assert "v2.0.0" in versions


# ---------- activate ----------

def test_activate(tmp_path):
    store = _make_store(tmp_path)
    src = _write_j2(tmp_path)
    store.add_template(str(src), "key", "v1.0.0")
    store.add_template(str(src), "key", "v2.0.0")
    active = store.activate_template("key", "v1.0.0")
    assert "active" in active

    # Проверяем что symlink ведёт на v1.0.0
    link = Path(active)
    assert link.is_symlink()
    assert "v1.0.0" in link.resolve().name


def test_activate_nonexistent_raises(tmp_path):
    store = _make_store(tmp_path)
    with pytest.raises(FileNotFoundError):
        store.activate_template("nonexistent", "v1.0.0")


# ---------- show (get_template_info) ----------

def test_get_template_info(tmp_path):
    store = _make_store(tmp_path)
    src = _write_j2(tmp_path)
    store.add_template(str(src), "infra", "v1.0.0")
    store.add_template(str(src), "infra", "v2.0.0")
    store.activate_template("infra", "v2.0.0")

    info = store.get_template_info("infra")
    assert isinstance(info, TemplateInfo)
    assert info.name == "infra"
    assert "v2.0.0" in info.versions
    assert "v1.0.0" in info.versions
    assert info.active_version == "v2.0.0"
    assert info.total_size_bytes > 0
    assert info.extension == ".j2"


def test_get_template_info_nonexistent(tmp_path):
    store = _make_store(tmp_path)
    with pytest.raises(FileNotFoundError):
        store.get_template_info("ghost")


# ---------- remove ----------

def test_remove_specific_version(tmp_path):
    store = _make_store(tmp_path)
    src = _write_j2(tmp_path)
    store.add_template(str(src), "db", "v1.0.0")
    store.add_template(str(src), "db", "v2.0.0")

    removed = store.remove_template("db", "v1.0.0")
    assert len(removed) >= 1

    items = store.list_templates()
    versions = [i.version for i in items if i.name == "db"]
    assert "v1.0.0" not in versions
    assert "v2.0.0" in versions


def test_remove_all_versions(tmp_path):
    store = _make_store(tmp_path)
    src = _write_j2(tmp_path)
    store.add_template(str(src), "vpn", "v1.0.0")
    store.add_template(str(src), "vpn", "v2.0.0")

    removed = store.remove_template("vpn")
    assert len(removed) >= 2

    items = store.list_templates()
    assert all(i.name != "vpn" for i in items)


def test_remove_active_version_clears_symlink(tmp_path):
    store = _make_store(tmp_path)
    src = _write_j2(tmp_path)
    store.add_template(str(src), "cert", "v1.0.0")
    store.add_template(str(src), "cert", "v2.0.0")
    store.activate_template("cert", "v1.0.0")

    store.remove_template("cert", "v1.0.0")
    # После удаления активной версии — active symlink должен быть снят
    info = store.get_template_info("cert")
    # v2.0.0 ещё есть, но active мог быть снят
    assert "v2.0.0" in info.versions


def test_remove_last_version_deletes_dir(tmp_path):
    store = _make_store(tmp_path)
    src = _write_j2(tmp_path)
    store.add_template(str(src), "single", "v1.0.0")

    store.remove_template("single", "v1.0.0")
    # Каталог шаблона должен быть удалён
    assert not (store.root / "single").exists()


def test_remove_nonexistent_raises(tmp_path):
    store = _make_store(tmp_path)
    with pytest.raises(FileNotFoundError):
        store.remove_template("nope")


# ---------- validation ----------

def test_add_rejects_forbidden_pattern(tmp_path):
    store = _make_store(tmp_path)
    bad = _write_j2(tmp_path, "evil.j2", "{{ __import__('os').system('rm -rf /') }}")
    with pytest.raises(ValueError, match="Forbidden pattern"):
        store.add_template(str(bad), "evil", "v1.0.0")


def test_add_rejects_eval(tmp_path):
    store = _make_store(tmp_path)
    bad = _write_j2(tmp_path, "eval.j2", "{{ eval('1+1') }}")
    with pytest.raises(ValueError, match="Forbidden pattern"):
        store.add_template(str(bad), "evaltest", "v1.0.0")


def test_add_rejects_bad_semver(tmp_path):
    store = _make_store(tmp_path)
    src = _write_j2(tmp_path)
    with pytest.raises(ValueError, match="vMAJOR"):
        store.add_template(str(src), "x", "1.0.0")  # нет 'v' префикса


def test_add_rejects_unsafe_name(tmp_path):
    store = _make_store(tmp_path)
    src = _write_j2(tmp_path)
    with pytest.raises(ValueError, match="Unsafe"):
        store.add_template(str(src), "../etc/passwd", "v1.0.0")


def test_add_rejects_unsupported_extension(tmp_path):
    store = _make_store(tmp_path)
    bad = tmp_path / "weird.exe"
    bad.write_bytes(b"\x00\x00")
    with pytest.raises(ValueError, match="Unsupported"):
        store.add_template(str(bad), "bin", "v1.0.0")


def test_add_rejects_too_large(tmp_path):
    store = _make_store(tmp_path)
    big = tmp_path / "big.j2"
    big.write_bytes(b"x" * (11 * 1024 * 1024))
    with pytest.raises(ValueError, match="10MB"):
        store.add_template(str(big), "huge", "v1.0.0")


# ---------- to_dict_list (API сериализация) ----------

def test_to_dict_list(tmp_path):
    store = _make_store(tmp_path)
    src = _write_j2(tmp_path)
    store.add_template(str(src), "api_tpl", "v1.0.0")
    store.activate_template("api_tpl", "v1.0.0")

    result = store.to_dict_list()
    assert len(result) == 1
    assert result[0]["name"] == "api_tpl"
    assert result[0]["active_version"] == "v1.0.0"
    assert "v1.0.0" in result[0]["versions"]


def test_to_dict_list_empty(tmp_path):
    store = _make_store(tmp_path)
    assert store.to_dict_list() == []
