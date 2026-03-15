"""Тесты генерации контента ловушек."""

import phantom.factory.generators as generators


def test_create_text_trap_renders(tmp_path, monkeypatch):
    monkeypatch.setattr(generators, "stomp_timestamp", lambda *args, **kwargs: None)
    template = tmp_path / "template.j2"
    template.write_text("user={{ admin_name }}", encoding="utf-8")
    out = tmp_path / "out.txt"
    gen = generators.ContentGenerator()
    ctx = gen.create_base_context()
    gen.create_text_trap(str(template), str(out), ctx, metadata={"trap_id": "t1"})
    assert out.exists()
    assert "user=" in out.read_text(encoding="utf-8")


def test_append_watermark(tmp_path):
    path = tmp_path / "file.bin"
    path.write_bytes(b"payload")
    gen = generators.ContentGenerator()
    gen._append_watermark(str(path), "abc123")
    data = path.read_bytes()
    assert b"PHANTOM_TRAP_ID:abc123" in data


def test_inject_zip_comment(tmp_path):
    import zipfile

    zip_path = tmp_path / "doc.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("a.txt", "x")

    gen = generators.ContentGenerator()
    gen._inject_zip_comment(str(zip_path), "zip123")

    with zipfile.ZipFile(zip_path, "r") as zf:
        assert zf.comment == b"PHANTOM_ID:zip123"
