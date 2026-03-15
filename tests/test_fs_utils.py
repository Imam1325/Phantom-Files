"""Тесты файловых утилит (utils/fs.py)."""

from pathlib import Path

from phantom.utils.fs import safe_mkdirs, atomic_write, read_text_safe, list_files


# ---------- safe_mkdirs ----------

def test_safe_mkdirs_creates_nested(tmp_path: Path):
    target = str(tmp_path / "a" / "b" / "c")
    safe_mkdirs(target)
    assert Path(target).is_dir()


def test_safe_mkdirs_existing_dir(tmp_path: Path):
    target = str(tmp_path / "existing")
    Path(target).mkdir()
    safe_mkdirs(target)  # Не бросает
    assert Path(target).is_dir()


def test_safe_mkdirs_idempotent(tmp_path: Path):
    target = str(tmp_path / "dir")
    safe_mkdirs(target)
    safe_mkdirs(target)
    assert Path(target).is_dir()


# ---------- atomic_write ----------

def test_atomic_write_creates_file(tmp_path: Path):
    target = str(tmp_path / "out.txt")
    atomic_write(target, "hello world")
    assert Path(target).read_text() == "hello world"


def test_atomic_write_overwrites(tmp_path: Path):
    target = str(tmp_path / "out.txt")
    atomic_write(target, "first")
    atomic_write(target, "second")
    assert Path(target).read_text() == "second"


def test_atomic_write_no_tmp_left(tmp_path: Path):
    """Временный файл не остаётся после записи."""
    target = str(tmp_path / "out.txt")
    atomic_write(target, "data")
    assert not Path(f"{target}.tmp").exists()


def test_atomic_write_unicode(tmp_path: Path):
    target = str(tmp_path / "unicode.txt")
    atomic_write(target, "Привет, мир! 🌍")
    assert Path(target).read_text(encoding="utf-8") == "Привет, мир! 🌍"


def test_atomic_write_empty(tmp_path: Path):
    target = str(tmp_path / "empty.txt")
    atomic_write(target, "")
    assert Path(target).read_text() == ""


# ---------- read_text_safe ----------

def test_read_text_safe_existing(tmp_path: Path):
    f = tmp_path / "data.txt"
    f.write_text("content")
    assert read_text_safe(str(f)) == "content"


def test_read_text_safe_missing():
    assert read_text_safe("/nonexistent/file.txt") == ""


def test_read_text_safe_missing_custom_default():
    assert read_text_safe("/nonexistent/file.txt", default="N/A") == "N/A"


def test_read_text_safe_unicode(tmp_path: Path):
    f = tmp_path / "uni.txt"
    f.write_text("Текст на русском", encoding="utf-8")
    assert read_text_safe(str(f)) == "Текст на русском"


# ---------- list_files ----------

def test_list_files_basic(tmp_path: Path):
    (tmp_path / "a.txt").write_text("a")
    (tmp_path / "b.txt").write_text("b")
    (tmp_path / "subdir").mkdir()
    files = list_files(str(tmp_path))
    assert len(files) == 2
    names = {Path(f).name for f in files}
    assert names == {"a.txt", "b.txt"}


def test_list_files_with_pattern(tmp_path: Path):
    (tmp_path / "a.txt").write_text("a")
    (tmp_path / "b.py").write_text("b")
    (tmp_path / "c.txt").write_text("c")
    files = list_files(str(tmp_path), pattern="*.txt")
    assert len(files) == 2
    names = {Path(f).name for f in files}
    assert names == {"a.txt", "c.txt"}


def test_list_files_empty_dir(tmp_path: Path):
    assert list_files(str(tmp_path)) == []


def test_list_files_nonexistent_dir():
    assert list_files("/nonexistent/directory") == []


def test_list_files_excludes_dirs(tmp_path: Path):
    (tmp_path / "file.txt").write_text("data")
    (tmp_path / "subdir").mkdir()
    files = list_files(str(tmp_path))
    assert len(files) == 1
    assert Path(files[0]).name == "file.txt"
