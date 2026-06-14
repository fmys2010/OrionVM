"""OrionVM — 标准库工具模块."""
from __future__ import annotations

import io
import json
import re
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, TypeVar

T = TypeVar("T")


# ==================== 编码兼容 ====================

def configure_stdio() -> None:
    """强制 UTF-8 编码, 避免容器/老终端下 print 中文报错."""
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream is None:
            continue
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


# ==================== 重试装饰器 ====================

def retry(
    attempts: int = 3,
    delay: float = 0.5,
    backoff: float = 2.0,
    retry_on: tuple[type[BaseException], ...] = (Exception,),
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """带指数退避的重试装饰器."""
    def decorator(fn: Callable[..., T]) -> Callable[..., T]:
        def wrapper(*args: Any, **kwargs: Any) -> T:
            current = delay
            last_exc: BaseException | None = None
            for i in range(attempts):
                try:
                    return fn(*args, **kwargs)
                except retry_on as e:
                    last_exc = e
                    if i == attempts - 1:
                        break
                    time.sleep(current)
                    current *= backoff
            assert last_exc is not None
            raise last_exc
        return wrapper
    return decorator


# ==================== 简易 logger ====================

class Logger:
    """线程安全的轻量 logger, 自动带时间戳."""

    def __init__(self, prefix: str = "[orionvm]") -> None:
        self.prefix = prefix

    def log(self, level: str, msg: str) -> None:
        ts = time.strftime("%H:%M:%S")
        try:
            print(f"{self.prefix} {ts} {level} {msg}", flush=True)
        except (BrokenPipeError, ValueError):
            pass

    def info(self, msg: str) -> None: self.log("INFO ", msg)
    def warn(self, msg: str) -> None: self.log("WARN ", msg)
    # logging 标准库惯例兼容: 'warning' 与 'warn' 等价
    warning = warn  # type: ignore[assignment]
    def error(self, msg: str) -> None: self.log("ERROR", msg)
    def debug(self, msg: str) -> None: self.log("DEBUG", msg)


import logging as _logging


def setup_logging(
    name: str = "orionvm",
    *,
    path: "Path | str | None" = None,
    level: int = _logging.INFO,
) -> Logger:
    """配置标准 logging 体系 ( handlers: console + optional file ).

    返回 Logger 适配器以保持与现有代码兼容.
    """
    log = _logging.getLogger(name)
    log.setLevel(level)
    # 避免重复添加 handler
    if log.handlers:
        return Logger(prefix=f"[{name}]")
    fmt = _logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s", "%H:%M:%S")
    sh = _logging.StreamHandler()
    sh.setLevel(level)
    sh.setFormatter(fmt)
    log.addHandler(sh)
    if path:
        fh = _logging.FileHandler(str(path), encoding="utf-8")
        fh.setLevel(level)
        fh.setFormatter(fmt)
        log.addHandler(fh)
    return Logger(prefix=f"[{name}]")


# ==================== 解析工具 ====================

_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def is_ipv4(s: str) -> bool:
    if not _IPV4_RE.match(s):
        return False
    return all(0 <= int(o) <= 255 for o in s.split("."))


def safe_int(val: Any, default: int = 0) -> int:
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


def safe_float(val: Any, default: float = 0.0) -> float:
    try:
        return float(val)
    except (TypeError, ValueError):
        return default


# ==================== JSON 读写 ====================

def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    tmp.replace(path)


def read_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return default


# ==================== OpenVPN 配置解析 ====================

def parse_openvpn_remote(config: str) -> tuple[str, int, str]:
    """从 OpenVPN 配置中提取 (host, port, proto)."""
    host = ""
    port = 0
    proto = "tcp"
    for raw in config.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        head = parts[0].lower()
        if head == "proto" and len(parts) >= 2:
            proto = parts[1].lower()
        elif head == "remote" and len(parts) >= 3:
            host = parts[1]
            port = safe_int(parts[2], 0)
            if len(parts) >= 4:
                proto = parts[3].lower()
    return host, port, proto


# ==================== 文本工具 ====================

@contextmanager
def opened_text(path: Path, mode: str = "r") -> Iterator[io.IOBase]:
    f = open(path, mode, encoding="utf-8", errors="replace")
    try:
        yield f
    finally:
        f.close()


def chunked(seq: Iterable[T], size: int) -> Iterator[list[T]]:
    """把序列切成固定大小批次."""
    if size <= 0:
        raise ValueError("chunk size must be > 0")
    buf: list[T] = []
    for item in seq:
        buf.append(item)
        if len(buf) >= size:
            yield buf
            buf = []
    if buf:
        yield buf
