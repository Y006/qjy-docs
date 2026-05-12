#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""KC110-EmbodiedAI 文档静态加密构建脚本。

目录约定：
    方式一：单文件文档
        content/private/<文档>.html

    方式二：目录型文档
        content/private/<文档目录>/<文档>.html
        content/private/<文档目录>/assets/<图片或其他资源>

输出约定：
    单文件文档输出到：
        content/public/<文档>.html

    目录型文档输出到：
        content/public/<文档目录>/<文档>.html

密码约定：
    脚本不再支持在代码中硬编码密码，也不会自动生成并写入密码文件。
    密码只能通过 --password 参数传入，或在运行时交互输入。

构建动作：
    1. encrypt：只把 content/private 中的私有 HTML 加密更新到 content/public。
    2. index：只扫描 content/public 下的 HTML 并重新生成 files-data.js。
    3. all：先执行 encrypt，再执行 index。

脚本会把 private 中的 HTML 与相关资源文件打包为加密页面。
files-data.js 的更新是独立索引动作，可单独执行。
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import getpass
import json
import mimetypes
import re
import secrets
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Any


# 不再支持在脚本内硬编码密码，避免真实密码随代码提交。
ROOT_DIR = Path(__file__).resolve().parent
CONTENT_DIR = ROOT_DIR / "content"
PRIVATE_DIR = CONTENT_DIR / "private"
PUBLIC_DIR = CONTENT_DIR / "public"
FILES_DATA_PATH = ROOT_DIR / "files-data.js"

PBKDF2_ITERATIONS = 390_000
ASSOCIATED_DATA = b"KC110-EmbodiedAI-docs-v1"
PAYLOAD_VERSION = 1


@dataclass
class CryptoModules:
    PBKDF2HMAC: Any
    hashes: Any
    AESGCM: Any


@dataclass
class DocumentMeta:
    date: str
    title: str
    doc_type: str
    desc: str = ""


class MetadataParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.in_title = False
        self.title_parts: list[str] = []
        self.meta: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = {key.lower(): value or "" for key, value in attrs}
        if tag.lower() == "title":
            self.in_title = True
        if tag.lower() == "meta":
            name = (attr_map.get("name") or attr_map.get("property") or "").lower()
            content = attr_map.get("content", "")
            if name and content:
                self.meta[name] = content.strip()

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title_parts.append(data)

    @property
    def title(self) -> str:
        return " ".join(part.strip() for part in self.title_parts if part.strip()).strip()


def log(level: str, message: str) -> None:
    timestamp = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] [{level}] {message}")


def fail(message: str, exit_code: int = 1) -> None:
    log("错误", message)
    raise SystemExit(exit_code)


def require_crypto() -> CryptoModules:
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    except ModuleNotFoundError as exc:
        package_name = exc.name or "cryptography"
        print()
        log("错误", f"缺少 Python 依赖包：{package_name}")
        print("本脚本使用 AES-GCM 与 PBKDF2-HMAC-SHA256 进行加密，不能降级为弱加密算法。")
        print("请在当前 Python 环境中安装依赖后重新运行：")
        print()
        print("    python3 -m pip install cryptography")
        print()
        print("如果项目使用虚拟环境，请先激活虚拟环境，再执行上述安装命令。")
        print("如果安装失败，请检查 Python 版本、pip 版本和网络访问权限。")
        raise SystemExit(2) from exc

    return CryptoModules(PBKDF2HMAC=PBKDF2HMAC, hashes=hashes, AESGCM=AESGCM)


def derive_key(password: str, salt: bytes, crypto: CryptoModules) -> bytes:
    kdf = crypto.PBKDF2HMAC(
        algorithm=crypto.hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_bytes(plain: bytes, password: str, crypto: CryptoModules) -> dict[str, Any]:
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    key = derive_key(password, salt, crypto)
    ciphertext = crypto.AESGCM(key).encrypt(nonce, plain, ASSOCIATED_DATA)
    return {
        "version": PAYLOAD_VERSION,
        "algorithm": "AES-GCM-256",
        "kdf": "PBKDF2-HMAC-SHA256",
        "iterations": PBKDF2_ITERATIONS,
        "associatedData": ASSOCIATED_DATA.decode("ascii"),
        "salt": base64.b64encode(salt).decode("ascii"),
        "iv": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }


def resolve_password(args: argparse.Namespace) -> str:
    if args.password:
        log("信息", "使用脚本参数指定的密码。该密码不会写入磁盘。")
        return args.password

    print("请输入用于加密 private 文档的密码。")
    print("密码只用于本次构建，不会写入脚本或磁盘文件。")
    password = getpass.getpass("密码：")
    if not password:
        fail("未输入密码，构建已取消。")
    return password


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(encoding="utf-8-sig")


def extract_metadata(html_path: Path, project_dir: Path) -> DocumentMeta:
    parser = MetadataParser()
    try:
        parser.feed(read_text(html_path))
    except Exception as exc:
        log("警告", f"解析元数据失败：{html_path.relative_to(ROOT_DIR)}；原因：{exc}")

    title = (
        parser.meta.get("doc-title")
        or parser.meta.get("title")
        or parser.title
        or html_path.stem
    )
    doc_type = parser.meta.get("doc-type") or project_dir.name
    desc = parser.meta.get("description") or parser.meta.get("doc-desc") or ""
    raw_date = parser.meta.get("doc-date") or parser.meta.get("date")
    date = normalize_date(raw_date) if raw_date else dt.date.today().isoformat()
    return DocumentMeta(date=date, title=title, doc_type=doc_type, desc=desc)


def normalize_date(value: str | None) -> str:
    if not value:
        return dt.date.today().isoformat()
    cleaned = value.strip().replace("/", "-")
    match = re.search(r"\d{4}-\d{1,2}-\d{1,2}", cleaned)
    if not match:
        return dt.date.today().isoformat()
    year, month, day = match.group(0).split("-")
    return f"{int(year):04d}-{int(month):02d}-{int(day):02d}"


def file_to_bundle_entry(path: Path, relative_path: Path) -> dict[str, str]:
    mime_type, _ = mimetypes.guess_type(path.name)
    if relative_path.suffix.lower() in {".html", ".htm"}:
        mime_type = "text/html;charset=utf-8"
    if not mime_type:
        mime_type = "application/octet-stream"

    return {
        "mime": mime_type,
        "data": base64.b64encode(path.read_bytes()).decode("ascii"),
    }


def create_document_bundle(project_dir: Path, html_path: Path) -> bytes:
    files: dict[str, dict[str, str]] = {}
    for path in sorted(project_dir.rglob("*")):
        if not path.is_file():
            continue
        if should_skip_private_file(path):
            continue
        relative_path = path.relative_to(project_dir)
        normalized = relative_path.as_posix()
        files[normalized] = file_to_bundle_entry(path, relative_path)

    main_path = html_path.relative_to(project_dir).as_posix()
    if main_path not in files:
        fail(f"内部错误：主 HTML 未进入资源包：{html_path}")

    bundle = {
        "version": PAYLOAD_VERSION,
        "main": main_path,
        "files": files,
        "generatedAt": dt.datetime.now().isoformat(timespec="seconds"),
    }
    return json.dumps(bundle, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def should_skip_private_file(path: Path) -> bool:
    parts = set(path.parts)
    if "__pycache__" in parts:
        return True
    return path.name.startswith(".") or path.name.endswith((".tmp", ".bak"))


def encrypted_page_template(payload: dict[str, Any], meta: DocumentMeta) -> str:
    payload_json = json.dumps(payload, ensure_ascii=False, indent=2)
    escaped_title = html_escape(meta.title)
    escaped_date = html_escape(meta.date)
    escaped_type = html_escape(meta.doc_type)
    escaped_desc = html_escape(meta.desc)
    desc_meta = ""
    if meta.desc:
        desc_meta = (
            f'    <meta name="description" content="{escaped_desc}">\\n'
            f'    <meta name="doc-desc" content="{escaped_desc}">\\n'
        )
    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex,nofollow">
    <meta name="doc-title" content="{escaped_title}">
    <meta name="doc-date" content="{escaped_date}">
    <meta name="doc-type" content="{escaped_type}">
{desc_meta}    <title>{escaped_title}</title>
    <style>
        :root {{
            --primary-color: #115EA2;
            --primary-dark: #0D477A;
            --text-dark: #1f2937;
            --text-muted: #6b7280;
            --border-normal: #d1d5db;
            --bg-light: #f3f4f6;
            --bg-white: #ffffff;
        }}
        * {{ box-sizing: border-box; }}
        body {{
            margin: 0;
            min-height: 100vh;
            font-family: "Times New Roman", "Noto Serif CJK SC", serif;
            color: var(--text-dark);
            background: var(--bg-light);
        }}
        .unlock-page {{
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 32px;
        }}
        .unlock-panel {{
            width: min(520px, 100%);
            background: var(--bg-white);
            border: 1px solid var(--border-normal);
            box-shadow: 0 16px 48px rgba(17, 24, 39, 0.12);
            padding: 32px;
        }}
        h1 {{
            margin: 0 0 10px;
            font-size: 24px;
            font-weight: 700;
            color: var(--primary-dark);
        }}
        .summary {{
            margin: 0 0 24px;
            line-height: 1.7;
            color: var(--text-muted);
            font-size: 14px;
        }}
        label {{
            display: block;
            margin-bottom: 8px;
            font-size: 14px;
            font-weight: 700;
        }}
        input {{
            width: 100%;
            height: 42px;
            border: 1px solid var(--border-normal);
            padding: 0 12px;
            font-size: 15px;
            outline: none;
        }}
        input:focus {{
            border-color: var(--primary-color);
            box-shadow: 0 0 0 3px rgba(17, 94, 162, 0.12);
        }}
        button {{
            margin-top: 16px;
            width: 100%;
            height: 42px;
            border: 0;
            background: var(--primary-color);
            color: white;
            font-size: 15px;
            font-weight: 700;
            cursor: pointer;
        }}
        button:disabled {{
            opacity: 0.7;
            cursor: wait;
        }}
        .status {{
            min-height: 22px;
            margin-top: 14px;
            font-size: 13px;
            line-height: 1.6;
            color: var(--text-muted);
        }}
        .status.error {{ color: #9f1239; }}
        .viewer {{
            width: 100vw;
            height: 100vh;
            border: 0;
            display: block;
            background: white;
        }}
    </style>
</head>
<body>
    <main id="unlockPage" class="unlock-page">
        <section class="unlock-panel">
            <h1>{escaped_title}</h1>
            <p class="summary">该文档已进行本地静态加密。请输入密码后在浏览器中解密查看，密码不会上传到服务器。</p>
            <label for="passwordInput">访问密码</label>
            <input id="passwordInput" type="password" autocomplete="current-password" autofocus>
            <button id="decryptButton" type="button">解密并打开文档</button>
            <div id="status" class="status"></div>
        </section>
    </main>
    <script>
        const ENCRYPTED_PAYLOAD = {payload_json};

        const statusNode = document.getElementById("status");
        const passwordInput = document.getElementById("passwordInput");
        const decryptButton = document.getElementById("decryptButton");

        function setStatus(message, isError) {{
            statusNode.textContent = message;
            statusNode.className = isError ? "status error" : "status";
        }}

        function base64ToBytes(value) {{
            const binary = atob(value);
            const bytes = new Uint8Array(binary.length);
            for (let index = 0; index < binary.length; index += 1) {{
                bytes[index] = binary.charCodeAt(index);
            }}
            return bytes;
        }}

        async function deriveKey(password, salt, iterations) {{
            const passwordKey = await crypto.subtle.importKey(
                "raw",
                new TextEncoder().encode(password),
                "PBKDF2",
                false,
                ["deriveKey"]
            );
            return crypto.subtle.deriveKey(
                {{
                    name: "PBKDF2",
                    salt,
                    iterations,
                    hash: "SHA-256"
                }},
                passwordKey,
                {{
                    name: "AES-GCM",
                    length: 256
                }},
                false,
                ["decrypt"]
            );
        }}

        async function decryptBundle(password) {{
            const salt = base64ToBytes(ENCRYPTED_PAYLOAD.salt);
            const iv = base64ToBytes(ENCRYPTED_PAYLOAD.iv);
            const ciphertext = base64ToBytes(ENCRYPTED_PAYLOAD.ciphertext);
            const key = await deriveKey(password, salt, ENCRYPTED_PAYLOAD.iterations);
            const plainBuffer = await crypto.subtle.decrypt(
                {{
                    name: "AES-GCM",
                    iv,
                    additionalData: new TextEncoder().encode(ENCRYPTED_PAYLOAD.associatedData)
                }},
                key,
                ciphertext
            );
            return JSON.parse(new TextDecoder().decode(plainBuffer));
        }}

        function decodeFile(file) {{
            return base64ToBytes(file.data);
        }}

        function bytesToText(bytes) {{
            return new TextDecoder().decode(bytes);
        }}

        function normalizeAssetPath(value, mainPath) {{
            if (!value || /^(https?:|data:|blob:|mailto:|tel:|#)/i.test(value)) {{
                return null;
            }}
            const withoutQuery = value.split("#")[0].split("?")[0];
            const base = "https://kc110.local/" + mainPath;
            const normalized = new URL(withoutQuery, base).pathname.replace(/^\\//, "");
            return normalized;
        }}

        function injectResponsiveImageStyle(doc) {{
            const style = doc.createElement("style");
            style.textContent = "img,video,canvas,svg{{max-width:100%;height:auto;}}";
            doc.head.appendChild(style);
        }}

        function rewriteDocumentAssets(doc, bundle, objectUrls) {{
            const attributes = ["src", "href", "poster"];
            const mainPath = bundle.main;
            doc.querySelectorAll("*").forEach((element) => {{
                attributes.forEach((attr) => {{
                    if (!element.hasAttribute(attr)) {{
                        return;
                    }}
                    const originalValue = element.getAttribute(attr);
                    const normalized = normalizeAssetPath(originalValue, mainPath);
                    if (normalized && objectUrls.has(normalized)) {{
                        element.setAttribute(attr, objectUrls.get(normalized));
                    }}
                }});
            }});
        }}

        function renderBundle(bundle) {{
            const files = bundle.files || {{}};
            const mainFile = files[bundle.main];
            if (!mainFile) {{
                throw new Error("加密包缺少主 HTML 文件。");
            }}

            const objectUrls = new Map();
            Object.entries(files).forEach(([path, file]) => {{
                if (path === bundle.main) {{
                    return;
                }}
                const blob = new Blob([decodeFile(file)], {{ type: file.mime || "application/octet-stream" }});
                objectUrls.set(path, URL.createObjectURL(blob));
            }});

            const mainHtml = bytesToText(decodeFile(mainFile));
            const doc = new DOMParser().parseFromString(mainHtml, "text/html");
            injectResponsiveImageStyle(doc);
            rewriteDocumentAssets(doc, bundle, objectUrls);

            const iframe = document.createElement("iframe");
            iframe.className = "viewer";
            iframe.setAttribute("sandbox", "allow-scripts allow-same-origin allow-forms allow-popups");
            iframe.srcdoc = "<!DOCTYPE html>\\n" + doc.documentElement.outerHTML;

            document.body.innerHTML = "";
            document.body.appendChild(iframe);
        }}

        async function handleDecrypt() {{
            const password = passwordInput.value;
            if (!password) {{
                setStatus("请输入密码，或返回构建脚本查看是否生成了自动密码。", true);
                return;
            }}

            decryptButton.disabled = true;
            setStatus("正在进行密钥派生与文档解密，请稍候。", false);

            try {{
                const bundle = await decryptBundle(password);
                setStatus("解密成功，正在加载文档。", false);
                renderBundle(bundle);
            }} catch (error) {{
                decryptButton.disabled = false;
                setStatus("解密失败。请检查密码是否正确，或确认文件未被截断。", true);
                console.error(error);
            }}
        }}

        decryptButton.addEventListener("click", handleDecrypt);
        passwordInput.addEventListener("keydown", (event) => {{
            if (event.key === "Enter") {{
                handleDecrypt();
            }}
        }});
    </script>
</body>
</html>
"""


def html_escape(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def find_private_projects() -> list[Path]:
    if not PRIVATE_DIR.exists():
        log("警告", f"未找到私有目录：{PRIVATE_DIR.relative_to(ROOT_DIR)}")
        return []
    ignored_dir_names = {"assets", "__pycache__"}
    return sorted(
        path
        for path in PRIVATE_DIR.iterdir()
        if path.is_dir()
        and path.name not in ignored_dir_names
        and not path.name.startswith(".")
    )


def build_private_documents(password: str, crypto: CryptoModules) -> list[dict[str, Any]]:
    PUBLIC_DIR.mkdir(parents=True, exist_ok=True)
    generated_entries: list[dict[str, Any]] = []
    projects = find_private_projects()
    root_html_files = sorted(PRIVATE_DIR.glob("*.html")) if PRIVATE_DIR.exists() else []

    if not projects and not root_html_files:
        log("警告", "没有发现可加密的 private 文档目录或顶层 HTML 文件。")
        return generated_entries

    def create_root_html_bundle(html_path: Path) -> bytes:
        files: dict[str, dict[str, str]] = {
            html_path.name: file_to_bundle_entry(html_path, Path(html_path.name))
        }
        shared_assets_dir = PRIVATE_DIR / "assets"
        if shared_assets_dir.exists():
            for path in sorted(shared_assets_dir.rglob("*")):
                if not path.is_file():
                    continue
                if should_skip_private_file(path):
                    continue
                relative_path = path.relative_to(PRIVATE_DIR)
                files[relative_path.as_posix()] = file_to_bundle_entry(path, relative_path)

        bundle = {
            "version": PAYLOAD_VERSION,
            "main": html_path.name,
            "files": files,
            "generatedAt": dt.datetime.now().isoformat(timespec="seconds"),
        }
        return json.dumps(bundle, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    def write_encrypted_document(meta: DocumentMeta, bundle: bytes, output_path: Path) -> None:
        payload = encrypt_bytes(bundle, password, crypto)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            encrypted_page_template(payload, meta),
            encoding="utf-8",
        )

        relative_output = output_path.relative_to(ROOT_DIR).as_posix()
        entry: dict[str, Any] = {
            "date": meta.date,
            "title": meta.title,
            "type": meta.doc_type,
            "file_path": relative_output,
        }
        if meta.desc:
            entry["desc"] = meta.desc
        generated_entries.append(entry)
        log(
            "信息",
            f"已生成加密文档：{relative_output}；资源数量：{len(json.loads(bundle.decode('utf-8'))['files'])}",
        )

    for html_path in root_html_files:
        meta = extract_metadata(html_path, html_path.with_suffix(""))
        bundle = create_root_html_bundle(html_path)
        write_encrypted_document(meta, bundle, PUBLIC_DIR / html_path.name)

    for project_dir in projects:
        html_files = sorted(project_dir.glob("*.html"))
        if not html_files:
            log("警告", f"跳过目录 {project_dir.relative_to(ROOT_DIR)}：未发现顶层 HTML 文件。")
            continue

        for html_path in html_files:
            meta = extract_metadata(html_path, project_dir)
            bundle = create_document_bundle(project_dir, html_path)
            write_encrypted_document(meta, bundle, PUBLIC_DIR / project_dir.name / html_path.name)

    return generated_entries


def scan_public_documents() -> list[dict[str, Any]]:
    if not PUBLIC_DIR.exists():
        log("警告", f"未找到公开目录：{PUBLIC_DIR.relative_to(ROOT_DIR)}")
        return []

    entries: list[dict[str, Any]] = []
    for html_path in sorted(PUBLIC_DIR.rglob("*.html")):
        relative_output = html_path.relative_to(ROOT_DIR).as_posix()
        meta = extract_metadata(html_path, html_path.parent)
        entries.append(
            {
                "date": meta.date,
                "title": meta.title,
                "type": meta.doc_type or "Public",
                "file_path": relative_output,
                **({"desc": meta.desc} if meta.desc else {}),
            }
        )
    return entries


def update_files_data(entries: list[dict[str, Any]]) -> None:
    normalized_entries = sorted(
        entries,
        key=lambda item: (item.get("date", ""), item.get("title", "")),
        reverse=True,
    )
    content = (
        "window.filesData = "
        + json.dumps(normalized_entries, ensure_ascii=False, indent=4)
        + ";\n"
    )
    FILES_DATA_PATH.write_text(content, encoding="utf-8")
    log("信息", f"已更新 {FILES_DATA_PATH.name}，文档条目数量：{len(normalized_entries)}。")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "静态文档构建工具：可选择只加密 private 到 public，"
            "或只根据 public 重新生成 files-data.js。"
        ),
    )
    parser.add_argument(
        "--action",
        choices=["encrypt", "index", "all"],
        help=(
            "选择构建动作：encrypt 只加密 private 到 public；"
            "index 只更新 files-data.js；all 先加密再更新索引。"
        ),
    )
    parser.add_argument(
        "--password",
        help="直接指定加密密码。仅在 action 为 encrypt 或 all 时使用；若省略，则进入中文交互。",
    )
    parser.add_argument(
        "--skip-index",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    return parser.parse_args()


def resolve_action(args: argparse.Namespace) -> str:
    if args.skip_index and not args.action:
        log("警告", "--skip-index 已不推荐使用；本次等同于 --action encrypt。")
        return "encrypt"

    if args.action:
        return args.action

    print("请选择要执行的构建动作：")
    print("  1. encrypt  只将 content/private 加密更新到 content/public")
    print("  2. index    只根据 content/public 更新 files-data.js")
    print("  3. all      先执行 encrypt，再执行 index")
    print()
    print("直接按 Enter 默认执行 all。")

    choice_map = {
        "1": "encrypt",
        "encrypt": "encrypt",
        "e": "encrypt",
        "2": "index",
        "index": "index",
        "i": "index",
        "3": "all",
        "all": "all",
        "a": "all",
        "": "all",
    }

    while True:
        try:
            choice = input("请输入选项 [1/2/3，默认 3]：").strip().lower()
        except EOFError:
            fail("当前环境无法交互选择动作，请使用 --action encrypt、--action index 或 --action all。")
        action = choice_map.get(choice)
        if action:
            return action
        print("无效选项。请输入 1、2、3，或 encrypt、index、all。")


def main() -> None:
    args = parse_args()
    action = resolve_action(args)

    log("信息", f"开始执行静态文档构建；当前动作：{action}")

    if action in {"encrypt", "all"}:
        log("信息", "执行动作：private 加密更新到 public。")
        log("信息", f"私有输入目录：{PRIVATE_DIR.relative_to(ROOT_DIR)}")
        log("信息", f"公开输出目录：{PUBLIC_DIR.relative_to(ROOT_DIR)}")
        crypto = require_crypto()
        password = resolve_password(args)
        build_private_documents(password, crypto)

    if action in {"index", "all"}:
        log("信息", "执行动作：public 更新到 files-data.js。")
        log("信息", f"公开扫描目录：{PUBLIC_DIR.relative_to(ROOT_DIR)}")
        public_entries = scan_public_documents()
        update_files_data(public_entries)

    log("信息", "构建流程结束。")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        fail("用户中断了构建流程。", exit_code=130)
