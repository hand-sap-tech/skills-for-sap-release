#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "questionary==2.0.1",
#     "requests==2.31.0",
#     "rich==13.7.1",
#     "cryptography==42.0.5",
# ]
# ///

"""
Skill Installer - 自动下载、解密并安装 Skill 到对应 AI 工具目录
用法: uv run install.py -- --key <encoded_key_string>
"""

import argparse
import base64
import json
import os
import platform
import shutil
import sys
import tempfile
import zipfile
from datetime import date
from pathlib import Path

import questionary
import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


def get_tool_paths() -> dict[str, Path]:
    is_windows = platform.system() == "Windows"
    home = Path.home()
    cwd = Path.cwd()

    if is_windows:
        appdata = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))
        return {
            "opencode": cwd / ".opencode" / "skills",
            "claude-desktop": appdata / "claude" / "skills",
            "cursor": appdata / "Cursor" / "skills",
            "windsurf": appdata / "Codeium" / "windsurf" / "skills",
        }
    else:
        return {
            "opencode": cwd / ".opencode" / "skills",
            "claude-desktop": home / ".claude" / "skills",
            "cursor": home / ".cursor" / "skills",
            "windsurf": home / ".codeium" / "windsurf" / "skills",
        }


def parse_encoded_key_string(
    encoded: str,
) -> tuple[str, str, str, str, str | None, str]:
    try:
        json_bytes = base64.b64decode(encoded)
        payload = json.loads(json_bytes.decode("utf-8"))
    except Exception as e:
        raise ValueError(f"Key string Base64/JSON 解码失败：{e}") from e

    required_fields = ("EmpName", "EmpNO", "EncryptKey", "ContentURL", "SkillName")
    for field in required_fields:
        value = payload.get(field)
        if not isinstance(value, str) or not value:
            raise ValueError(f"Key string 缺少字段：{field}")

    name = payload["EmpName"]
    employee_id = payload["EmpNO"]
    hex_key = payload["EncryptKey"]
    release_url = payload["ContentURL"]
    skill_name = payload["SkillName"]
    skill_dir_name = skill_name.split("/")[-1].strip()
    if not skill_dir_name:
        raise ValueError("Key string 字段 SkillName 格式错误。")

    package_version = None
    version_value = payload.get("Version")
    if isinstance(version_value, str) and version_value:
        package_version = version_value

    if len(hex_key) != 64 or not all(c in "0123456789abcdefABCDEF" for c in hex_key):
        raise ValueError("hex_key 格式错误：期望 64 字符 hex 字符串。")

    return name, employee_id, hex_key, release_url, package_version, skill_dir_name


def download_release(url: str, dest: Path) -> None:
    console.print(f"[cyan]正在下载...[/cyan] {url}")
    response = requests.get(url, stream=True, allow_redirects=True, timeout=120)
    response.raise_for_status()

    total = int(response.headers.get("content-length", 0))
    downloaded = 0

    with open(dest, "wb") as f:
        for chunk in response.iter_content(chunk_size=8192):
            f.write(chunk)
            downloaded += len(chunk)

    console.print(f"[green]✓[/green] 下载完成：{dest.name} ({downloaded // 1024} KB)")


def decrypt_file(enc_path: Path, hex_key: str, out_path: Path) -> None:
    console.print("[cyan]正在解密...[/cyan]")

    with open(enc_path, "rb") as f:
        data = f.read()

    if not data.startswith(b"Salted__"):
        raise ValueError("文件格式错误：不是 openssl Salted 格式。")

    salt = data[8:16]
    ciphertext = data[16:]
    key_material = hex_key.encode("utf-8")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=48,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    derived = kdf.derive(key_material)
    aes_key, aes_iv = derived[:32], derived[32:48]

    cipher = Cipher(
        algorithms.AES(aes_key), modes.CBC(aes_iv), backend=default_backend()
    )
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    with open(out_path, "wb") as f:
        f.write(plaintext)

    console.print(f"[green]✓[/green] 解密完成：{out_path.name}")


def select_install_target() -> Path:
    tool_paths = get_tool_paths()

    choices = [
        questionary.Choice(title=f"{name}  →  {str(path)}", value=path)
        for name, path in tool_paths.items()
    ]
    choices.append(questionary.Choice(title="自定义路径...", value="custom"))

    console.print()
    selected = questionary.select(
        "请选择你使用的 AI 工具（skills 将安装到对应目录）：", choices=choices
    ).ask()

    if selected is None:
        console.print("[red]已取消安装。[/red]")
        sys.exit(0)

    if selected == "custom":
        custom_path = questionary.path(
            "请输入自定义 skills 目录路径：", validate=lambda p: True
        ).ask()
        if custom_path is None:
            console.print("[red]已取消安装。[/red]")
            sys.exit(0)
        selected = Path(custom_path)

    confirmed = questionary.confirm(
        f"将 skills 安装到：{selected}\n  如果目录不存在，将自动创建。确认？"
    ).ask()

    if not confirmed:
        console.print("[red]已取消安装。[/red]")
        sys.exit(0)

    return selected


def extract_skills(
    zip_path: Path,
    target_dir: Path,
    skill_dir_name: str,
) -> list[Path]:
    target_dir.mkdir(parents=True, exist_ok=True)
    installed_dirs = []

    with zipfile.ZipFile(zip_path, "r") as zf:
        top_level_entries = set()
        for member in zf.namelist():
            if member:
                top_name = member.split("/", 1)[0]
                if top_name and top_name != "__MACOSX":
                    top_level_entries.add(top_name)
            member_path = (target_dir / member).resolve()
            if not str(member_path).startswith(str(target_dir.resolve())):
                raise ValueError(f"检测到 Zip Slip 攻击，拒绝解压：{member}")

        zf.extractall(target_dir)

    if top_level_entries == {"skills"}:
        skills_root = target_dir / "skills"
        if skills_root.is_dir():
            for child in list(skills_root.iterdir()):
                dest = target_dir / child.name
                if dest.exists():
                    if dest.is_dir():
                        shutil.rmtree(dest)
                    else:
                        dest.unlink()
                child.rename(dest)
            skills_root.rmdir()

    if "SKILL.md" in top_level_entries:
        skill_root = target_dir / skill_dir_name
        skill_root.mkdir(parents=True, exist_ok=True)

        for entry_name in sorted(top_level_entries):
            source = target_dir / entry_name
            if source == skill_root or not source.exists():
                continue

            dest = skill_root / source.name
            if dest.exists():
                if dest.is_dir():
                    shutil.rmtree(dest)
                else:
                    dest.unlink()
            source.rename(dest)

    for entry in target_dir.iterdir():
        if entry.is_dir():
            installed_dirs.append(entry)

    return installed_dirs


def write_watermark_to_skill_mds(
    skills_dir: Path, name: str, employee_id: str, package_version: str
) -> list[Path]:
    today = date.today().isoformat()
    watermark = (
        f'\n<!-- SKILL-INSTALLER: installed_by="{name}" '
        f'employee_id="{employee_id}" '
        f'install_date="{today}" '
        f'package_version="{package_version}" -->\n'
    )

    modified_files = []
    for skill_md in skills_dir.rglob("SKILL.md"):
        content = skill_md.read_text(encoding="utf-8")
        if "SKILL-INSTALLER:" not in content:
            skill_md.write_text(content.rstrip("\n") + watermark, encoding="utf-8")
            modified_files.append(skill_md)

    return modified_files


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Skill Installer — 下载并安装加密的 Skill 包"
    )
    parser.add_argument(
        "--key", required=True, help="encoded_key_string（含用户信息+密钥+下载地址）"
    )
    args = parser.parse_args()

    console.print(
        Panel.fit(
            "[bold cyan]Skill Installer[/bold cyan]\n"
            "自动下载 · 解密 · 安装到 AI 工具目录",
            border_style="cyan",
        )
    )

    try:
        (
            name,
            employee_id,
            hex_key,
            release_url,
            package_version_from_key,
            skill_dir_name,
        ) = parse_encoded_key_string(args.key)
    except ValueError as e:
        console.print(f"[red]✗ Key 解析失败：{e}[/red]")
        return 1

    console.print(f"[dim]已识别用户：{name}（{employee_id}）[/dim]")

    target_dir = select_install_target()

    with tempfile.TemporaryDirectory(prefix="skill-installer-") as tmpdir:
        tmp = Path(tmpdir)
        enc_file = tmp / "skills.zip.enc"
        zip_file = tmp / "skills.zip"

        try:
            download_release(release_url, enc_file)
        except requests.RequestException as e:
            console.print(f"[red]✗ 下载失败：{e}[/red]")
            return 1

        try:
            decrypt_file(enc_file, hex_key, zip_file)
        except Exception as e:
            console.print(f"[red]✗ 解密失败（密钥可能不正确）：{e}[/red]")
            return 1

        console.print(f"[cyan]正在安装到[/cyan] {target_dir}")
        try:
            installed = extract_skills(zip_file, target_dir, skill_dir_name)
        except Exception as e:
            console.print(f"[red]✗ 解压失败：{e}[/red]")
            return 1

    if package_version_from_key:
        package_version = package_version_from_key
    else:
        url_parts = release_url.rstrip("/").split("/")
        package_version = url_parts[-2] if len(url_parts) >= 2 else "unknown"

    modified = write_watermark_to_skill_mds(
        target_dir, name, employee_id, package_version
    )

    console.print()
    table = Table(title="安装完成", border_style="green")
    table.add_column("项目", style="cyan", no_wrap=True)
    table.add_column("详情")

    table.add_row("安装路径", str(target_dir))
    table.add_row(
        "已安装 Skill", "\n".join(d.name for d in installed) or "（无子目录）"
    )
    table.add_row("SKILL.md 水印", f"已写入 {len(modified)} 个文件")
    table.add_row("安装人", f"{name}（{employee_id}）")
    table.add_row("包版本", package_version)

    console.print(table)
    console.print("[bold green]✓ Skill 安装成功！[/bold green]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
