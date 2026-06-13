"""
SecureVault - Application Layer Folder Protection for Windows
Encrypts folder contents using AES-256-GCM and manages access via password dialogs.

Version : 3.0
Changes : Added OneDrive compatibility — auto pauses/resumes OneDrive sync
          during lock/unlock operations to prevent Permission Denied errors.
"""

import sys
import os
import json
import hashlib
import secrets
import shutil
import ctypes
import subprocess
import time
import math
import random
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64
import tkinter as tk
from tkinter import messagebox
import winreg
from datetime import datetime

# ── Constants ──────────────────────────────────────────────────────────────────
APP_NAME        = "SecureVault"
LOCK_META_FILE  = ".securevault_meta"
LOCK_DATA_DIR   = ".securevault_data"
LOCK_ICON_NAME  = "vault_overlay.ico"
ITERATIONS      = 100_000
MAX_ATTEMPTS    = 5

# ── OneDrive helpers ───────────────────────────────────────────────────────────

def _is_onedrive_path(folder: Path) -> bool:
    """Check if the folder lives inside any OneDrive-synced directory."""
    folder_str = str(folder).lower()
    onedrive_paths = [
        os.environ.get("OneDrive", "").lower(),
        os.environ.get("OneDriveConsumer", "").lower(),
        os.environ.get("OneDriveCommercial", "").lower(),
    ]
    return any(od and folder_str.startswith(od) for od in onedrive_paths)


def _pause_onedrive() -> bool:
    """
    Kill OneDrive.exe so it stops holding file locks.
    Returns True if OneDrive was actually running (so we know to restart it later).
    """
    result = subprocess.run(
        ["tasklist", "/fi", "imagename eq OneDrive.exe"],
        capture_output=True, text=True)
    was_running = "OneDrive.exe" in result.stdout

    if was_running:
        subprocess.run(["taskkill", "/f", "/im", "OneDrive.exe"],
                       capture_output=True, check=False)
        time.sleep(2)   # give OneDrive time to fully release file handles

    return was_running


def _resume_onedrive() -> None:
    """Restart OneDrive after operations complete."""
    onedrive_exe = os.path.join(
        os.environ.get("LOCALAPPDATA", ""),
        "Microsoft", "OneDrive", "OneDrive.exe")
    if os.path.exists(onedrive_exe):
        subprocess.Popen([onedrive_exe])


# ── Crypto helpers ─────────────────────────────────────────────────────────────

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


# Chunk size for large-file encryption: 256 MB per chunk.
# AES-GCM max per call = 2^31-1 bytes (~2 GB).
# We stay well below that and keep memory usage bounded.
CHUNK_SIZE = 256 * 1024 * 1024   # 256 MB

def encrypt_data(data: bytes, key: bytes) -> bytes:
    """
    Encrypt bytes using AES-256-GCM with automatic chunking for large files.
    Files <= CHUNK_SIZE: single-chunk (backward compatible, nonce+ciphertext).
    Files >  CHUNK_SIZE: multi-chunk format:
        [magic 4B "SVMC"][chunk_count 4B LE]
        for each chunk: [nonce 12B][ct_len 4B LE][ciphertext+tag]
    """
    aesgcm = AESGCM(key)

    if len(data) <= CHUNK_SIZE:
        # Single chunk — same format as before (fully backward compatible)
        nonce = secrets.token_bytes(12)
        ct    = aesgcm.encrypt(nonce, data, None)
        return nonce + ct

    # Multi-chunk for large files
    chunks = []
    offset = 0
    while offset < len(data):
        chunk = data[offset : offset + CHUNK_SIZE]
        nonce = secrets.token_bytes(12)
        ct    = aesgcm.encrypt(nonce, chunk, None)
        # Store: nonce(12) + ct_len(4) + ct
        ct_len = len(ct).to_bytes(4, "little")
        chunks.append(nonce + ct_len + ct)
        offset += CHUNK_SIZE

    header = b"SVMC" + len(chunks).to_bytes(4, "little")
    return header + b"".join(chunks)


def decrypt_data(blob: bytes, key: bytes) -> bytes:
    """
    Decrypt bytes encrypted by encrypt_data().
    Auto-detects single-chunk vs multi-chunk format.
    """
    aesgcm = AESGCM(key)

    if blob[:4] == b"SVMC":
        # Multi-chunk format
        chunk_count = int.from_bytes(blob[4:8], "little")
        parts       = []
        pos         = 8
        for _ in range(chunk_count):
            nonce  = blob[pos : pos + 12];  pos += 12
            ct_len = int.from_bytes(blob[pos : pos + 4], "little"); pos += 4
            ct     = blob[pos : pos + ct_len]; pos += ct_len
            parts.append(aesgcm.decrypt(nonce, ct, None))
        return b"".join(parts)

    # Single-chunk (original format — backward compatible)
    nonce, ct = blob[:12], blob[12:]
    return aesgcm.decrypt(nonce, ct, None)


def hash_password(password: str, salt: bytes) -> str:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS)
    return base64.b64encode(dk).decode()


# ── Password strength checker ──────────────────────────────────────────────────

# Password rule: exactly 1 lowercase + 1 uppercase + 1 special + 1 digit = 4 chars
PW_RULE_LOWER   = 1
PW_RULE_UPPER   = 1
PW_RULE_SPECIAL = 1
PW_RULE_DIGITS  = 1
PW_RULE_TOTAL   = 4   # 1+1+1+1

def validate_password(password: str):
    """
    Validates password: exactly 1 lowercase + 1 uppercase + 1 special + 1 digit
    = total exactly 4 characters.
    Returns (is_valid, message, color)
    """
    lower   = sum(1 for c in password if c.islower())
    upper   = sum(1 for c in password if c.isupper())
    digits  = sum(1 for c in password if c.isdigit())
    special = sum(1 for c in password if not c.isalnum())
    total   = len(password)

    # Fully valid: each type exactly 1, total exactly 4
    if (lower >= PW_RULE_LOWER and upper >= PW_RULE_UPPER and
            digits >= PW_RULE_DIGITS and special >= PW_RULE_SPECIAL and
            total == PW_RULE_TOTAL):
        return True, "Password format is valid!", "#059669"

    all_types_met = (lower >= PW_RULE_LOWER and upper >= PW_RULE_UPPER and
                     digits >= PW_RULE_DIGITS and special >= PW_RULE_SPECIAL)

    if total > PW_RULE_TOTAL and all_types_met:
        # All char types satisfied — only complain about length
        extra = total - PW_RULE_TOTAL
        return False, f"Too long — remove {extra} character{'s' if extra > 1 else ''}", "#ef4444"

    # Some types still missing
    parts = []
    if lower   < PW_RULE_LOWER:   parts.append(f"{PW_RULE_LOWER - lower} a-z")
    if upper   < PW_RULE_UPPER:   parts.append(f"{PW_RULE_UPPER - upper} A-Z")
    if special < PW_RULE_SPECIAL: parts.append(f"{PW_RULE_SPECIAL - special} !@#")
    if digits  < PW_RULE_DIGITS:  parts.append(f"{PW_RULE_DIGITS - digits} 0-9")
    msg = "Add: " + ",  ".join(parts)
    if total > PW_RULE_TOTAL:
        extra = total - PW_RULE_TOTAL
        msg += f"  —  remove {extra} extra char{'s' if extra > 1 else ''}"
    return False, msg, "#d97706"


def get_format_status(password: str):
    """Live counter display — shows actual counts so user sees exact state."""
    lower   = sum(1 for c in password if c.islower())
    upper   = sum(1 for c in password if c.isupper())
    digits  = sum(1 for c in password if c.isdigit())
    special = sum(1 for c in password if not c.isalnum())
    total   = len(password)
    all_ok  = (lower == PW_RULE_LOWER and upper == PW_RULE_UPPER and
               digits == PW_RULE_DIGITS and special == PW_RULE_SPECIAL and
               total == PW_RULE_TOTAL)
    status = (f"a-z: {lower}/{PW_RULE_LOWER}   A-Z: {upper}/{PW_RULE_UPPER}   "
              f"!@#: {special}/{PW_RULE_SPECIAL}   0-9: {digits}/{PW_RULE_DIGITS}   "
              f"total: {total}/{PW_RULE_TOTAL}")
    return status, "#059669" if all_ok else "#d97706"



def elide_path(path: Path, max_chars=40) -> str:
    path_str = str(path)
    if len(path_str) <= max_chars:
        return path_str
    prefix = path_str[:15]
    suffix = path_str[- (max_chars - 18):]
    return f"{prefix}...{suffix}"


# ── Folder lock / unlock logic ─────────────────────────────────────────────────

def get_lock_layer(folder: Path) -> int:
    """Return 0 = unlocked, 1 = layer-1 locked, 2 = layer-2 locked."""
    meta_path = folder / LOCK_META_FILE
    if not meta_path.exists():
        return 0
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        return meta.get("layer", 1)
    except Exception:
        return 1

def is_locked(folder: Path) -> bool:
    return get_lock_layer(folder) > 0


def lock_folder(folder: Path, password: str) -> None:
    """
    Encrypt folder contents. Supports double-layer encryption.
    - If folder is NOT locked: performs Layer-1 encryption on original files.
    - If folder IS Layer-1 locked: performs Layer-2 encryption on top of
      the existing encrypted data (.svd files + meta), wrapping them so
      that decrypting Layer-2 reveals the Layer-1 encrypted state, and
      only decrypting Layer-1 reveals the original files.
    Auto-pauses OneDrive if needed.
    """
    current_layer = get_lock_layer(folder)
    if current_layer >= 2:
        raise RuntimeError("Maximum 2 encryption layers already applied.")

    onedrive_was_running = False
    if _is_onedrive_path(folder):
        onedrive_was_running = _pause_onedrive()

    try:
        salt    = secrets.token_bytes(32)
        key     = derive_key(password, salt)
        pw_hash = hash_password(password, salt)

        if current_layer == 0:
            # ── LAYER 1: encrypt original user files ─────────────────────────
            data_dir = folder / LOCK_DATA_DIR
            data_dir.mkdir(exist_ok=True)

            # System/shell files Windows manages — always skip
            SKIP_FILES = {"desktop.ini", "thumbs.db", ".ds_store"}

            file_map = {}
            for item in folder.rglob("*"):
                rel   = item.relative_to(folder)
                parts = rel.parts
                if parts and parts[0] in (LOCK_META_FILE, LOCK_DATA_DIR):
                    continue
                if not item.is_file():
                    continue
                if item.name.lower() in SKIP_FILES:
                    continue
                # Strip system/hidden attrs and read
                _set_attrib(item, "-s -h -r")
                try:
                    raw = item.read_bytes()
                except PermissionError:
                    continue   # still unreadable — skip silently
                enc      = encrypt_data(raw, key)
                enc_name = secrets.token_hex(16) + ".svd"
                (data_dir / enc_name).write_bytes(enc)
                file_map[str(rel)] = enc_name
                try:
                    item.unlink()
                except PermissionError:
                    pass   # leave it; won't affect decryption

            # Remove now-empty user subdirectories
            for item in sorted(folder.rglob("*"), key=lambda p: len(p.parts), reverse=True):
                rel   = item.relative_to(folder)
                parts = rel.parts
                if parts and parts[0] in (LOCK_META_FILE, LOCK_DATA_DIR):
                    continue
                if item.is_dir():
                    try:
                        item.rmdir()
                    except OSError:
                        pass

            meta = {
                "version"   : 2,
                "app"       : APP_NAME,
                "layer"     : 1,
                "salt"      : base64.b64encode(salt).decode(),
                "pw_hash"   : pw_hash,
                "file_map"  : file_map,
                "locked"    : True,
                "locked_at" : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "attempts"  : 0,
            }
            (folder / LOCK_META_FILE).write_text(json.dumps(meta, indent=2), encoding="utf-8")

        else:
            # ── LAYER 2: encrypt the Layer-1 meta + all .svd files ───────────
            # Strategy: bundle the existing meta JSON + each .svd blob into a
            # new set of .svd2 files, then replace the meta with Layer-2 info.
            # Decrypting Layer-2 restores exactly this state (meta + .svd files)
            # so the user still sees the Layer-1 encrypted vault afterward.

            data_dir  = folder / LOCK_DATA_DIR
            l1_meta_path = folder / LOCK_META_FILE

            # Read and encrypt the Layer-1 meta file itself as a special entry
            l1_meta_bytes = l1_meta_path.read_bytes()
            enc_meta      = encrypt_data(l1_meta_bytes, key)
            enc_meta_name = secrets.token_hex(16) + ".svd2"
            (data_dir / enc_meta_name).write_bytes(enc_meta)

            # Read and encrypt each Layer-1 .svd file into .svd2
            svd2_map = {"__L1_META__": enc_meta_name}
            for svd_file in list(data_dir.glob("*.svd")):
                raw      = svd_file.read_bytes()
                enc      = encrypt_data(raw, key)
                enc_name = secrets.token_hex(16) + ".svd2"
                (data_dir / enc_name).write_bytes(enc)
                svd2_map[svd_file.name] = enc_name
                svd_file.unlink()

            # Remove the Layer-1 meta (now encrypted inside svd2_map)
            l1_meta_path.unlink(missing_ok=True)

            # Write Layer-2 meta
            meta = {
                "version"   : 2,
                "app"       : APP_NAME,
                "layer"     : 2,
                "salt"      : base64.b64encode(salt).decode(),
                "pw_hash"   : pw_hash,
                "svd2_map"  : svd2_map,   # maps original svd name -> svd2 name
                "locked"    : True,
                "locked_at" : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "attempts"  : 0,
            }
            (folder / LOCK_META_FILE).write_text(json.dumps(meta, indent=2), encoding="utf-8")

        _apply_lock_icon(folder)

    finally:
        if onedrive_was_running:
            _resume_onedrive()


def unlock_folder(folder: Path, password: str):
    """
    Decrypt one layer of the vault. Auto-pauses OneDrive if needed.
    - If Layer-2 locked: decrypts Layer-2 → reveals Layer-1 encrypted state
      (the folder stays locked, showing encrypted .svd files).
    - If Layer-1 locked: decrypts Layer-1 → reveals original files.
    Returns (True, 'ok') | (False, 'wrong') | (False, 'locked_out') | (False, 'tampered')
    """
    meta_path = folder / LOCK_META_FILE
    if not meta_path.exists():
        return True, "ok"

    meta     = json.loads(meta_path.read_text(encoding="utf-8"))
    salt     = base64.b64decode(meta["salt"])
    attempts = meta.get("attempts", 0)
    layer    = meta.get("layer", 1)

    if attempts >= MAX_ATTEMPTS:
        return False, "locked_out"

    pw_chk = hash_password(password, salt)
    if pw_chk != meta["pw_hash"]:
        meta["attempts"] = attempts + 1
        meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
        return False, "wrong"

    onedrive_was_running = False
    if _is_onedrive_path(folder):
        onedrive_was_running = _pause_onedrive()

    try:
        key      = derive_key(password, salt)
        data_dir = folder / LOCK_DATA_DIR

        if layer == 2:
            # ── Peel Layer-2: decrypt .svd2 files back to .svd + meta ────────
            svd2_map = meta["svd2_map"]

            for orig_name, svd2_name in svd2_map.items():
                svd2_file = data_dir / svd2_name
                try:
                    raw = decrypt_data(svd2_file.read_bytes(), key)
                except Exception:
                    return False, "tampered"

                if orig_name == "__L1_META__":
                    # Restore the Layer-1 meta file
                    meta_path.write_bytes(raw)
                else:
                    # Restore the Layer-1 .svd encrypted file
                    (data_dir / orig_name).write_bytes(raw)

                svd2_file.unlink()

            # Layer-2 meta was already overwritten above (or stays if error).
            # The folder is now Layer-1 locked — keep the lock icon.
            _apply_lock_icon(folder)
            return True, "ok"

        else:
            # ── Peel Layer-1: decrypt .svd files back to original files ──────
            file_map = meta["file_map"]

            for rel_str, enc_name in file_map.items():
                enc_file = data_dir / enc_name
                try:
                    raw = decrypt_data(enc_file.read_bytes(), key)
                except Exception:
                    return False, "tampered"
                dest = folder / rel_str
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(raw)

            shutil.rmtree(data_dir, ignore_errors=True)
            meta_path.unlink(missing_ok=True)
            _remove_lock_icon(folder)
            return True, "ok"

    finally:
        if onedrive_was_running:
            _resume_onedrive()


# ── Icon overlay ───────────────────────────────────────────────────────────────

def _get_icon_path() -> str:
    candidates = [
        Path(sys.executable).parent / "vault_icon.ico",
        Path(__file__).parent / "vault_icon.ico",
        Path(os.environ.get("APPDATA", "")) / APP_NAME / "vault_icon.ico",
    ]
    for c in candidates:
        if c.exists():
            return str(c)
    return ""


def _apply_lock_icon(folder: Path) -> None:
    ini       = folder / "desktop.ini"
    icon_path = _get_icon_path()
    if not icon_path:
        icon_path = "%SystemRoot%\\System32\\shell32.dll,47"
    content = (
        "[.ShellClassInfo]\r\n"
        f"IconResource={icon_path},0\r\n"
        "IconIndex=0\r\n"
        "[ViewState]\r\n"
        "Mode=\r\n"
        "Vid=\r\n"
        "FolderType=Generic\r\n"
    )
    # Strip system/hidden attrs first so we can overwrite it
    if ini.exists():
        _set_attrib(ini, "-s -h -r")
    try:
        ini.write_text(content, encoding="utf-8")
    except PermissionError:
        pass   # Couldn't write desktop.ini — non-fatal, icon won't show
    else:
        _set_attrib(ini, "+s +h")
    _set_attrib(folder, "+r")


def _remove_lock_icon(folder: Path) -> None:
    ini = folder / "desktop.ini"
    if ini.exists():
        _set_attrib(ini, "-s -h")
        ini.unlink(missing_ok=True)
    _set_attrib(folder, "-r")


def _set_attrib(path: Path, flags: str) -> None:
    try:
        subprocess.run(["attrib"] + flags.split() + [str(path)],
                       capture_output=True, check=False)
    except Exception:
        pass


# ── GUI Theme ──────────────────────────────────────────────────────────────────

LIGHT_BG     = "#050312"  # Deep dark cyber violet/black for window background
PANEL_BG     = "#0b0520"  # Glassmorphism dark card background
PANEL_BG2    = "#12052a"  # Radial glow core color
CARD_BG      = "#0b0520"
ACCENT       = "#8b5cf6"  # Vibrant purple
ACCENT_DIM   = "#3b2075"  # Muted purple border/glow
ACCENT2      = "#7c3aec"
ACCENT_GLOW  = "#c084fc"
TEXT_PRI     = "#ffffff"  # White text
TEXT_SEC     = "#e2e8f0"  # Light gray text
TEXT_DIM     = "#94a3b8"  # Slate text
ERROR_COL    = "#ef4444"
ERROR_DIM    = "#270e1a"  # Dark red callout bg
SUCCESS      = "#10b981"
SUCCESS_DIM  = "#07241a"  # Dark green success bg
BORDER       = "#3b2075"
BORDER_LIGHT = "#1e123f"
WARNING      = "#f59e0b"


def _animate_window_entry(win):
    win.attributes("-alpha", 0.0)
    steps = 15
    duration = 200
    delay = duration // steps
    
    def step(i):
        try:
            if i > steps:
                win.attributes("-alpha", 1.0)
                return
            pct = i / steps
            win.attributes("-alpha", pct)
            win.after(delay, step, i + 1)
        except Exception:
            pass
        
    step(1)


def _style_window(win, title, w=480, h=600):
    win.title(title)
    win.configure(bg=LIGHT_BG)
    win.state('zoomed')
    win.attributes("-topmost", True)
    try:
        win.iconbitmap(default="")
    except Exception:
        pass
    _animate_window_entry(win)


def _get_rounded_rect_points(x1, y1, x2, y2, radius=15):
    """Generate points list for rounded rectangle polygon."""
    return [x1+radius, y1,
            x1+radius, y1,
            x2-radius, y1,
            x2-radius, y1,
            x2, y1,
            x2, y1+radius,
            x2, y1+radius,
            x2, y2-radius,
            x2, y2-radius,
            x2, y2,
            x2-radius, y2,
            x2-radius, y2,
            x1+radius, y2,
            x1+radius, y2,
            x1, y2,
            x1, y2-radius,
            x1, y2-radius,
            x1, y1+radius,
            x1, y1+radius,
            x1, y1]


def _draw_rounded_rect(canvas, x1, y1, x2, y2, radius=15, **kwargs):
    """Draw a smooth rounded rectangle on canvas."""
    points = _get_rounded_rect_points(x1, y1, x2, y2, radius)
    return canvas.create_polygon(points, **kwargs, smooth=True)


def _draw_card_with_glow(canvas, x1, y1, x2, y2, radius=18, tags=None):
    """Draw a glassmorphism card with double border glow and smooth drop shadow."""
    # Outer shadow layers
    for offset, width, color in [(6, 4, "#030206"), (4, 3, "#070312"), (2, 2, "#0e0624")]:
        _draw_rounded_rect(canvas, x1+offset, y1+offset, x2+offset, y2+offset, radius=radius, fill=color, outline="", tags=tags)
    # Inner border glows
    for offset, width, color in [(2, 2.5, "#3b2075"), (0, 1.5, "#7c3aed")]:
        _draw_rounded_rect(canvas, x1-offset, y1-offset, x2+offset, y2+offset, radius=radius+offset, fill="", outline=color, width=width, tags=tags)
    # Main dark glass panel
    return _draw_rounded_rect(canvas, x1, y1, x2, y2, radius=radius, fill="#0b0520", outline="#3b2075", width=1.5, tags=tags)




def _create_canvas_btn(canvas, x, y, w, h, text, cmd, primary=True, tags=None):
    """Create a fully animated pill-shaped canvas button in premium cyber styling."""
    if primary:
        bg = "#7c3aed"
        fg = "#ffffff"
        border = "#a78bfa"
        hover_bg = "#6d28d9"
    else:
        bg = "#120a2e"
        fg = "#c084fc"
        border = "#3b2075"
        hover_bg = "#23114d"

    btn_tag = f"btn_{random.randint(1000, 9999)}"
    if tags:
        full_tags = (tags, btn_tag)
    else:
        full_tags = btn_tag

    glow_id = None
    if primary:
        glow_id = _draw_rounded_rect(canvas, x-2, y-2, x+w+2, y+h+2, radius=h//2 + 2,
                                     fill="", outline="#c084fc", width=2.0, tags=full_tags)
        canvas.itemconfig(glow_id, state="hidden")

    rect_id = _draw_rounded_rect(canvas, x, y, x + w, y + h, radius=h//2,
                                 fill=bg, outline=border, width=1.5, tags=full_tags)
    
    text_id = canvas.create_text(x + w//2, y + h//2, text=text,
                                 fill=fg, font=("Segoe UI", 10, "bold"), tags=full_tags)
    
    arrow_id = None
    if primary:
        arrow_id = canvas.create_text(x + w - 24, y + h//2, text=">",
                                      fill=fg, font=("Segoe UI", 11, "bold"), tags=full_tags)

    is_animating = [False]

    def animate_scale(target_state, duration=100):
        if is_animating[0]:
            return
        is_animating[0] = True
        
        steps = 4
        step_time = duration // steps
        
        def step(i):
            try:
                pct = i / steps
                if target_state == 'hover':
                    dx = -2 * pct
                    dy = -2 * pct
                    dw = 4 * pct
                    dh = 4 * pct
                    if arrow_id:
                        canvas.coords(arrow_id, x + w - 24 + 5 * pct, y + h//2)
                elif target_state == 'normal':
                    dx = 0
                    dy = 0
                    dw = 0
                    dh = 0
                    if arrow_id:
                        canvas.coords(arrow_id, x + w - 24, y + h//2)
                elif target_state == 'click':
                    dx = 2 * pct
                    dy = 2 * pct
                    dw = -4 * pct
                    dh = -4 * pct
                    
                canvas.coords(rect_id, *_get_rounded_rect_points(x + dx, y + dy, x + w + dx + dw, y + h + dy + dh, radius=(h + dh)//2))
                if i < steps:
                    canvas.after(step_time, step, i + 1)
                else:
                    is_animating[0] = False
            except Exception:
                is_animating[0] = False
                
        step(1)

    def on_enter(e):
        if glow_id:
            canvas.itemconfig(glow_id, state="normal")
        canvas.itemconfig(rect_id, fill=hover_bg)
        if not primary:
            canvas.itemconfig(text_id, fill="#ffffff")
        animate_scale('hover')

    def on_leave(e):
        if glow_id:
            canvas.itemconfig(glow_id, state="hidden")
        canvas.itemconfig(rect_id, fill=bg)
        if not primary:
            canvas.itemconfig(text_id, fill=fg)
        animate_scale('normal')

    def on_click(e):
        animate_scale('click', duration=50)
        canvas.after(60, lambda: animate_scale('normal', duration=50))
        canvas.after(100, cmd)

    for item in [rect_id, text_id] + ([arrow_id] if arrow_id else []) + ([glow_id] if glow_id else []):
        canvas.tag_bind(item, "<Enter>", on_enter)
        canvas.tag_bind(item, "<Leave>", on_leave)
        canvas.tag_bind(item, "<Button-1>", on_click)

    return {
        "rect_id": rect_id,
        "text_id": text_id,
        "arrow_id": arrow_id,
        "glow_id": glow_id,
        "x": x,
        "y": y,
        "w": w,
        "h": h
    }


def _entry(parent, show=None, bg="#120d2a"):
    """Clean borderless flat Entry widget for canvas lines."""
    return tk.Entry(parent, show=show,
                    bg=bg, fg="#ffffff", insertbackground="#c084fc",
                    relief="flat", font=("Segoe UI", 11),
                    bd=0, highlightthickness=0)


def _version_badge(canvas, x, y, tags=None):
    """Draw a version badge directly on canvas."""
    rect = _draw_rounded_rect(canvas, x, y, x + 48, y + 20, radius=4,
                              fill="#271554", outline="#8b5cf6", width=1, tags=tags)
    txt = canvas.create_text(x + 24, y + 10, text="v3.0", fill="#c084fc",
                             font=("Segoe UI", 9, "bold"), tags=tags)
    return rect, txt


def _progress_bar(parent, w=300, h=6):
    """Create an animated progress bar using canvas."""
    canvas = tk.Canvas(parent, width=w, height=h, bg=PANEL_BG2,
                       highlightthickness=0, bd=0)
    canvas.pack(pady=(8, 4))
    return canvas


def _animate_progress(win, canvas, w=300, h=6, duration_ms=2500):
    """Animate progress bar with a sliding glow effect."""
    bar = canvas.create_rectangle(0, 0, 0, h, fill=ACCENT, outline="")
    glow = canvas.create_rectangle(0, 0, 0, h, fill=ACCENT_DIM, outline="")
    steps = 60
    step_ms = duration_ms // steps

    def _step(i):
        if i > steps:
            return
        pct = i / steps
        bar_w = int(w * pct)
        canvas.coords(bar, 0, 0, bar_w, h)
        glow_start = max(0, bar_w - 40)
        canvas.coords(glow, glow_start, 0, bar_w, h)
        win.after(step_ms, _step, i + 1)

    _step(0)


def _animate_slide_up(canvas, tag="animate_group", offset=60, steps=25, interval_ms=12):
    """Apply a smooth ease-out slide-up transition to canvas elements."""
    canvas.move(tag, 0, offset)
    current_offset = offset

    def step():
        nonlocal current_offset
        if current_offset <= 0:
            return
        move_y = int(current_offset * 0.18) + 1
        if move_y > current_offset:
            move_y = current_offset
        canvas.move(tag, 0, -move_y)
        current_offset -= move_y
        canvas.after(interval_ms, step)

    canvas.after(50, step)


# ── Micro-Interaction Helpers ───────────────────────────────────────────────

def animate_underline(canvas, underline_id, x1, x2, cy, focus_in=True, steps=10, step_time=15):
    cx = (x1 + x2) / 2
    def step(i):
        try:
            pct = i / steps
            if not focus_in:
                pct = 1 - pct
            ease = 1 - (1 - pct) * (1 - pct)
            current_w = (x2 - x1) * ease
            lx1 = cx - current_w / 2
            lx2 = cx + current_w / 2
            canvas.coords(underline_id, lx1, cy, lx2, cy)
            if i < steps:
                canvas.after(step_time, step, i + 1)
        except Exception:
            pass
    step(1)


def pulse_glow(canvas, glow_ids, entry_widget):
    if canvas.focus_get() != entry_widget:
        return
    t = time.time()
    offset = math.sin(t * 5.0) * 0.8
    try:
        canvas.itemconfig(glow_ids[0], width=max(1.0, 1.5 + offset * 0.3))
        canvas.itemconfig(glow_ids[1], width=max(1.5, 2.0 + offset * 0.5))
        canvas.itemconfig(glow_ids[2], width=max(1.5, 2.0 + offset * 0.7))
        canvas.after(50, lambda: pulse_glow(canvas, glow_ids, entry_widget))
    except Exception:
        pass


def trigger_typing_sweep(canvas, x1, x2, cy):
    sweep_w = 40
    sweep_id = canvas.create_line(x1, cy, x1 + sweep_w, cy, fill="#c084fc", width=2.5)
    steps = 15
    step_time = 15
    def step(i):
        try:
            pct = i / steps
            curr_x = x1 + (x2 - x1 - sweep_w) * pct
            canvas.coords(sweep_id, curr_x, cy, curr_x + sweep_w, cy)
            if i == steps:
                canvas.delete(sweep_id)
            else:
                colors = ["#c084fc", "#d8b4fe", "#e9d5ff", "#f3e8ff", "#faf5ff"]
                color_idx = min(i * len(colors) // steps, len(colors) - 1)
                canvas.itemconfig(sweep_id, fill=colors[color_idx])
                canvas.after(step_time, step, i + 1)
        except Exception:
            pass
    step(1)


def _shake_widget(canvas, tag_or_ids, step=0):
    shakes = [12, -20, 16, -12, 8, -5, 3, -1, 0]
    if step >= len(shakes):
        return
    offset = shakes[step]
    canvas.move(tag_or_ids, offset, 0)
    canvas.after(25, lambda: _shake_widget(canvas, tag_or_ids, step + 1))


def _rotate_and_translate_points(points, center_x, center_y, angle_rad, dx, dy):
    cos_a = math.cos(angle_rad)
    sin_a = math.sin(angle_rad)
    new_points = []
    for i in range(0, len(points), 2):
        px = points[i] - center_x
        py = points[i+1] - center_y
        rx = px * cos_a - py * sin_a
        ry = px * sin_a + py * cos_a
        new_points.append(rx + center_x + dx)
        new_points.append(ry + center_y + dy)
    return new_points


def animate_strength_bar(canvas, bar_id, target_w, target_color):
    try:
        coords = canvas.coords(bar_id)
        if not coords:
            return
        curr_x2 = coords[2]
        curr_x1 = coords[0]
        curr_w = curr_x2 - curr_x1
        steps = 8
        step_time = 15
        def step(i):
            try:
                coords_now = canvas.coords(bar_id)
                if not coords_now:
                    return
                pct = i / steps
                w = curr_w + (target_w - curr_w) * pct
                canvas.coords(bar_id, curr_x1, coords_now[1], curr_x1 + w, coords_now[3])
                canvas.itemconfig(bar_id, fill=target_color)
                if i < steps:
                    canvas.after(step_time, step, i + 1)
            except Exception:
                pass
        step(1)
    except Exception:
        pass


def _animate_spinner(canvas, cx, cy, r, active_ref):
    angle = 0
    spinner_id = canvas.create_arc(cx-r, cy-r, cx+r, cy+r, start=angle, extent=270, style="arc", outline="#ffffff", width=2, tags="animate_group")
    
    def loop():
        nonlocal angle
        if not active_ref[0]:
            try:
                canvas.delete(spinner_id)
            except Exception:
                pass
            return
        angle = (angle + 15) % 360
        try:
            canvas.itemconfig(spinner_id, start=angle)
            canvas.after(30, loop)
        except Exception:
            pass
            
    loop()
    return spinner_id


def _set_button_loading(canvas, btn_data, loading_text="SECURING..."):
    canvas.itemconfig(btn_data["text_id"], text=loading_text)
    if btn_data["arrow_id"]:
        canvas.itemconfig(btn_data["arrow_id"], state="hidden")
    
    cx = btn_data["x"] + btn_data["w"] - 35
    cy = btn_data["y"] + btn_data["h"] // 2
    r = 7
    
    active_ref = [True]
    spinner_id = _animate_spinner(canvas, cx, cy, r, active_ref)
    return active_ref, spinner_id


def _create_glow_input(canvas, x, y, w, h, icon="🔑", show="•", tags="animate_group"):
    container_tag = f"input_container_{random.randint(1000, 9999)}"
    if tags:
        full_tags = (tags, container_tag)
    else:
        full_tags = container_tag

    g3 = _draw_rounded_rect(canvas, x-5, y-5, x+w+5, y+h+5, radius=10, fill="", outline="#4c1d95", width=2, tags=full_tags)
    g2 = _draw_rounded_rect(canvas, x-3, y-3, x+w+3, y+h+3, radius=9, fill="", outline="#6d28d9", width=2, tags=full_tags)
    g1 = _draw_rounded_rect(canvas, x-1, y-1, x+w+1, y+h+1, radius=8, fill="", outline="#8b5cf6", width=1.5, tags=full_tags)
    
    canvas.itemconfig(g3, state="hidden")
    canvas.itemconfig(g2, state="hidden")
    canvas.itemconfig(g1, state="hidden")
    
    bg_rect = _draw_rounded_rect(canvas, x, y, x+w, y+h, radius=8, fill="#120d2a", outline="#3b2075", width=1, tags=full_tags)
    
    canvas.create_text(x + 15, y + h//2, text=icon, fill="#c084fc", font=("Segoe UI", 11), tags=full_tags)
    
    cy = y + h - 1.5
    underline_id = canvas.create_line((x+w)/2, cy, (x+w)/2, cy, fill="#c084fc", width=2, tags=full_tags)
    
    entry_widget = _entry(canvas.master, show=show, bg="#120d2a")
    entry_widget.configure(fg="#ffffff", insertbackground="#c084fc")
    entry_x = x + 30
    entry_w = w - 60
    entry_y = y + (h - 22) // 2
    
    entry_win = canvas.create_window(entry_x, entry_y, window=entry_widget, anchor="nw", width=entry_w, height=22, tags=full_tags)
    
    eye_id = None
    slash_id = None
    if show is not None:
        eye_x = x + w - 16
        eye_y = y + h // 2
        eye_id = canvas.create_text(eye_x, eye_y, text="👁", fill=TEXT_DIM, font=("Segoe UI", 11), tags=full_tags)
        slash_id = canvas.create_line(eye_x - 6, eye_y - 6, eye_x + 6, eye_y + 6, fill="#ef4444", width=1.5, tags=full_tags)
        if show == "":
            canvas.itemconfig(slash_id, state="hidden")
            
        def toggle_eye(e):
            curr_show = entry_widget.cget("show")
            if curr_show == "•":
                entry_widget.configure(show="")
                canvas.itemconfig(slash_id, state="hidden")
                canvas.itemconfig(eye_id, fill=ACCENT)
            else:
                entry_widget.configure(show="•")
                canvas.itemconfig(slash_id, state="normal")
                canvas.itemconfig(eye_id, fill=TEXT_DIM)
                
        canvas.tag_bind(eye_id, "<Button-1>", toggle_eye)
        if slash_id:
            canvas.tag_bind(slash_id, "<Button-1>", toggle_eye)
            
        def set_hand_cursor(e):
            canvas.config(cursor="hand2")
        def set_normal_cursor(e):
            canvas.config(cursor="")
            
        canvas.tag_bind(eye_id, "<Enter>", set_hand_cursor)
        canvas.tag_bind(eye_id, "<Leave>", set_normal_cursor)
        if slash_id:
            canvas.tag_bind(slash_id, "<Enter>", set_hand_cursor)
            canvas.tag_bind(slash_id, "<Leave>", set_normal_cursor)
            
    def on_focus_in(e):
        canvas.itemconfig(bg_rect, outline=ACCENT)
        canvas.itemconfig(g1, state="normal")
        canvas.itemconfig(g2, state="normal")
        canvas.itemconfig(g3, state="normal")
        animate_underline(canvas, underline_id, x + 8, x + w - 8, cy, focus_in=True)
        pulse_glow(canvas, [g1, g2, g3], entry_widget)
        
    def on_focus_out(e):
        canvas.itemconfig(bg_rect, outline=BORDER)
        canvas.itemconfig(g1, state="hidden")
        canvas.itemconfig(g2, state="hidden")
        canvas.itemconfig(g3, state="hidden")
        animate_underline(canvas, underline_id, x + 8, x + w - 8, cy, focus_in=False)
        
    def on_key_press(e):
        if e.keysym not in ("Tab", "Return", "BackSpace", "Shift_L", "Shift_R", "Control_L", "Control_R", "Alt_L", "Alt_R", "Caps_Lock", "Escape"):
            trigger_typing_sweep(canvas, x + 8, x + w - 8, cy)
            
    entry_widget.bind("<FocusIn>", on_focus_in)
    entry_widget.bind("<FocusOut>", on_focus_out)
    entry_widget.bind("<KeyPress>", on_key_press)
    
    return entry_widget, container_tag, bg_rect


# ── Premium Cyber Animation Extensions ───────────────────────────────────────

def _trigger_particle_burst(canvas, x, y, color="#c084fc", count=60):
    particles = []
    for _ in range(count):
        angle = random.uniform(0, math.pi * 2)
        speed = random.uniform(2, 8)
        p = {
            "x": x,
            "y": y,
            "vx": math.cos(angle) * speed,
            "vy": math.sin(angle) * speed,
            "size": random.uniform(2, 6),
            "life": 1.0
        }
        pid = canvas.create_oval(
            x, y, x + p["size"], y + p["size"],
            fill=color,
            outline=""
        )
        p["id"] = pid
        particles.append(p)

    def animate():
        active = []
        for p in particles:
            p["x"] += p["vx"]
            p["y"] += p["vy"]
            p["vx"] *= 0.96
            p["vy"] *= 0.96
            p["life"] -= 0.03
            if p["life"] > 0:
                canvas.coords(
                    p["id"],
                    p["x"], p["y"],
                    p["x"] + p["size"], p["y"] + p["size"]
                )
                active.append(p)
            else:
                canvas.delete(p["id"])
        particles[:] = active
        if particles:
            canvas.after(16, animate)

    animate()


def _animate_background_matrix(canvas):
    """Create a 60 FPS moving cyber particle constellation field with radial center glow."""
    particles = []
    canvas.update_idletasks()
    w = max(1200, canvas.winfo_width())
    h = max(800, canvas.winfo_height())
    
    for _ in range(35):
        particles.append({
            "x": random.randint(0, w),
            "y": random.randint(0, h),
            "vx": random.uniform(-0.8, 0.8),
            "vy": random.uniform(-0.8, 0.8),
            "radius": random.uniform(2, 4),
            "color": random.choice(["#8b5cf6", "#7c3aed", "#c084fc", "#4c1d95"])
        })
        
    def loop():
        canvas.delete("bg_net")
        
        # Radial background glows at center
        cx, cy = w // 2, h // 2
        canvas.create_oval(cx - 320, cy - 320, cx + 320, cy + 320, fill="#110729", outline="", tags="bg_net")
        canvas.create_oval(cx - 180, cy - 180, cx + 180, cy + 180, fill="#0f0322", outline="", tags="bg_net")
        
        # Update particles
        for p in particles:
            p["x"] += p["vx"]
            p["y"] += p["vy"]
            
            if p["x"] < 0 or p["x"] > w: p["vx"] *= -1
            if p["y"] < 0 or p["y"] > h: p["vy"] *= -1
            
            canvas.create_oval(p["x"] - p["radius"], p["y"] - p["radius"],
                              p["x"] + p["radius"], p["y"] + p["radius"],
                              fill=p["color"], outline="", tags="bg_net")
                              
        # Connect close nodes
        for i in range(len(particles)):
            for j in range(i + 1, len(particles)):
                dx = particles[i]["x"] - particles[j]["x"]
                dy = particles[i]["y"] - particles[j]["y"]
                dist = math.sqrt(dx*dx + dy*dy)
                if dist < 120:
                    if dist < 50:
                        color = "#2c1552"
                    elif dist < 85:
                        color = "#1e0f39"
                    else:
                        color = "#120a26"
                    canvas.create_line(particles[i]["x"], particles[i]["y"],
                                       particles[j]["x"], particles[j]["y"],
                                       fill=color, width=1, tags="bg_net")
                                       
        canvas.tag_lower("bg_net")
        canvas.after(25, loop)
        
    loop()


def _draw_scanner_ring(canvas, cx, cy):
    """Draw and slowly rotate holographic security arcs behind the card."""
    angle = [0]
    
    def rotate():
        canvas.delete("scanner_ring")
        angle[0] += 0.8
        a = angle[0]
        
        # Dotted outer ring
        canvas.create_oval(cx - 280, cy - 280, cx + 280, cy + 280,
                           outline="#23104c", width=1.5, dash=(4, 8), tags="scanner_ring")
                           
        # Concentric segmented arcs
        canvas.create_arc(cx - 295, cy - 295, cx + 295, cy + 295,
                          start=a, extent=45, style="arc", outline="#7c3aed", width=2.5, tags="scanner_ring")
        canvas.create_arc(cx - 295, cy - 295, cx + 295, cy + 295,
                          start=a + 120, extent=60, style="arc", outline="#c084fc", width=1.5, tags="scanner_ring")
        canvas.create_arc(cx - 295, cy - 295, cx + 295, cy + 295,
                          start=a + 240, extent=30, style="arc", outline="#6d28d9", width=2, tags="scanner_ring")
                          
        # Counter-rotating outer ring
        canvas.create_arc(cx - 312, cy - 312, cx + 312, cy + 312,
                          start=-a * 1.3, extent=90, style="arc", outline="#3b1b70", width=1.5, tags="scanner_ring")
        canvas.create_arc(cx - 312, cy - 312, cx + 312, cy + 312,
                          start=-a * 1.3 + 180, extent=45, style="arc", outline="#4c1d95", width=1.0, tags="scanner_ring")
                          
        canvas.tag_lower("scanner_ring")
        canvas.tag_raise("scanner_ring", "bg_net")
        canvas.after(20, rotate)
        
    rotate()


def _draw_shield_centerpiece(canvas, cx, cy, tags="animate_group"):
    """Draw a vector shield & lock centerpiece representing active security."""
    w, h = 60, 70
    shield_pts = [
        cx, cy - h//2,
        cx + w//2, cy - h//2,
        cx + w//2, cy - h//6,
        cx, cy + h//2,
        cx - w//2, cy - h//6,
        cx - w//2, cy - h//2
    ]
    canvas.create_polygon(shield_pts, fill="#12062e", outline="#8b5cf6", width=2, smooth=True, tags=tags)
    
    inner_w, inner_h = w - 12, h - 12
    inner_pts = [
        cx, cy - inner_h//2,
        cx + inner_w//2, cy - inner_h//2,
        cx + inner_w//2, cy - inner_h//6,
        cx, cy + inner_h//2,
        cx - inner_w//2, cy - inner_h//6,
        cx - inner_w//2, cy - inner_h//2
    ]
    canvas.create_polygon(inner_pts, fill="", outline="#c084fc", width=1, smooth=True, tags=tags)
    
    # Draw Lock inside
    _draw_rounded_rect(canvas, cx - 14, cy, cx + 14, cy + 18, radius=4, fill="#7c3aed", outline="#ffffff", width=1, tags=tags)
    canvas.create_oval(cx - 3, cy + 5, cx + 3, cy + 11, fill="#ffffff", outline="", tags=tags)
    
    # Shackle (starts open, closes down) - drawn as a perfect, smooth, gap-free U-shape
    shackle_pts = []
    shackle_pts.extend([cx - 8, cy + 2])
    shackle_pts.extend([cx - 8, cy - 8])
    for deg in range(180, -10, -10):
        rad = math.radians(deg)
        shackle_pts.extend([cx + 8 * math.cos(rad), cy - 8 - 8 * math.sin(rad)])
    shackle_pts.extend([cx + 8, cy - 8])
    shackle_pts.extend([cx + 8, cy + 2])

    shackle_id = canvas.create_line(
        shackle_pts,
        fill="#ffffff", width=4, capstyle="round", tags=tags
    )
    return shackle_id


def _animate_startup_lock(canvas, shackle_id, cx, cy):
    """Animate shackle closing on startup and emit a radial pulse wave."""
    shackle_y = -8
    canvas.move(shackle_id, 0, shackle_y)
    
    def step(i):
        nonlocal shackle_y
        try:
            if shackle_y < 0:
                shackle_y = min(0, shackle_y + 2)
                canvas.move(shackle_id, 0, 2)
                canvas.after(16, step, i + 1)
            else:
                _pulse_wave(canvas, cx, cy)
                _screen_flash(canvas)
                _shake_canvas_subtle(canvas)
        except Exception:
            pass
    canvas.after(250, step, 1)


def _shake_canvas_subtle(canvas):
    """Micro-tactile camera bounce."""
    shakes = [(2, -1), (-3, 2), (2, -2), (-1, 1), (0, 0)]
    def step(i):
        if i >= len(shakes):
            return
        dx, dy = shakes[i]
        prev_dx = shakes[i-1][0] if i > 0 else 0
        prev_dy = shakes[i-1][1] if i > 0 else 0
        canvas.move("all", dx - prev_dx, dy - prev_dy)
        canvas.after(16, step, i + 1)
    step(0)


def _flash_card_error(canvas, card_id):
    """Briefly flash the glassmorphism border to red and ease back."""
    canvas.itemconfig(card_id, outline="#ef4444", width=2.0)
    canvas.after(100, lambda: canvas.itemconfig(card_id, outline="#991b1b"))
    canvas.after(250, lambda: canvas.itemconfig(card_id, outline="#7c3aed"))
    canvas.after(400, lambda: canvas.itemconfig(card_id, outline="#3b2075", width=1.5))


def _draw_info_panel(canvas, x, y, w, h, icon, title, subtitle, tags="animate_group"):
    """Draw floating micro info panels on left/right fields."""
    _draw_rounded_rect(canvas, x, y, x + w, y + h, radius=8, fill="#0a051d", outline="#341b6b", width=1, tags=tags)
    canvas.create_text(x + 22, y + h//2, text=icon, fill="#c084fc", font=("Segoe UI", 13), tags=tags)
    canvas.create_text(x + 45, y + h//2 - 9, text=title, fill="#ffffff", font=("Segoe UI", 10, "bold"), anchor="w", tags=tags)
    canvas.create_text(x + 45, y + h//2 + 9, text=subtitle, fill="#94a3b8", font=("Segoe UI", 9), anchor="w", tags=tags)


def _draw_bottom_badge(canvas, x, y, w, h, icon, text, tags=None):
    """Draw horizontal mini status badge at window footer."""
    _draw_rounded_rect(canvas, x, y, x + w, y + h, radius=6, fill="#0a051d", outline="#1a0c3a", width=1, tags=tags)
    canvas.create_text(x + 18, y + h//2, text=icon, fill="#c084fc", font=("Segoe UI", 11), tags=tags)
    canvas.create_text(x + 32, y + h//2, text=text, fill="#94a3b8", font=("Segoe UI", 9, "bold"), anchor="w", tags=tags)


def _confetti_burst(canvas, cx, cy, count=45):
    """Celebratory confetti particles that fly outward with gravity and fade."""
    confetti_colors = [
        "#10b981", "#34d399", "#6ee7b7",
        "#a855f7", "#c084fc", "#d8b4fe",
        "#f59e0b", "#fbbf24",
    ]
    particles = []
    for _ in range(count):
        angle = random.uniform(0, math.pi * 2)
        speed = random.uniform(3, 10)
        size_w = random.uniform(3, 7)
        size_h = random.uniform(2, 5)
        color = random.choice(confetti_colors)
        p = {
            "x": cx, "y": cy,
            "vx": math.cos(angle) * speed,
            "vy": math.sin(angle) * speed - random.uniform(2, 5),
            "w": size_w, "h": size_h,
            "life": 1.0,
            "gravity": 0.15,
        }
        pid = canvas.create_rectangle(
            cx - size_w/2, cy - size_h/2,
            cx + size_w/2, cy + size_h/2,
            fill=color, outline="", tags="confetti"
        )
        p["id"] = pid
        particles.append(p)

    def animate():
        alive = []
        for p in particles:
            p["x"] += p["vx"]
            p["y"] += p["vy"]
            p["vy"] += p["gravity"]
            p["vx"] *= 0.98
            p["life"] -= 0.015
            if p["life"] > 0:
                w = p["w"] * p["life"]
                h = p["h"] * p["life"]
                try:
                    canvas.coords(p["id"], p["x"] - w/2, p["y"] - h/2, p["x"] + w/2, p["y"] + h/2)
                    alive.append(p)
                except Exception: pass
            else:
                try: canvas.delete(p["id"])
                except Exception: pass
        particles[:] = alive
        if particles:
            canvas.after(16, animate)
    animate()


def _pulse_wave(canvas, x, y):
    rings = []
    for i in range(3):
        rid = canvas.create_oval(x, y, x, y, outline="#c084fc", width=2)
        rings.append({"id": rid, "r": 0, "delay": i * 10})

    def animate():
        active = False
        for ring in rings:
            if ring["delay"] > 0:
                ring["delay"] -= 1
                active = True
                continue
            ring["r"] += 4
            r = ring["r"]
            canvas.coords(ring["id"], x - r, y - r, x + r, y + r)
            if r < 120:
                active = True
            else:
                canvas.delete(ring["id"])
        if active:
            canvas.after(16, animate)
    animate()


def _screen_flash(canvas):
    w = canvas.winfo_width()
    h = canvas.winfo_height()
    flash = canvas.create_rectangle(0, 0, w, h, fill="#c084fc", outline="")
    alpha = [1.0]

    def fade():
        alpha[0] -= 0.1
        if alpha[0] <= 0:
            canvas.delete(flash)
            return
        colors = ["#f3e8ff", "#e9d5ff", "#ddd6fe", "#c084fc"]
        idx = min(int(alpha[0] * 3), 3)
        canvas.itemconfig(flash, fill=colors[idx])
        canvas.after(16, fade)
    fade()


def _create_progress_ring(canvas, x, y):
    ring = canvas.create_arc(
        x - 60, y - 60, x + 60, y + 60,
        start=90, extent=0, style="arc",
        outline="#10b981", width=6
    )
    percent = canvas.create_text(
        x, y, text="0%",
        fill="white", font=("Segoe UI", 16, "bold")
    )
    return ring, percent



# ── Lock Dialog ────────────────────────────────────────────────────────────────

class LockDialog:
    def __init__(self, folder: Path, current_layer: int = 0):
        self.folder        = folder
        self.current_layer = current_layer   # 0 = fresh, 1 = adding layer 2
        self.result        = False
        self.root          = tk.Tk()
        self.is_lock_dialog = True
        if current_layer == 1:
            title = "SecureVault — Add Layer 2 Encryption"
        else:
            title = "SecureVault — Protect Folder"
        _style_window(self.root, title, 440, 600)
        self._build()
        self.root.mainloop()

    def _build(self):
        r = self.root
        self.root.update()
        win_w = self.root.winfo_width()
        win_h = self.root.winfo_height()
        
        dx = max(0, (win_w - 440) // 2)
        dy = max(0, (win_h - 600) // 2)

        self.canvas = tk.Canvas(r, width=win_w, height=win_h, bg=LIGHT_BG, highlightthickness=0, bd=0)
        self.canvas.pack(fill="both", expand=True)

        # Background particle constellation
        _animate_background_matrix(self.canvas)
        
        # Rotating security scanner arcs behind card
        _draw_scanner_ring(self.canvas, win_w // 2, win_h // 2)

        # Glassmorphic card container
        self.card_id = _draw_card_with_glow(self.canvas, 20 + dx, 20 + dy, 420 + dx, 580 + dy, radius=18, tags="card_group")

        # Shield & closing shackle centerpiece
        self.shackle_id = _draw_shield_centerpiece(self.canvas, 220 + dx, 90 + dy, tags="form_group")
        _animate_startup_lock(self.canvas, self.shackle_id, 220 + dx, 90 + dy)

        # Floating info panels on sides
        _draw_info_panel(self.canvas, dx - 225, 150 + dy, 210, 58, "🔒", "AES-256-GCM", "Military Grade Encryption", tags="card_group")
        _draw_info_panel(self.canvas, dx - 225, 370 + dy, 210, 58, "🔑", "PBKDF2", "100,000 Iterations", tags="card_group")
        _draw_info_panel(self.canvas, dx + 455, 150 + dy, 210, 58, "🛡", "YOUR DATA STAYS YOURS", "Zero Knowledge Architecture", tags="card_group")
        _draw_info_panel(self.canvas, dx + 455, 370 + dy, 210, 58, "👁", "DATA INTEGRITY", "Tamper Proof Protection", tags="card_group")

        # Footer badges
        cx = win_w // 2
        by = win_h - 60
        _draw_bottom_badge(self.canvas, cx - 422, by, 200, 34, "🛡", "AES-256-GCM Encryption", tags="card_group")
        _draw_bottom_badge(self.canvas, cx - 207, by, 200, 34, "🔑", "PBKDF2 100,000 Iterations", tags="card_group")
        _draw_bottom_badge(self.canvas, cx + 8, by, 200, 34, "🔒", "DATA INTEGRITY Verified", tags="card_group")
        _draw_bottom_badge(self.canvas, cx + 223, by, 200, 34, "👁", "TAMPER PROOF Protection", tags="card_group")

        # Card content shifted to fit shield centerpiece
        if self.current_layer == 1:
            main_title    = "Add Layer 2 Encryption"
            main_subtitle = "Double-encrypts your already-locked vault."
            rule_text     = "Set a DIFFERENT passkey for Layer 2"
            badge_label   = "DOUBLE LAYER Protection"
        else:
            main_title    = "Secure Vault"
            main_subtitle = "Secures the folder from unauthorized use."
            rule_text     = f"Rule: {PW_RULE_LOWER} lower + {PW_RULE_UPPER} upper + {PW_RULE_SPECIAL} special + {PW_RULE_DIGITS} digit"
            badge_label   = "AES-256-GCM Encryption"

        self.canvas.create_text(220 + dx, 155 + dy, text=main_title, fill=TEXT_PRI, font=("Segoe UI", 20, "bold"), anchor="center", tags="form_group")
        _version_badge(self.canvas, 310 + dx, 146 + dy, tags="form_group")
        self.canvas.create_text(220 + dx, 182 + dy, text=main_subtitle, fill=TEXT_DIM, font=("Segoe UI", 10, "italic"), anchor="center", tags="form_group")

        # Target pill container
        _draw_rounded_rect(self.canvas, 50 + dx, 204 + dy, 390 + dx, 230 + dy, radius=6, fill="#120d2a", outline="#3b2075", width=1, tags="form_group")
        self.canvas.create_text(220 + dx, 217 + dy, text=f"📁 Target: {elide_path(self.folder.resolve(), 35)}", fill=TEXT_PRI, font=("Segoe UI", 9, "bold"), anchor="center", tags="form_group")

        if _is_onedrive_path(self.folder):
            self.canvas.create_text(220 + dx, 248 + dy, text="☁ OneDrive sync will auto-pause during operation", fill=WARNING, font=("Segoe UI", 9, "bold"), anchor="center", tags="form_group")

        self.canvas.create_text(220 + dx, 272 + dy, text="CONFIGURE PASSKEY", fill=ACCENT_GLOW, font=("Segoe UI", 9, "bold"), anchor="center", tags="form_group")
        self.pw1, self.pw1_tag, self.pw1_rect = _create_glow_input(self.canvas, 90 + dx, 284 + dy, 260, 36, icon="🔑", show="•", tags="form_group")

        self.strength_lbl = self.canvas.create_text(220 + dx, 334 + dy, text=rule_text, fill=TEXT_DIM, font=("Segoe UI", 9), anchor="center", tags="form_group")
        self.format_lbl = self.canvas.create_text(220 + dx, 348 + dy, text="", fill=WARNING, font=("Segoe UI", 9), anchor="center", tags="form_group")
        self.strength_track = self.canvas.create_line(90 + dx, 358 + dy, 350 + dx, 358 + dy, fill="#120d2a", width=4, capstyle="round", tags="form_group")
        self.strength_bar = self.canvas.create_line(90 + dx, 358 + dy, 90 + dx, 358 + dy, fill="#dc2626", width=4, capstyle="round", tags="form_group")

        self.canvas.create_text(220 + dx, 378 + dy, text="VERIFY VAULT PASSKEY", fill=ACCENT_GLOW, font=("Segoe UI", 9, "bold"), anchor="center", tags="form_group")
        self.pw2, self.pw2_tag, self.pw2_rect = _create_glow_input(self.canvas, 90 + dx, 390 + dy, 260, 36, icon="🔒", show="•", tags="form_group")

        self.msg_id = self.canvas.create_text(220 + dx, 442 + dy, text="", fill=ERROR_COL, font=("Segoe UI", 9, "bold"), anchor="center", tags="form_group")

        self.pw1.bind("<KeyRelease>", self._update_strength)
        self.pw2.bind("<Return>", lambda e: self._do_lock())

        btn_label = "ADD LAYER 2   " if self.current_layer == 1 else "SECURE VAULT   "
        self.btn_submit = _create_canvas_btn(self.canvas, 105 + dx, 465 + dy, 230, 46, btn_label, self._do_lock, primary=True, tags="form_group")
        _create_canvas_btn(self.canvas, 105 + dx, 523 + dy, 230, 40, "CANCEL", self.root.destroy, primary=False, tags="form_group")

        _animate_slide_up(self.canvas, "form_group", offset=60)

    def _update_strength(self, event=None):
        win_w = self.root.winfo_width()
        win_h = self.root.winfo_height()
        dx = max(0, (win_w - 440) // 2)
        dy = max(0, (win_h - 600) // 2)
        
        pw = self.pw1.get()
        if not pw:
            self.canvas.itemconfig(self.strength_lbl, text="Rule: 1 lower + 1 upper + 1 special + 1 digit", fill=TEXT_DIM)
            self.canvas.itemconfig(self.format_lbl, text="")
            self.canvas.coords(self.strength_bar, 90 + dx, 358 + dy, 90 + dx, 358 + dy)
            return
        status, color = get_format_status(pw)
        self.canvas.itemconfig(self.strength_lbl, text=status, fill=color)
        valid, msg, mcol = validate_password(pw)
        self.canvas.itemconfig(self.format_lbl, text=msg, fill=mcol)

        lower   = sum(1 for c in pw if c.islower())
        upper   = sum(1 for c in pw if c.isupper())
        digits  = sum(1 for c in pw if c.isdigit())
        special = sum(1 for c in pw if not c.isalnum())
        
        pts = min(lower, PW_RULE_LOWER) + min(upper, PW_RULE_UPPER) + min(digits, PW_RULE_DIGITS) + min(special, PW_RULE_SPECIAL)
        pct = pts / float(PW_RULE_TOTAL)
        if len(pw) > PW_RULE_TOTAL:
            pct = max(0.0, pct - (len(pw) - PW_RULE_TOTAL) * 0.15)
        elif len(pw) < PW_RULE_TOTAL:
            pct = pct * (len(pw) / float(PW_RULE_TOTAL))
            
        target_w = int(260 * pct)
        if pct < 0.4:
            bar_color = "#ef4444"
        elif pct < 0.9:
            bar_color = "#f59e0b"
        else:
            bar_color = "#10b981"
            
        animate_strength_bar(self.canvas, self.strength_bar, target_w, bar_color)


    def _do_lock(self):
        p1 = self.pw1.get()
        p2 = self.pw2.get()

        valid, msg, _ = validate_password(p1)
        if not valid:
            self.canvas.itemconfig(self.msg_id, text=f"⚠ {msg}", fill=ERROR_COL)
            _shake_widget(self.canvas, self.pw1_tag)
            self.canvas.itemconfig(self.pw1_rect, outline=ERROR_COL)
            self.root.after(500, lambda: self.canvas.itemconfig(self.pw1_rect, outline=BORDER))
            return

        if p1 != p2:
            self.canvas.itemconfig(self.msg_id, text="⚠ Passkeys do not match.", fill=ERROR_COL)
            _shake_widget(self.canvas, self.pw2_tag)
            self.canvas.itemconfig(self.pw2_rect, outline=ERROR_COL)
            self.root.after(500, lambda: self.canvas.itemconfig(self.pw2_rect, outline=BORDER))
            self.pw2.delete(0, "end")
            self.pw2.focus_set()
            return

        active_ref, spinner_id = _set_button_loading(self.canvas, self.btn_submit, "SECURING...")

        import threading
        self.crypto_done = False
        self.crypto_error = None
        
        def worker():
            try:
                lock_folder(self.folder, p1)
                self.crypto_done = True
            except Exception as e:
                self.crypto_error = e
                self.crypto_done = True
                
        self.crypto_thread = threading.Thread(target=worker)
        self.crypto_thread.daemon = True
        self.crypto_thread.start()

        self._check_lock_status(active_ref, spinner_id)

    def _check_lock_status(self, active_ref, spinner_id):
        if self.crypto_done:
            active_ref[0] = False
            try:
                self.canvas.delete(spinner_id)
            except Exception:
                pass
            if self.crypto_error:
                self._show_error_screen(self.crypto_error)
            else:
                self.slide_out_inputs(self._success_screen)
        else:
            self.root.after(50, lambda: self._check_lock_status(active_ref, spinner_id))

    def slide_out_inputs(self, callback):
        # Transition instantly to success screen as requested
        callback()

    def _run_securing_animation(self):
        try:
            self.pw1.destroy()
            self.pw2.destroy()
        except Exception:
            pass

        win_w = self.root.winfo_width()
        win_h = self.root.winfo_height()
        dx = max(0, (win_w - 440) // 2)
        dy = max(0, (win_h - 600) // 2)

        cx, cy = 220 + dx, 260 + dy

        # Clear active inputs/labels inside the card
        self.canvas.delete("form_group")

        # Title indicators for securing progress
        self.canvas.create_text(220 + dx, 75 + dy, text="Securing Vault...", fill=ACCENT, font=("Segoe UI", 16, "bold"), anchor="center", tags="sec_anim")
        self.status_txt = self.canvas.create_text(220 + dx, 102 + dy, text="INITIALIZING AES KEY...", fill=TEXT_DIM, font=("Segoe UI", 10), anchor="center", tags="sec_anim")

        # Layered cyber vector folder icon
        folder_pts_back = [
            cx-40, cy-18,
            cx-15, cy-18,
            cx-8,  cy-8,
            cx+40, cy-8,
            cx+40, cy+22,
            cx-40, cy+22
        ]
        self.canvas.create_polygon(folder_pts_back, fill="#12062e", outline="#8b5cf6", width=2, tags="sec_anim")
        folder_pts_front = [
            cx-38, cy-5,
            cx+38, cy-5,
            cx+38, cy+22,
            cx-38, cy+22
        ]
        self.folder_shape = self.canvas.create_polygon(folder_pts_front, fill="#0b0520", outline="#c084fc", width=1.5, tags="sec_anim")

        # Circular progress arcs around the folder
        self.progress_arc = self.canvas.create_arc(cx - 75, cy - 75, cx + 75, cy + 75, start=90, extent=0, style="arc", outline="#10b981", width=4, tags="sec_anim")
        self.progress_txt = self.canvas.create_text(cx, cy + 52, text="0%", fill="#10b981", font=("Segoe UI", 13, "bold"), tags="sec_anim")

        # Scanning digital laser sweeps
        self.laser_glow = self.canvas.create_line(cx - 55, cy - 10, cx + 55, cy - 10, fill="#10b981", width=8, tags="sec_anim")
        self.laser_id = self.canvas.create_line(cx - 55, cy - 10, cx + 55, cy - 10, fill="#34d399", width=2.5, tags="sec_anim")

        # Binary/Hex floating nodes
        chars = ["0", "1", "A", "F", "9", "X", "🔒"]
        binary_chars = []
        for _ in range(12):
            tx = cx + random.randint(-65, 65)
            ty = cy + random.randint(-40, 40)
            cid = self.canvas.create_text(tx, ty, text=random.choice(chars), fill="#8b5cf6", font=("Consolas", 9), tags="sec_anim")
            binary_chars.append({"id": cid, "vy": random.uniform(-1, -3), "x": tx, "y": ty})

        pct_val = [0]
        def _update_pct():
            try:
                if pct_val[0] < 100:
                    if pct_val[0] == 99 and not self.crypto_done:
                        pass
                    else:
                        pct_val[0] += 2
                    
                    pct = pct_val[0]
                    self.canvas.itemconfig(self.progress_txt, text=f"{pct}%")
                    self.canvas.itemconfig(self.progress_arc, extent=-(pct * 3.6))
                    
                    if pct < 30:
                        self.canvas.itemconfig(self.status_txt, text="DERIVING KEYS (PBKDF2)...")
                    elif pct < 65:
                        self.canvas.itemconfig(self.status_txt, text="ENCRYPTING VAULT CONTENTS...")
                    elif pct < 90:
                        self.canvas.itemconfig(self.status_txt, text="PAUSING SYNC HANDLES...")
                    else:
                        self.canvas.itemconfig(self.status_txt, text="FINALIZING DIRECTORIES...")

                    # Smooth laser sine sweep
                    laser_y = cy + 4 + 18 * math.sin(pct * 0.16)
                    self.canvas.coords(self.laser_id, cx - 55, laser_y, cx + 55, laser_y)
                    self.canvas.coords(self.laser_glow, cx - 57, laser_y, cx + 57, laser_y)

                    # Floating digital nodes
                    for char in binary_chars:
                        self.canvas.move(char["id"], 0, char["vy"])
                        char["y"] += char["vy"]
                        if char["y"] < cy - 50:
                            char["y"] = cy + 30
                            char["x"] = cx + random.randint(-65, 65)
                            self.canvas.coords(char["id"], char["x"], char["y"])
                            self.canvas.itemconfig(char["id"], text=random.choice(chars))

                    self.canvas.after(16, _update_pct)
                else:
                    self.canvas.delete("sec_anim")
                    self._trigger_morph_to_lock()
            except Exception:
                self._success_screen()

        _update_pct()

    def _trigger_morph_to_lock(self):
        win_w = self.root.winfo_width()
        win_h = self.root.winfo_height()
        dx = max(0, (win_w - 440) // 2)
        dy = max(0, (win_h - 600) // 2)

        cx, cy = 220 + dx, 260 + dy

        # Spark burst on folder collapse
        _trigger_particle_burst(self.canvas, cx, cy, color="#10b981", count=45)

        # Draw lock body instantly with glowing shadows
        _draw_rounded_rect(self.canvas, cx-25, cy-8, cx+25, cy+22, radius=6, fill="#070312", outline="", tags="morph_group")
        self.lock_body = _draw_rounded_rect(self.canvas, cx-24, cy-10, cx+24, cy+20, radius=6, fill="#12062e", outline="#10b981", width=2.5, tags="morph_group")
        
        # Keyhole
        self.canvas.create_oval(cx-4, cy-1, cx+4, cy+7, fill="#10b981", outline="", tags="morph_group")
        self.canvas.create_polygon(cx-2, cy+5, cx+2, cy+5, cx+1, cy+14, cx-1, cy+14, fill="#10b981", outline="", tags="morph_group")

        # Closed shackle - drawn as a perfect, smooth, gap-free U-shape
        shackle_pts = []
        shackle_pts.extend([cx - 14, cy - 8])
        shackle_pts.extend([cx - 14, cy - 22])
        for deg in range(180, -10, -10):
            rad = math.radians(deg)
            shackle_pts.extend([cx + 14 * math.cos(rad), cy - 22 - 12 * math.sin(rad)])
        shackle_pts.extend([cx + 14, cy - 22])
        shackle_pts.extend([cx + 14, cy - 8])

        self.shackle_id = self.canvas.create_line(
            shackle_pts,
            fill="#10b981", width=4, capstyle="round", tags="morph_group"
        )

        # Tactile visual lock feedback
        _pulse_wave(self.canvas, cx, cy)
        _screen_flash(self.canvas)
        _shake_canvas_subtle(self.canvas)

        self.canvas.after(350, self._success_screen)

    def _show_error_screen(self, ex):
        self.canvas.itemconfig(self.btn_submit["text_id"], text="SECURE VAULT   ")
        if self.btn_submit["arrow_id"]:
            self.canvas.itemconfig(self.btn_submit["arrow_id"], state="normal")
            
        self.canvas.itemconfig(self.msg_id, text=f"❌ Securing failed: {ex}", fill=ERROR_COL)
        _shake_widget(self.canvas, self.pw1_tag)
        self.canvas.itemconfig(self.pw1_rect, outline=ERROR_COL)
        _flash_card_error(self.canvas, self.card_id)

    def _success_screen(self):
        self.canvas.delete("all")

        win_w = self.root.winfo_width()
        win_h = self.root.winfo_height()
        dx = max(0, (win_w - 440) // 2)
        dy = max(0, (win_h - 560) // 2)

        cx, cy = 220 + dx, 200 + dy
        cr = 46

        # Redraw deep background matrix net
        _animate_background_matrix(self.canvas)
        
        # Redraw rotating holographic arcs
        _draw_scanner_ring(self.canvas, win_w // 2, win_h // 2)

        # Centered glassmorphic card container
        _draw_card_with_glow(self.canvas, 20 + dx, 20 + dy, 420 + dx, 540 + dy, radius=18, tags="success_group")

        # Concentric glowing security rings behind checkmark
        self.canvas.create_oval(cx - cr - 16, cy - cr - 16, cx + cr + 16, cy + cr + 16, outline="#10b981", width=1.5, dash=(4, 4), tags="success_group")
        self.canvas.create_oval(cx - cr - 32, cy - cr - 32, cx + cr + 32, cy + cr + 32, outline="#072d21", width=1.0, dash=(2, 2), tags="success_group")

        # Inner green circle checkmark bg
        self.canvas.create_oval(cx - cr, cy - cr, cx + cr, cy + cr, fill=SUCCESS_DIM, outline=SUCCESS, width=3, tags="success_group")

        # Checkmark vector lines
        x1, y1 = cx - 18, cy + 2
        x2, y2 = cx - 6,  cy + 14
        x3, y3 = cx + 18, cy - 12
        self.canvas.create_line(x1, y1, x2, y2, fill=SUCCESS, width=5, capstyle="round", tags="success_group")
        self.canvas.create_line(x2, y2, x3, y3, fill=SUCCESS, width=5, capstyle="round", tags="success_group")

        # Success Title and Subtitle
        self.canvas.create_text(220 + dx, 280 + dy, text="Vault Protected", fill=SUCCESS, font=("Segoe UI", 18, "bold"), anchor="center", tags="success_group")
        self.canvas.create_text(220 + dx, 308 + dy, text="AES-256-GCM Encryption Active", fill=TEXT_DIM, font=("Segoe UI", 10), anchor="center", tags="success_group")

        # Red-left-bordered warning callout notice card
        _draw_rounded_rect(self.canvas, 50 + dx, 338 + dy, 390 + dx, 392 + dy, radius=6, fill=ERROR_DIM, outline="#52121f", width=1, tags="success_group")
        self.canvas.create_line(51 + dx, 344 + dy, 51 + dx, 386 + dy, fill=ERROR_COL, width=4, tags="success_group")
        
        self.canvas.create_text(220 + dx, 356 + dy, text="⚠  CRITICAL NOTICE", fill=ERROR_COL, font=("Segoe UI", 10, "bold"), anchor="center", tags="success_group")
        self.canvas.create_text(220 + dx, 375 + dy, text="Lost passkeys cannot be recovered.", fill="#fca5a5", font=("Segoe UI", 9), anchor="center", tags="success_group")

        # Celebratory success visual cues
        _trigger_particle_burst(self.canvas, cx, cy, color="#10b981", count=50)
        _pulse_wave(self.canvas, cx, cy)

        # Close button
        _create_canvas_btn(self.canvas, 105 + dx, 440 + dy, 230, 46, "CLOSE VAULT", self.root.destroy, primary=True, tags="success_group")


# ── Unlock Dialog ──────────────────────────────────────────────────────────────

class UnlockDialog:
    def __init__(self, folder: Path, current_layer: int = 1):
        self.folder        = folder
        self.current_layer = current_layer   # 1 or 2
        self.result        = False
        self.attempts      = 0
        self.root          = tk.Tk()
        self.root.state("zoomed")
        if current_layer == 2:
            title = "SecureVault — Remove Layer 2"
        else:
            title = "SecureVault — Access Folder"
        if _is_onedrive_path(folder):
            title += "  ☁ OneDrive"
        _style_window(self.root, title, 440, 520)
        self._build()
        self.root.mainloop()

    def _build(self):
        r = self.root
        self.root.update()
        win_w = self.root.winfo_width()
        win_h = self.root.winfo_height()

        dx = max(0, (win_w - 440) // 2)
        dy = max(0, (win_h - 520) // 2)

        self.canvas = tk.Canvas(r, width=win_w, height=win_h, bg=LIGHT_BG, highlightthickness=0, bd=0)
        self.canvas.pack(fill="both", expand=True)

        # Background Constellation matrix net
        _animate_background_matrix(self.canvas)

        # Rotating arcs scanner ring
        _draw_scanner_ring(self.canvas, win_w // 2, win_h // 2)

        # Glassmorphic card container
        self.card_id = _draw_card_with_glow(self.canvas, 20 + dx, 20 + dy, 420 + dx, 500 + dy, radius=18, tags="card_group")

        # Centerpiece Shield and closed lock
        self.shackle_id = _draw_shield_centerpiece(self.canvas, 220 + dx, 90 + dy, tags="form_group")
        _animate_startup_lock(self.canvas, self.shackle_id, 220 + dx, 90 + dy)

        # Floating side info panels
        _draw_info_panel(self.canvas, dx - 225, 130 + dy, 210, 58, "🔒", "AES-256-GCM", "Military Grade Encryption", tags="card_group")
        _draw_info_panel(self.canvas, dx - 225, 310 + dy, 210, 58, "🔑", "PBKDF2", "600,000 Iterations", tags="card_group")
        _draw_info_panel(self.canvas, dx + 455, 130 + dy, 210, 58, "🛡", "YOUR DATA STAYS YOURS", "Zero Knowledge Architecture", tags="card_group")
        _draw_info_panel(self.canvas, dx + 455, 310 + dy, 210, 58, "👁", "DATA INTEGRITY", "Tamper Proof Protection", tags="card_group")

        # Footer badges
        cx = win_w // 2
        by = win_h - 60
        _draw_bottom_badge(self.canvas, cx - 422, by, 200, 34, "🛡", "AES-256-GCM Encryption", tags="card_group")
        _draw_bottom_badge(self.canvas, cx - 207, by, 200, 34, "🔑", "PBKDF2 600,000 Iterations", tags="card_group")
        _draw_bottom_badge(self.canvas, cx + 8, by, 200, 34, "🔒", "DATA INTEGRITY Verified", tags="card_group")
        _draw_bottom_badge(self.canvas, cx + 223, by, 200, 34, "👁", "TAMPER PROOF Protection", tags="card_group")

        # Texts shifted to fit centerpiece
        if self.current_layer == 2:
            unlock_subtitle = "Enter Layer 2 passkey to reveal Layer 1 vault."
            layer_badge     = "🔐 Layer 2 of 2 — Double Encrypted"
            passkey_label   = "ENTER LAYER 2 PASSKEY"
            btn_text        = "REMOVE LAYER 2   "
        else:
            unlock_subtitle = "Decrypts and restores folder access."
            layer_badge     = "🔒 Layer 1 of 1"
            passkey_label   = "ENTER VAULT PASSKEY"
            btn_text        = "OPEN VAULT   "

        self.canvas.create_text(220 + dx, 155 + dy, text="Secure Vault", fill=TEXT_PRI, font=("Segoe UI", 20, "bold"), anchor="center", tags="form_group")
        _version_badge(self.canvas, 310 + dx, 146 + dy, tags="form_group")
        self.canvas.create_text(220 + dx, 182 + dy, text=unlock_subtitle, fill=TEXT_DIM, font=("Segoe UI", 10, "italic"), anchor="center", tags="form_group")

        # Target pill container
        _draw_rounded_rect(self.canvas, 50 + dx, 204 + dy, 390 + dx, 230 + dy, radius=6, fill="#120d2a", outline="#3b2075", width=1, tags="form_group")
        self.canvas.create_text(220 + dx, 217 + dy, text=f"📁 Target: {elide_path(self.folder.resolve(), 35)}", fill=TEXT_PRI, font=("Segoe UI", 9, "bold"), anchor="center", tags="form_group")

        if _is_onedrive_path(self.folder):
            self.canvas.create_text(220 + dx, 248 + dy, text="☁ OneDrive sync will auto-pause during operation", fill=WARNING, font=("Segoe UI", 9, "bold"), anchor="center", tags="form_group")

        self.canvas.create_text(220 + dx, 272 + dy, text=passkey_label, fill=ACCENT_GLOW, font=("Segoe UI", 9, "bold"), anchor="center", tags="form_group")
        self.pw, self.pw_tag, self.pw_rect = _create_glow_input(self.canvas, 90 + dx, 284 + dy, 260, 36, icon="🔑", show="•", tags="form_group")

        self.attempts_lbl = self.canvas.create_text(220 + dx, 342 + dy, text=f"Attempts Remaining: {MAX_ATTEMPTS}", fill=TEXT_SEC, font=("Segoe UI", 9, "bold"), anchor="center", tags="form_group")
        self.msg_id = self.canvas.create_text(220 + dx, 362 + dy, text="", fill=ERROR_COL, font=("Segoe UI", 9, "bold"), anchor="center", tags="form_group")

        self.pw.bind("<Return>", lambda e: self._do_unlock())

        # Buttons
        self.btn_submit = _create_canvas_btn(self.canvas, 105 + dx, 385 + dy, 230, 46, btn_text, self._do_unlock, primary=True, tags="form_group")
        _create_canvas_btn(self.canvas, 105 + dx, 445 + dy, 230, 40, "CANCEL", self.root.destroy, primary=False, tags="form_group")

        _animate_slide_up(self.canvas, "form_group", offset=60)

    def _do_unlock(self):
        pw = self.pw.get()
        if not pw:
            self.canvas.itemconfig(self.msg_id, text="⚠ Please enter passkey.", fill=ERROR_COL)
            _shake_widget(self.canvas, self.pw_tag)
            return

        self.canvas.itemconfig(self.msg_id, text="🔄 Verifying passkey...", fill=ACCENT)
        self.root.update()

        active_ref, spinner_id = _set_button_loading(self.canvas, self.btn_submit, "OPENING...")

        import threading
        self.crypto_done = False
        self.crypto_res = None
        self.crypto_reason = None
        
        def worker():
            try:
                ok, reason = unlock_folder(self.folder, pw)
                self.crypto_res = ok
                self.crypto_reason = reason
                self.crypto_done = True
            except Exception as e:
                self.crypto_res = False
                self.crypto_reason = str(e)
                self.crypto_done = True
                
        self.crypto_thread = threading.Thread(target=worker)
        self.crypto_thread.daemon = True
        self.crypto_thread.start()

        self._check_unlock_status(active_ref, spinner_id)

    def _check_unlock_status(self, active_ref, spinner_id):
        if self.crypto_done:
            active_ref[0] = False
            try:
                self.canvas.delete(spinner_id)
            except Exception:
                pass
            if self.crypto_res:
                self.result = True
                self.slide_out_inputs(self._success_screen)
            else:
                self._show_error_screen(self.crypto_reason)
        else:
            self.root.after(50, lambda: self._check_unlock_status(active_ref, spinner_id))

    def slide_out_inputs(self, callback):
        callback()

    def _show_error_screen(self, reason):
        # Revert spinner button state
        self.canvas.itemconfig(self.btn_submit["text_id"], text="OPEN VAULT   ")
        if self.btn_submit["arrow_id"]:
            self.canvas.itemconfig(self.btn_submit["arrow_id"], state="normal")
            
        _flash_card_error(self.canvas, self.card_id)
        _shake_widget(self.canvas, self.pw_tag)
        self.canvas.itemconfig(self.pw_rect, outline=ERROR_COL)
        self.root.after(500, lambda: self.canvas.itemconfig(self.pw_rect, outline=BORDER))

        if reason == "locked_out":
            self.canvas.itemconfig(self.msg_id, text="🚫 Vault permanently locked.", fill=ERROR_COL)
            self.canvas.itemconfig(self.attempts_lbl, text="Attempts remaining: 0", fill=ERROR_COL)
            self.pw.configure(state="disabled")
        elif reason == "tampered":
            self.canvas.itemconfig(self.msg_id, text="⚠ Integrity failed! Data tampered.", fill=WARNING)
        else:
            self.attempts += 1
            remaining = MAX_ATTEMPTS - self.attempts
            self.canvas.itemconfig(self.attempts_lbl, text=f"Attempts Remaining: {remaining}", fill=ERROR_COL if remaining <= 1 else WARNING)
            self.canvas.itemconfig(self.msg_id, text="❌ Incorrect passkey.", fill=ERROR_COL)
            self.pw.delete(0, "end")
            self.pw.focus_set()

    def _success_screen(self):
        self.canvas.delete("all")

        win_w = self.root.winfo_width()
        win_h = self.root.winfo_height()
        dx = max(0, (win_w - 440) // 2)
        dy = max(0, (win_h - 460) // 2)

        cx, cy = 220 + dx, 175 + dy
        cr = 46

        # Redraw deep background matrix net
        _animate_background_matrix(self.canvas)
        
        # Redraw rotating holographic arcs
        _draw_scanner_ring(self.canvas, win_w // 2, win_h // 2)

        # Centered glassmorphic card container
        _draw_card_with_glow(self.canvas, 20 + dx, 20 + dy, 420 + dx, 440 + dy, radius=18, tags="success_group")

        # Concentric security rings behind checkmark
        self.canvas.create_oval(cx - cr - 16, cy - cr - 16, cx + cr + 16, cy + cr + 16, outline="#10b981", width=1.5, dash=(4, 4), tags="success_group")
        self.canvas.create_oval(cx - cr - 32, cy - cr - 32, cx + cr + 32, cy + cr + 32, outline="#072d21", width=1.0, dash=(2, 2), tags="success_group")

        # Inner green checkmark bg
        self.canvas.create_oval(cx - cr, cy - cr, cx + cr, cy + cr, fill=SUCCESS_DIM, outline=SUCCESS, width=3, tags="success_group")

        # Checkmark vector lines
        x1, y1 = cx - 18, cy + 2
        x2, y2 = cx - 6,  cy + 14
        x3, y3 = cx + 18, cy - 12
        self.canvas.create_line(x1, y1, x2, y2, fill=SUCCESS, width=5, capstyle="round", tags="success_group")
        self.canvas.create_line(x2, y2, x3, y3, fill=SUCCESS, width=5, capstyle="round", tags="success_group")

        if self.current_layer == 2:
            # Layer-2 removed: vault is now Layer-1 locked, do NOT open folder
            success_title    = "Layer 2 Removed!"
            success_subtitle = "Vault is now Layer 1 encrypted. Enter Layer 1 passkey to open."
            def on_close():
                self.root.destroy()
            btn_label = "CLOSE"
        else:
            # Layer-1 removed: original files are restored
            success_title    = "Access Granted!"
            success_subtitle = "Your files have been decrypted."
            def on_close():
                subprocess.Popen(["explorer", str(self.folder)])
                self.root.destroy()
            btn_label = "OPEN FOLDER"

        # Title and subtitle
        self.canvas.create_text(220 + dx, 250 + dy, text=success_title, fill=SUCCESS, font=("Segoe UI", 18, "bold"), anchor="center", tags="success_group")
        self.canvas.create_text(220 + dx, 276 + dy, text=success_subtitle, fill=TEXT_DIM, font=("Segoe UI", 10), anchor="center", tags="success_group")

        # Celebratory particles and waves
        _trigger_particle_burst(self.canvas, cx, cy, color="#10b981", count=50)
        _pulse_wave(self.canvas, cx, cy)

        # Done button
        _create_canvas_btn(self.canvas, 105 + dx, 320 + dy, 230, 46, btn_label, on_close, primary=True, tags="success_group")



# ── Windows Registry helpers ───────────────────────────────────────────────────

def get_script_path() -> str:
    return os.path.abspath(__file__)


def register_context_menu() -> None:
    python_exe = sys.executable

    def _set(key_path, name, value):
        with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, key_path) as k:
            winreg.SetValueEx(k, name, 0, winreg.REG_SZ, value)

    script = get_script_path()
    cmd    = f'"{python_exe}" "{script}" lock "%1"'

    _set(r"Directory\shell\SecureVault",         "",     "🔐 Protect with SecureVault")
    _set(r"Directory\shell\SecureVault",         "Icon", python_exe)
    _set(r"Directory\shell\SecureVault\command", "",     cmd)
    print("✅  SecureVault context menu registered successfully.")


def unregister_context_menu() -> None:
    def _del(key_path):
        try:
            winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, key_path)
        except FileNotFoundError:
            pass

    _del(r"Directory\shell\SecureVault\command")
    _del(r"Directory\shell\SecureVault")
    print("✅  SecureVault context menu removed successfully.")


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("SecureVault v3.0 — Folder Encryption Tool")
        print("=" * 45)
        print("Usage:")
        print("  secure_vault.py install          — register right-click menu")
        print("  secure_vault.py uninstall        — remove right-click menu")
        print("  secure_vault.py lock <folder>    — protect or access a folder")
        sys.exit(0)

    cmd = sys.argv[1].lower()

    if cmd == "install":
        if ctypes.windll.shell32.IsUserAnAdmin() == 0:
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, " ".join(sys.argv), None, 1)
            sys.exit(0)
        register_context_menu()

    elif cmd == "uninstall":
        if ctypes.windll.shell32.IsUserAnAdmin() == 0:
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, " ".join(sys.argv), None, 1)
            sys.exit(0)
        unregister_context_menu()

    elif cmd == "lock":
        if len(sys.argv) < 3:
            print("❌  Error: folder path is required.")
            sys.exit(1)

        folder = Path(sys.argv[2])
        if not folder.is_dir():
            messagebox.showerror(APP_NAME,
                f"The selected path is not a valid folder:\n{folder}")
            sys.exit(1)

        layer = get_lock_layer(folder)

        if layer == 0:
            # Unlocked → show Lock dialog (Layer 1)
            dlg = LockDialog(folder, current_layer=0)

        elif layer == 1:
            # Layer-1 locked → ask user: unlock Layer 1 OR add Layer 2?
            import tkinter as _tk
            _root = _tk.Tk()
            _root.withdraw()
            choice = messagebox.askquestion(
                APP_NAME,
                "This folder is protected with Layer 1 encryption.\n\n"
                "What would you like to do?\n\n"
                "YES  → Unlock / Decrypt Layer 1\n"
                "NO   → Add Layer 2 (double encrypt)",
                icon="question"
            )
            _root.destroy()
            if choice == "yes":
                # Unlock Layer 1
                dlg = UnlockDialog(folder, current_layer=1)
            else:
                # Add Layer 2
                dlg = LockDialog(folder, current_layer=1)

        elif layer == 2:
            # Layer-2 locked → can only unlock Layer 2 first
            dlg = UnlockDialog(folder, current_layer=2)

    else:
        print(f"❌  Unknown command: '{cmd}'")
        print("    Run without arguments to see usage.")
        sys.exit(1)


if __name__ == "__main__":
    main()
