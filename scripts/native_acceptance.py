"""Exercise the same real frozen Tk controls/core on an explicit synthetic profile; no arbitrary scripts. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: capture — line 82
# parameter: target — line 82
# parameter: window — line 82
# variable: load — line 88
# variable: gdi — line 89
# variable: user — line 89
# variable: pointer — line 90
# variable: arguments — line 91
# variable: library — line 91
# variable: name — line 91
# variable: result — line 91
# variable: function — line 109
# variable: handle — line 112
# variable: rectangle — line 113
# variable: height — line 116
# variable: width — line 116
# variable: source — line 119
# variable: destination — line 120
# variable: bitmap — line 121
# variable: previous — line 122
# variable: pixels — line 127
# variable: header — line 128
# variable: raw — line 135
# variable: scanlines — line 136
# variable: row — line 137
# variable: column — line 139
# variable: offset — line 140
# definition: chunk — line 143
# parameter: data — line 143
# parameter: name — line 143
# definition: exercise — line 165
# parameter: output — line 165
# parameter: reopen — line 165
# parameter: window — line 165
# variable: deadline — line 168
# variable: receipt — line 169
# definition: finish — line 187
# parameter: error — line 187
# variable: data — line 194
# variable: name — line 194
# variable: row — line 196
# definition: checked — line 203
# parameter: callback — line 203
# definition: wait — line 211
# parameter: callback — line 211
# definition: assessed — line 221
# variable: report — line 223
# variable: key — line 224
# definition: drifted — line 242
# variable: drift — line 244
# definition: fleet — line 254
# variable: result — line 256
# variable: parent — line 273
# variable: exported — line 277
# variable: path — line 278
# definition: rejected — line 287
# definition: begin — line 294
# END CODE MAP

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import struct
import sys
import time
import zlib
from pathlib import Path
from typing import TYPE_CHECKING, Any

from hardening import desktop_project as project
from hardening.io import json_value

if TYPE_CHECKING:
    from hardening.desktop import Workbench


def capture(window: Workbench, target: Path) -> None:
    """Capture only this owned synthetic Tk window via PrintWindow, never the user's whole desktop."""
    if sys.platform != "win32":
        raise OSError("native screenshot acceptance targets Windows")
    from ctypes import wintypes

    load = ctypes.WinDLL
    user, gdi = load("user32", use_last_error=True), load("gdi32", use_last_error=True)
    pointer = ctypes.c_void_p
    for library, name, arguments, result in [
        (user, "GetAncestor", [pointer, ctypes.c_uint], pointer),
        (user, "GetWindowDC", [pointer], pointer),
        (gdi, "CreateCompatibleDC", [pointer], pointer),
        (gdi, "CreateCompatibleBitmap", [pointer, ctypes.c_int, ctypes.c_int], pointer),
        (gdi, "SelectObject", [pointer, pointer], pointer),
        (gdi, "DeleteObject", [pointer], ctypes.c_int),
        (gdi, "DeleteDC", [pointer], ctypes.c_int),
        (user, "ReleaseDC", [pointer, pointer], ctypes.c_int),
        (user, "PrintWindow", [pointer, pointer, ctypes.c_uint], ctypes.c_int),
        (user, "GetWindowRect", [pointer, ctypes.POINTER(wintypes.RECT)], ctypes.c_int),
        (
            gdi,
            "GetDIBits",
            [pointer, pointer, ctypes.c_uint, ctypes.c_uint, pointer, pointer, ctypes.c_uint],
            ctypes.c_int,
        ),
    ]:
        function = getattr(library, name)
        function.argtypes, function.restype = arguments, result
    window.root.update_idletasks()
    handle = user.GetAncestor(window.root.winfo_id(), 2)
    rectangle = wintypes.RECT()
    if not user.GetWindowRect(handle, ctypes.byref(rectangle)):
        raise OSError("owned window bounds unavailable")
    width, height = rectangle.right - rectangle.left, rectangle.bottom - rectangle.top
    if not 1 <= width <= 4096 or not 1 <= height <= 4096:
        raise OSError("owned screenshot outside bounded dimensions")
    source = user.GetWindowDC(handle)
    destination = gdi.CreateCompatibleDC(source)
    bitmap = gdi.CreateCompatibleBitmap(source, width, height)
    previous = gdi.SelectObject(destination, bitmap)
    try:
        if not user.PrintWindow(handle, destination, 2):
            raise OSError("owned window rendering unavailable")
        gdi.SelectObject(destination, previous)
        pixels = ctypes.create_string_buffer(width * height * 4)
        header = ctypes.create_string_buffer(
            struct.pack(
                "<IiiHHIIiiII", 40, width, -height, 1, 32, 0, width * height * 4, 0, 0, 0, 0
            )
        )
        if gdi.GetDIBits(source, bitmap, 0, height, pixels, header, 0) != height:
            raise OSError("owned screenshot pixels incomplete")
        raw = pixels.raw
        scanlines = bytearray()
        for row in range(height):
            scanlines.append(0)
            for column in range(width):
                offset = (row * width + column) * 4
                scanlines.extend((raw[offset + 2], raw[offset + 1], raw[offset]))

        def chunk(name: bytes, data: bytes) -> bytes:
            """Encode a bounded standard PNG chunk with its actual CRC."""
            return (
                struct.pack(">I", len(data))
                + name
                + data
                + struct.pack(">I", zlib.crc32(name + data))
            )

        target.write_bytes(
            b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(bytes(scanlines)))
            + chunk(b"IEND", b"")
        )
    finally:
        gdi.SelectObject(destination, previous)
        gdi.DeleteObject(bitmap)
        gdi.DeleteDC(destination)
        user.ReleaseDC(handle, source)


def exercise(window: Workbench, output: Path, reopen: bool) -> None:
    """Drive actual offline audit/drift/fleet controls with independent oracles, not host collectors."""
    output.mkdir(mode=0o700)
    deadline = time.monotonic() + 55
    receipt: dict[str, Any] = {
        "schema": 1,
        "product": project.PRODUCT,
        "version": project.VERSION,
        **window.identity,
        "pid": os.getpid(),
        "parent_pid": os.getppid(),
        "synthetic": True,
        "reopen": reopen,
        "passed": False,
        "steps": [],
    }

    (output / "acceptance.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")

    receipt["tcl_version"] = window.root.tk.call("info", "patchlevel")
    receipt["tk_version"] = window.root.tk.call("package", "require", "Tk")

    def finish(error: bool = False) -> None:
        """Record only synthetic aggregate/hash evidence and request the ordinary graceful exit."""
        receipt["passed"] = not error
        window.acceptance_result = not error
        receipt["bundles"] = {
            str(row["id"]): {
                name: hashlib.sha256(data).hexdigest()
                for name, data in window.state.files(row["id"]).items()
            }
            for row in window.state.history()
        }
        (output / "acceptance.json").write_text(
            json.dumps(receipt, indent=2) + "\n", encoding="utf-8"
        )
        window.exit()

    def checked(callback: Any) -> None:
        """A failed oracle remains a failed receipt; original data is not replaced by a sample or reset."""
        try:
            callback()
        except Exception:
            receipt["failure"] = "native acceptance assertion or operation failed"
            finish(True)

    def wait(callback: Any) -> None:
        """Wait for this owned real operation without retries, collector access or forced shutdown."""
        if time.monotonic() > deadline:
            receipt["failure"] = "owned operation deadline exceeded"
            finish(True)
        elif window.busy:
            window.root.after(60, lambda: wait(callback))
        else:
            checked(callback)

    def assessed() -> None:
        """Assert a scoped deviation is not PASS and inspect real control/review guidance."""
        report = json_value(window.state.files(1)["report.json"])
        assert {key: report["summary"][key] for key in ("PASS", "FAIL", "UNKNOWN", "EXCEPTED")} == {
            "PASS": 2,
            "FAIL": 2,
            "UNKNOWN": 0,
            "EXCEPTED": 1,
        }
        window.search.set("EXCEPTED")
        assert len(window.table.get_children()) == 1
        window.table.selection_set("0")
        window.inspect()
        capture(window, output / "offline-control-review.png")
        receipt["steps"].append("real-offline-assessment-exception-remains-deviation")
        window.prepared.set(project.SCENARIOS[1])
        window.load_prepared()
        window.authorized.set(True)
        window.run_button.invoke()
        wait(drifted)

    def drifted() -> None:
        """Require the original independently documented three regressions from unchanged real drift rules."""
        drift = json_value(window.state.files(2)["drift.json"])
        assert drift["regressions"] == 3 and drift["evidence_gaps"] == 0
        assert len(window.current["Same-host drift"]) == 3
        receipt["steps"].append("real-same-host-policy-bound-drift")
        window.prepared.set(project.SCENARIOS[2])
        window.load_prepared()
        window.authorized.set(True)
        window.run_button.invoke()
        wait(fleet)

    def fleet() -> None:
        """A declared but unobserved third host must contribute five UNKNOWN controls and an owner queue."""
        result = json_value(window.state.files(3)["fleet.json"])
        assert (
            result["expected_hosts"] == 3
            and result["assessed_hosts"] == 2
            and result["missing_hosts"] == 1
        )
        assert result["counts"] == {"PASS": 10, "FAIL": 0, "UNKNOWN": 5, "EXCEPTED": 0}
        assert result["all_expected_controls_pass"] is False
        window.view.set("Evidence refresh queue")
        window.search.set("")
        window.render()
        assert len(window.table.get_children()) == 1
        window.table.selection_set("0")
        window.inspect()
        capture(window, output / "missing-host-refresh.png")
        from unittest.mock import patch

        parent = output / "private-export"
        parent.mkdir()
        with patch("tkinter.filedialog.askdirectory", return_value=str(parent)):
            window.export_button.invoke()
        exported = next(parent.iterdir())
        assert {path.name: path.read_bytes() for path in exported.iterdir()} == window.state.files(
            3
        )
        receipt["steps"].append("real-declared-inventory-missing-unknown-exact-export")
        window.values["as_of"].set("2026-02-30T00:00:00Z")
        window.authorized.set(True)
        window.run_button.invoke()
        wait(rejected)

    def rejected() -> None:
        """Invalid evaluation clocks reject without silently substituting today's clock or deleting results."""
        assert len(window.state.history()) == 3
        assert "rejected" in window.status.get().lower()
        receipt["steps"].append("impossible-clock-retained-prior-evidence")
        finish()

    def begin() -> None:
        """Exercise actual permission/Run/history widgets, with no live collector path in this application."""
        if reopen:
            assert len(window.state.history()) == 3
            window.history_table.selection_set("1")
            window.open_button.invoke()
            assert len(window.current["Control findings"]) == 5
            window.history_table.selection_set("3")
            window.open_button.invoke()
            assert len(window.current["Evidence refresh queue"]) == 1
            receipt["steps"].append("actual-process-reopen-persisted-three-bundles")
            finish()
            return
        assert window.state.history() == []
        window.run_button.invoke()
        assert not window.busy and window.state.history() == []
        window.authorized.set(True)
        window.run_button.invoke()
        wait(assessed)

    checked(begin)
