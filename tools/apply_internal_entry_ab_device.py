#!/usr/bin/env python3
"""Apply the research-only OLD-vs-DIRECT_K UI overlay after RENDER1H materialization.

The overlay intentionally patches only MainActivity. It does not touch JNI, native
renderer code, RENDER1H tables, or the normal M11RenderWorkflow control action.
"""
from pathlib import Path

PATH = Path("app/src/main/java/com/m11/diagnostic/MainActivity.java")


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one anchor, found {count}")
    return text.replace(old, new, 1)


def main() -> None:
    text = PATH.read_text()

    text = replace_once(
        text,
        "    private static final int REQUEST_RENDER_M11_STANDARD = 1105;\n",
        "    private static final int REQUEST_RENDER_M11_STANDARD = 1105;\n"
        "    private static final int REQUEST_INTERNAL_ENTRY_AB = 1106;\n",
        "request code",
    )

    render_button = '''        Button render = new Button(this);\n        render.setText("Select Xiaomi DNG — render M11 Standard");\n        render.setOnClickListener(v -> chooseDng(REQUEST_RENDER_M11_STANDARD));\n        body.addView(render);\n'''
    text = replace_once(
        text,
        render_button,
        render_button + '''\n        Button entryAb = new Button(this);\n        entryAb.setText("Select Xiaomi DNG — internal-entry OLD vs DIRECT_K A/B");\n        entryAb.setOnClickListener(v -> chooseDng(REQUEST_INTERNAL_ENTRY_AB));\n        body.addView(entryAb);\n''',
        "A/B button",
    )

    text = replace_once(
        text,
        "                requestCode != REQUEST_REAL_RAW_EXPORT_SOURCE &&\n"
        "                requestCode != REQUEST_RENDER_M11_STANDARD) return;\n",
        "                requestCode != REQUEST_REAL_RAW_EXPORT_SOURCE &&\n"
        "                requestCode != REQUEST_RENDER_M11_STANDARD &&\n"
        "                requestCode != REQUEST_INTERNAL_ENTRY_AB) return;\n",
        "accepted request codes",
    )

    old_branch = '''        } else if (requestCode == REQUEST_REAL_RAW_EXPORT_SOURCE) {\n            pendingExportSource = uri;\n            status.setText("Source DNG selected. Choose where to save the private REALRAW1C AHD gzip export.");\n            chooseExportDestination();\n        } else {\n            status.setText("Rendering M11 Standard from the exact canonical firmware asset. Baseline math is frozen; no highlight workaround is being applied…");\n            new Thread(() -> runM11StandardRender(uri), "m11-render1a-standard").start();\n        }\n'''
    new_branch = '''        } else if (requestCode == REQUEST_REAL_RAW_EXPORT_SOURCE) {\n            pendingExportSource = uri;\n            status.setText("Source DNG selected. Choose where to save the private REALRAW1C AHD gzip export.");\n            chooseExportDestination();\n        } else if (requestCode == REQUEST_INTERNAL_ENTRY_AB) {\n            status.setText("Running same-DNG internal-entry A/B. OLD keeps the frozen bridge + static CC0; DIRECT_K uses firmware K from Xiaomi XYZ D50 + identity CC0. Native RENDER1H remains unchanged…");\n            new Thread(() -> runInternalEntryAb(uri), "m11-internal-entry-ab").start();\n        } else {\n            status.setText("Rendering M11 Standard from the exact canonical firmware asset. Baseline math is frozen; no highlight workaround is being applied…");\n            new Thread(() -> runM11StandardRender(uri), "m11-render1a-standard").start();\n        }\n'''
    text = replace_once(text, old_branch, new_branch, "request dispatch")

    method_anchor = '''    private void runM11StandardRender(Uri uri) {\n'''
    ab_method = '''    private void runInternalEntryAb(Uri uri) {\n        String result;\n        try {\n            result = describeDocument(uri) + "\\n\\n" + M11InternalEntryAbWorkflow.run(this, uri);\n        } catch (Throwable t) {\n            result = "M11 internal-entry A/B FAILED\\n" +\n                    t.getClass().getSimpleName() + ": " + String.valueOf(t.getMessage()) + "\\n\\n" +\n                    "RENDER1H was not promoted or modified. The A/B is fail-closed on exact asset, ISO band, Xiaomi source metadata and native render gates.";\n        }\n        final String text = result;\n        runOnUiThread(() -> status.setText(text));\n    }\n\n'''
    text = replace_once(text, method_anchor, ab_method + method_anchor, "A/B method insertion")

    PATH.write_text(text)
    print("internal-entry A/B device overlay applied")
    print("patched=MainActivity.java only")
    print("native_renderer_modified=false")
    print("normal_RENDER1H_action_preserved=true")


if __name__ == "__main__":
    main()
