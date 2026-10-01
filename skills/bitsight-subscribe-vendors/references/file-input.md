# File Input Parsing

Read the file and parse it. One identifier per line is preferred, but comma-separated values on a single line are also accepted. Skip blank lines and lines starting with `#`.

If the file uses multiple columns (e.g. CSV with headers), scan each value to detect its type — do not rely on column position or header names. Ignore columns that contain emails or other irrelevant data.

Detect each value's type:
```
if matches UUID pattern (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx) → GUID
elif has "." and no "@" → Domain
else → Display name
```

After parsing, show the user a preview before proceeding:
*"I found N identifiers in the file: X GUIDs, Y domains, Z display names. Here's a sample — does this look right?"*

If the file cannot be read or is empty, stop and ask the user to verify the path.

When the user is preparing a file: *"For best results, put one company per line — GUIDs, domains, or names are all fine."*
