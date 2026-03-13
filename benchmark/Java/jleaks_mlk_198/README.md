# JLeaks MLK subset (198)

This subset is generated to match the current Java MLK scope in this repo.

Filter rules:
- resource types == file
- root causes == noCloseEPath
- is interprocedural == no
- key variable attribute == local variable
- third-party libraries is empty
- standard libraries is a single java.io.* type
- non-Android only (file/standard libraries/third-party libraries do not contain android/androidx/dalvik)
- max 2 samples per project (keep lowest IDs)

Selected samples: 198
Copied into `bug_files/`: 198

Metadata:
- `metadata/selected_ids.txt`
- `metadata/manifest.csv`

Run note:
- This benchmark contains many standalone bug snippets that are not fully compilable as a project.
- If you use `src/run_repoaudit.sh`, prefer `SOOT_FACTS_MODE=ts-fallback` (or disable soot prefilter).
- The updated script auto-downgrades bridge mode to `ts-fallback` when path contains `jleaks`.
