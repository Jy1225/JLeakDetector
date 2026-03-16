# JLeaks MLK subset (20)

This subset is reduced from `jleaks_mlk_198` to the 20 samples that best fit the **current RepoAudit Java-MLK scope**.

Selection heuristics used:
- `vuln_subtype == file-noCloseEPath`
- `is_interprocedural == no`
- Defect method has both source and close evidence in `.repoaudit/soot_facts.json` (`source_lines > 0` and `close_sites > 0`)
- In latest run (`result/dfbscan/deepseek-chat/MLK/Java/jleaks_mlk_198/2026-03-16-12-40-24-0/detect_info.json`), each selected file has `detect_count == 1` (low duplicate noise)
- Prefer lower per-file method complexity.

Selected samples: 20
Copied into `bug_files/`: 20

Metadata:
- `metadata/selected_ids.txt`
- `metadata/manifest.csv`
- `metadata/vulnerability_list.csv`
- `metadata/vulnerability_list.md`
