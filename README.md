# WordPress Security Skills for Claude Code

A collection of Claude Code skills for WordPress security research and bug bounty hunting.

## Skills

### `patchstack-audit`

A senior WordPress security researcher skill targeting the [Patchstack Alliance](https://patchstack.com/alliance/) bug bounty program.

**What it does:**
- Runs Patchstack eligibility gate before wasting time on ineligible plugins
- Maps all entry points: AJAX, REST, admin_post, shortcodes, cron, rewrite endpoints
- Traces every source → sink (SQLi, XSS, LFI, CSRF, Object Injection, File Upload)
- Scores CVSS v3.1 and drops anything below 6.5 or with AC:H automatically
- Produces submission-ready reports in Patchstack's expected format

**Install:**
```
npx skills add https://github.com/sh00von/wordpress-security-skills --skill patchstack-audit
```

**Usage:**
```
/patchstack-audit                                  # from inside a plugin folder
/patchstack-audit C:\path\to\plugin               # explicit path
```

## Requirements

- [Claude Code](https://claude.ai/code)
- Local WordPress install (Laragon or similar)
- PHP + MySQL accessible via CLI

## License

MIT
