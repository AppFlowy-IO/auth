# AppFlowy Branch Migration History

**Version:** 2.0
**Date:** 2025-11-08
**Status:** ✅ Migration Complete | ✅ Tests Added | 📝 Ready for PR

---

## Executive Summary

The `appflowy` branch (28 commits, 251 commits behind master) contained password management features. We created `appflowy2` from latest master and systematically merged these features.

**Result:** `appflowy2` = master (latest) + appflowy features (11 commits) + tests (21 new tests)

---

## Branch Timeline

```mermaid
timeline
    title AppFlowy Migration Timeline

    March 2024 : Divergence Point (10fa347)
               : appflowy branches from master

    March-Oct 2024 : Parallel Development
                   : appflowy → 28 commits (password features)
                   : master → 251 commits (OAuth 2.1, WebAuthn, etc.)

    Nov 8, 2025 : Migration
                : Created appflowy2 from master
                : Merged 11 feature commits
                : Added 21 unit tests
                : ✅ All tests pass
```

---

## What We Migrated

```mermaid
mindmap
  root((appflowy2<br/>11 Commits))
    Core Feature
      IsNonDefaultPassword field
      Database migration
    New APIs
      GET /user/auth-info
      POST /user/change-password
    Enhancements
      Regex password validation
      Enhanced error messages
      OTP detailed errors
    Infrastructure
      AutoCreateNamespace config
      Migration timeout
      Admin user support
```

**Key Features:**
1. **IsNonDefaultPassword** - Track if user set their own password vs admin-set
2. **Change Password API** - Dedicated endpoint with old password validation
3. **Regex Validation** - Support patterns like `[0-9]`, `[a-zA-Z]` (master only has literal chars)
4. **Better Errors** - WeakPasswordError now includes `min_length` and `required_characters`
5. **Auto Schema** - AutoCreateNamespace config for easier deployment

---

### In-Place Patches to Upstream Migrations

In addition to the cherry-picked feature commits, the following upstream files
have been modified in place. Re-apply these on every merge from master:

| File | Patch | Why |
|------|-------|-----|
| `migrations/20240612123726_enable_rls_update_grants.up.sql` | Wraps the `grant select … to postgres with grant option` block in `if exists (select 1 from pg_roles where rolname = 'postgres') then … end if;` | Upstream hardcodes the `postgres` role. Self-hosted deployments using a non-default DB superuser hit `ERROR: role "postgres" does not exist (SQLSTATE 42704)` and crash-loop on first start. RLS is still enabled unconditionally; only the grants are gated. See AppFlowy-Cloud issue #1615. |

**On every master merge:** check `git diff master..HEAD -- migrations/20240612123726_enable_rls_update_grants.up.sql` is non-empty and the conditional is still present. If a merge undoes the patch (e.g., upstream rewrites the file), re-apply the gate before tagging a release.

---

## Verification: Master Does NOT Have These

✅ **All 11 commits are necessary** - Verified against current master (commit `4e8275f`):

| Feature | Master Has It? | Impact |
|---------|----------------|--------|
| IsNonDefaultPassword field | ❌ NO | Core new feature for password tracking |
| POST /user/change-password | ❌ NO | Master only has PUT /user (different logic) |
| GET /user/auth-info | ❌ NO | New endpoint for auth status |
| Regex password validation | ❌ NO | Master uses literal `strings.ContainsAny()` |
| Enhanced WeakPasswordError | ❌ NO | Missing `min_length`/`required_characters` |
| AutoCreateNamespace | ❌ NO | New deployment option |
| OTP detailed errors | ❌ NO | Master returns `bool`, not `(bool, error)` |

**Why separate?** Master focused on OAuth/WebAuthn while appflowy focused on password security. Parallel development on different features.

---

## Commit Mapping (17→11)

```mermaid
graph LR
    subgraph appflowy[appflowy: 17 commits]
        A1[8fa035f: Error fields]
        A2[ed02a80: IsNonDefaultPassword]
        A3[2d6ec37 + c58b94a: APIs]
        A4[8eeed99: Regex]
        A5[ea99d5c + bfad335: OTP]
        A6[ec1dbcd: Recovery]
        A7[b435be1 + 5 more: Config]
    end

    subgraph appflowy2[appflowy2: 11 commits]
        B1[6b0bd34: WeakPasswordError]
        B2[f42bf63: User model]
        B3[255c886: Migration]
        B4[77e19de: Regex]
        B5[0342fac: API endpoints]
        B6[45462bf: Config]
        B7[b378172: OTP]
        B8[22562d4: Recovery]
        B9[4e2c148: Migration cmd]
        B10[4a85725: Admin]
        B11[60a5f95: Fixes]
    end

    A1 --> B1
    A2 --> B2
    A2 --> B3
    A3 --> B5
    A4 --> B4
    A5 --> B7
    A6 --> B8
    A7 --> B6
    A7 --> B9

    style appflowy fill:#e1f5ff
    style appflowy2 fill:#e8f5e9
```

**Mapping Summary:**
- 7 commits: 1:1 mapping
- 2 commits: Split (model split from migration)
- 9 commits: Combined (6 config commits → 2)

---

## Test Coverage

**Added 21 new tests** across 4 files (~475 lines):

```mermaid
pie title Test Coverage by Category
    "Change Password API" : 7
    "Auth Info API" : 4
    "IsNonDefaultPassword Field" : 4
    "Regex Validation" : 4
    "Recovery Reset" : 2
```

| Test Area | Tests | Status |
|-----------|-------|--------|
| Password validation (regex) | 4 test cases | ✅ PASS |
| POST /user/change-password | 7 functions | ✅ PASS |
| GET /user/auth-info | 4 functions | ✅ PASS |
| IsNonDefaultPassword field | 4 functions | ✅ PASS |
| Recovery reset logic | 2 functions | ✅ PASS |

**Coverage:** 82% (9/11 commits have tests)

**Missing tests:** Migration file and config tests (low priority)

---

## Files Modified

**17 files, ~800 lines added:**

- **API (6 files):** password.go, user.go, verify.go, api.go, helpers.go, errors.go
- **Models (1 file):** user.go
- **Config (1 file):** configuration.go
- **Commands (2 files):** migrate_cmd.go, admin.go
- **Migrations (2 files):** up/down SQL
- **Tests (4 files):** password_test.go, user_test.go, models/user_test.go, verify_test.go
- **Docs (1 file):** This file

---

## How to Test

```bash
# Quick test (automated)
./test-appflowy2.sh

# Or manual
docker-compose -f docker-compose-dev.yml up -d postgres
sleep 10
make migrate_test
make test
docker-compose -f docker-compose-dev.yml down
```

See `TESTING_GUIDE.md` for details.

---

## Branch Status

| Branch | Purpose | Keep? |
|--------|---------|-------|
| `master` | Main development | ✅ Always |
| `appflowy` | Original work (v0.8.0) | ⚠️ Delete after PR |
| `appflowy-backup` | Backup of original | 🔵 Optional |
| `appflowy2` | Merge branch | ⚠️ Delete after PR |

---

## Next Steps

```mermaid
stateDiagram-v2
    [*] --> Review: Current
    Review --> Test: Run tests
    Test --> Push: All pass
    Push --> PR: Create PR
    PR --> Merge: Approved
    Merge --> [*]: Done
```

### Commands

```bash
# 1. Review changes
git diff master..appflowy2 --stat

# 2. Run tests
./test-appflowy2.sh

# 3. Push branch
git push origin appflowy2

# 4. Create PR
gh pr create --base master --head appflowy2 \
  --title "feat: add password management features from appflowy" \
  --body "See appflowy/APPFLOWY_BRANCH_MIGRATION_HISTORY.md"

# 5. After merge
git checkout master && git pull
git branch -d appflowy2
git branch -d appflowy  # Optional
```

---

## Technical Details

### Key Implementation Changes

**1. IsNonDefaultPassword Field**
```go
type User struct {
    IsNonDefaultPassword bool `json:"-" db:"is_non_default_password"`
}
```
- Tracks if user changed their own password
- Reset to false on recovery/email change
- Used by change-password endpoint for validation

**2. Change Password Endpoint**
```go
POST /user/change-password
{
  "current_password": "old",  // Required if IsNonDefaultPassword=true
  "password": "new"
}
```
- Validates current password for user-set passwords
- Rejects same password
- Enforces password strength
- Sets IsNonDefaultPassword=true

**3. Regex Password Validation**
```go
// Old (master): literal characters
strings.ContainsAny(password, "abc")  // Must have 'a' AND 'b' AND 'c'

// New (appflowy2): regex support
regexp.Compile("[0-9]").MatchString(password)  // At least one digit
```

**4. Enhanced Error Response**
```json
{
  "weak_password": {
    "message": "Password is too weak",
    "reasons": ["length", "characters"],
    "min_length": 8,
    "required_characters": ["[0-9]", "[a-zA-Z]"]
  }
}
```

---

## Summary

```mermaid
graph LR
    A[appflowy<br/>28 commits<br/>251 behind] -->|Analyzed| B[17 feature commits]
    B -->|Merged| C[appflowy2<br/>11 commits]
    C -->|Added| D[21 tests]
    D -->|Verified| E[All unique features]
    E -->|Ready| F[PR to master]

    style F fill:#9f9
```

**What we did:**
1. ✅ Created appflowy2 from latest master
2. ✅ Merged 11 unique feature commits
3. ✅ Added 21 comprehensive tests
4. ✅ Verified master doesn't have these features
5. ✅ All tests passing
6. 📝 Ready for PR review

**Impact:** Enhanced password security with better validation, dedicated change password flow, and improved error messages.

---

**Last Updated:** 2025-11-08
**Commits:** appflowy (17) → appflowy2 (11) + tests
**Test Status:** ✅ 21/21 passing
**Build Status:** ✅ Passing
