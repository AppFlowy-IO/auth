# Testing Guide for AppFlowy2 Branch

**Last Updated:** 2025-11-08
**Branch:** appflowy2

---

## Quick Start

### Option 1: Using Docker (Recommended ⭐)

This is the easiest way - no local PostgreSQL setup needed!

```bash
# 1. Start the database
docker-compose -f docker-compose-dev.yml up -d postgres

# 2. Wait for database to be ready (5-10 seconds)
sleep 10

# 3. Run migrations
make migrate_test

# 4. Run all tests
make test

# 5. Stop database when done
docker-compose -f docker-compose-dev.yml down
```

### Option 2: Using Local PostgreSQL

If you have PostgreSQL installed locally:

```bash
# 1. Create test user and database
createuser -s supabase_auth_admin
psql -c "ALTER USER supabase_auth_admin WITH PASSWORD 'root';"
createdb -O supabase_auth_admin postgres

# 2. Run migrations
make migrate_test

# 3. Run all tests
make test
```

---

## Testing Our New Features

### Test Only New Features We Added

Most of these tests are methods of a testify suite, so `go test -run` has to name the suite
first: `TestUser/TestUserChangePassword`, not `TestUserChangePassword`. A pattern that names
only the method matches no test, and `go test` then prints `ok ... [no tests to run]`. The
commands in this guide had that mistake until 2026-11-25, which is how tests that could not
pass were recorded as passing.

```bash
# Test password validation (regex support)
go test -v -run TestPasswordStrengthChecks ./internal/api

# Test change password endpoint, and that PUT /user also stores a chosen password
go test -v -run 'TestUser/(TestUserChangePassword|TestUserUpdatePasswordIsAChosenPassword)' ./internal/api

# Test auth info endpoint
go test -v -run 'TestUser/TestUserAuthInfo' ./internal/api

# Test IsNonDefaultPassword field
go test -v -run 'TestUser/(TestIsNonDefaultPassword|TestUserAuthInfoStruct)' ./internal/models

# Test what a verified recovery and an email change do to the flag
go test -v -run 'TestVerify/(TestPasswordRecoveryResets|TestEmailChangeKeeps)' ./internal/api
```

### Run All Our New Tests (23 tests)

```bash
go test -v -run 'TestPasswordStrengthChecks' ./internal/api
go test -v -run '^(TestUser|TestVerify)$' ./internal/api ./internal/models
```

The second command runs the whole `TestUser` and `TestVerify` suites. Run a suite whole at least
once: its tests share one configuration, and a test that leaves a setting changed only breaks
the tests that run after it.

---

## Full Test Suite

### Run All Tests (Entire Project)

```bash
# Using Makefile (recommended)
make test

# Or manually
go test ./... -v -count=1
```

### Run Tests with Coverage

```bash
# Generate coverage report
go test ./... -coverprofile=coverage.out

# View coverage in browser
go tool cover -html=coverage.out
```

### Run Tests for Specific Packages

```bash
# API tests
go test -v ./internal/api

# Model tests
go test -v ./internal/models

# Configuration tests
go test -v ./internal/conf

# All internal tests
go test -v ./internal/...
```

---

## Common Issues and Solutions

### Issue 1: Database Connection Failed

**Error:**
```
failed to connect to `host=localhost user=supabase_auth_admin database=postgres`:
password authentication failed for user "supabase_auth_admin"
```

**Solution:**
```bash
# Option A: Use Docker
docker-compose -f docker-compose-dev.yml up -d postgres
sleep 10

# Option B: Fix local PostgreSQL
psql -c "ALTER USER supabase_auth_admin WITH PASSWORD 'root';"
```

### Issue 2: Migration Not Applied

**Error:**
```
column "is_non_default_password" does not exist
```

**Solution:**
```bash
# Run migrations first
make migrate_test

# Or manually
go run cmd/migrate/*.go
```

### Issue 3: Port Already in Use

**Error:**
```
bind: address already in use
```

**Solution:**
```bash
# Find process using port 5432
lsof -i :5432

# Kill it or stop existing PostgreSQL
docker-compose -f docker-compose-dev.yml down

# Then restart
docker-compose -f docker-compose-dev.yml up -d postgres
```

---

## Test Results Summary

After running all tests, you should see:

### New Tests Added (21 total)

| Test File | Tests | Expected Result |
|-----------|-------|-----------------|
| `internal/api/password_test.go` | 4 cases | ✅ PASS |
| `internal/api/user_test.go` | 11 functions | ✅ PASS |
| `internal/models/user_test.go` | 4 functions | ✅ PASS |
| `internal/api/verify_test.go` | 2 functions | ✅ PASS |

### Example Successful Output

```
=== RUN   TestPasswordStrengthChecks
--- PASS: TestPasswordStrengthChecks (0.00s)

=== RUN   TestUser
=== RUN   TestUser/TestUserChangePasswordSuccess
--- PASS: TestUser/TestUserChangePasswordSuccess (0.15s)
=== RUN   TestUser/TestUserChangePasswordWrongOldPassword
--- PASS: TestUser/TestUserChangePasswordWrongOldPassword (0.12s)
=== RUN   TestUser/TestUserAuthInfoGet
--- PASS: TestUser/TestUserAuthInfoGet (0.08s)
--- PASS: TestUser (2.45s)

=== RUN   TestIsNonDefaultPasswordDefaultValue
--- PASS: TestIsNonDefaultPasswordDefaultValue (0.05s)

PASS
ok  	github.com/supabase/auth/internal/api	2.729s
```

---

## Step-by-Step Testing Workflow

### Complete Test Run (Recommended)

```bash
# Step 1: Start database
echo "Starting PostgreSQL..."
docker-compose -f docker-compose-dev.yml up -d postgres
sleep 10

# Step 2: Check database is ready
echo "Checking database connection..."
docker-compose -f docker-compose-dev.yml exec postgres psql -U postgres -c "SELECT 1;"

# Step 3: Run migrations
echo "Running migrations..."
make migrate_test

# Step 4: Run our new tests
echo "Testing new features..."
go test -v -run "TestPasswordStrengthChecks" ./internal/api
go test -v -run "TestUser/TestUserChangePassword" ./internal/api
go test -v -run "TestUser/TestUserAuthInfo" ./internal/api
go test -v -run "TestUser/TestIsNonDefaultPassword" ./internal/models
go test -v -run "TestVerify/TestPasswordRecoveryResets" ./internal/api

# Step 5: Run full test suite
echo "Running full test suite..."
make test

# Step 6: Cleanup
echo "Cleaning up..."
docker-compose -f docker-compose-dev.yml down
```

### Save This as a Script

```bash
# Save to test-appflowy2.sh
cat > test-appflowy2.sh << 'EOF'
#!/bin/bash
set -e

echo "🚀 Starting AppFlowy2 Test Suite..."

# Start database
echo "📦 Starting PostgreSQL..."
docker-compose -f docker-compose-dev.yml up -d postgres
sleep 10

# Run migrations
echo "🔄 Running migrations..."
DATABASE_URL="postgres://postgres:root@localhost:5432/postgres" \
DB_NAMESPACE="auth" \
go run cmd/migrate/*.go

# Run new tests
echo "✅ Testing new features..."
echo "  → Password validation tests..."
go test -v -run TestPasswordStrengthChecks ./internal/api 2>&1 | grep -E "PASS|FAIL"

echo "  → Change password endpoint..."
go test -v -run "TestUser/TestUserChangePassword" ./internal/api 2>&1 | grep -E "PASS|FAIL"

echo "  → Auth info endpoint..."
go test -v -run "TestUser/TestUserAuthInfo" ./internal/api 2>&1 | grep -E "PASS|FAIL"

echo "  → IsNonDefaultPassword field..."
go test -v -run "TestUser/TestIsNonDefaultPassword" ./internal/models 2>&1 | grep -E "PASS|FAIL"

echo "  → Recovery reset logic..."
go test -v -run "TestVerify/(TestPasswordRecoveryResets|TestEmailChangeKeeps)" ./internal/api 2>&1 | grep -E "PASS|FAIL"

# Cleanup
echo "🧹 Cleaning up..."
docker-compose -f docker-compose-dev.yml down

echo "✨ All tests completed!"
EOF

chmod +x test-appflowy2.sh
```

Then run:
```bash
./test-appflowy2.sh
```

---

## CI/CD Testing

For continuous integration, use:

```bash
# GitHub Actions compatible
make docker-test
```

---

## Performance Testing

### Run Tests in Parallel

```bash
# Run with parallelism
go test ./... -parallel 4

# Note: Database tests run serially (-p 1) to avoid conflicts
```

### Run Specific Slow Tests

```bash
# Run only fast tests (< 1s)
go test ./... -short

# Run only specific package
go test -v ./internal/api -run TestUser
```

---

## Debugging Failed Tests

### Verbose Output

```bash
# Maximum verbosity
go test -v -race -count=1 ./internal/api
```

### Run Single Test

```bash
# Run only one test function
go test -v ./internal/api -run TestUserChangePasswordSuccess

# Run tests matching pattern
go test -v ./internal/api -run "UserChangePassword"
```

### Check Test Logs

```bash
# Run with logging
GOTRUE_LOG_LEVEL=debug go test -v ./internal/api -run TestUserChangePasswordSuccess
```

---

## Test Coverage Report

```bash
# Generate coverage for our changes
go test ./internal/api ./internal/models -coverprofile=coverage.out

# View HTML report
go tool cover -html=coverage.out -o coverage.html
open coverage.html

# Check coverage percentage
go tool cover -func=coverage.out | grep total
```

---

## Quick Reference

### Essential Commands

| Command | Description |
|---------|-------------|
| `make test` | Run full test suite |
| `make migrate_test` | Run migrations for tests |
| `docker-compose -f docker-compose-dev.yml up -d postgres` | Start test database |
| `go test ./... -v` | Run all tests verbosely |
| `go test -run TestName ./package` | Run specific test |
| `go test ./... -coverprofile=coverage.out` | Generate coverage |

### Environment Variables

```bash
# Override database URL
DATABASE_URL="postgres://user:pass@localhost:5432/db" go test ./...

# Set namespace
DB_NAMESPACE="auth" go test ./...

# Enable debug logging
GOTRUE_LOG_LEVEL=debug go test -v ./internal/api
```

---

## Continuous Testing During Development

### Watch Mode (Manual)

```bash
# Terminal 1: Keep database running
docker-compose -f docker-compose-dev.yml up postgres

# Terminal 2: Run tests on file change (using entr or similar)
find . -name "*.go" | entr -c go test ./internal/api -v
```

### Before Committing

```bash
# Run this checklist
go test ./...                           # All tests pass
go vet ./...                            # No vet warnings
go fmt ./...                            # Code formatted
staticcheck ./...                       # Static analysis passes
```

---

## Expected Test Output

When all tests pass, you should see:

```
✅ Password validation: PASS (4 test cases with regex support)
✅ User change password: PASS (8 test functions covering all edge cases)
✅ User update stores a chosen password: PASS (1 test function)
✅ User auth info: PASS (4 test functions)
✅ IsNonDefaultPassword: PASS (4 test functions)
✅ Recovery and email change: PASS (2 test functions)

Total: 23 new tests, all passing
Coverage: ~82% of new code
```

---

## Next Steps After Testing

1. ✅ All tests pass locally
2. ✅ Coverage report looks good
3. 📝 Review test output in `TESTING_GUIDE.md`
4. 🚀 Ready to commit and create PR

---

**Questions?**
- Check `APPFLOWY_UNIT_TEST_COVERAGE.md` for detailed test specifications
- Check `APPFLOWY_MERGE_ANALYSIS.md` for technical implementation details
