-- name: CreateProfile :exec
INSERT INTO profiles (account_id, full_name, nickname, email, is_public)
VALUES ($1, $2, $3, $4, $5);

-- name: GetProfileByAccountID :one
SELECT p.account_id, p.full_name, p.nickname, p.email, p.bio, p.is_public, a.nim, a.role, a.status
FROM profiles p
         JOIN accounts a ON p.account_id = a.id
WHERE p.account_id = $1 LIMIT 1;

-- name: UpdateProfile :exec
UPDATE profiles
SET full_name = COALESCE(sqlc.narg('full_name'), full_name),
    nickname = COALESCE(sqlc.narg('nickname'), nickname),
    bio = COALESCE(sqlc.narg('bio'), bio),
    is_public = COALESCE(sqlc.narg('is_public'), is_public),
    updated_at = NOW()
WHERE account_id = $1;

-- name: CreateAccount :one
INSERT INTO accounts (id, nim, password_hash, role, status, must_change_password)
VALUES ($1, $2, $3, $4, $5, $6)
    RETURNING id, nim, role, status;

-- name: SuspendAccount :exec
UPDATE accounts
SET status = 'SUSPENDED', updated_at = NOW()
WHERE id = $1;

-- name: CreateTOTPSecret :exec
INSERT INTO admin_totp_secrets (account_id, totp_secret, backup_codes)
VALUES ($1, $2, $3);

-- name: GetTOTPSecret :one
SELECT totp_secret, is_verified, backup_codes
FROM admin_totp_secrets
WHERE account_id = $1 LIMIT 1;

-- name: VerifyTOTP :exec
UPDATE admin_totp_secrets
SET is_verified = TRUE
WHERE account_id = $1;