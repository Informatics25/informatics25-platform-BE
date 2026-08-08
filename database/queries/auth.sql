-- name: GetAccountByNIM :one
SELECT id, nim, password_hash, role, status, must_change_password, created_at, updated_at
FROM accounts
WHERE nim = $1 LIMIT 1;

-- name: GetAccountByID :one
SELECT id, nim, role, status, must_change_password, created_at, updated_at
FROM accounts
WHERE id = $1 LIMIT 1;

-- name: UpdatePassword :exec
UPDATE accounts
SET password_hash = $2,
    must_change_password = false,
    status = 'ACTIVE',
    updated_at = CURRENT_TIMESTAMP
WHERE id = $1;

-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens (account_id, token_hash, expires_at)
VALUES ($1, $2, $3)
    RETURNING *;

-- name: GetRefreshToken :one
SELECT id, account_id, token_hash, expires_at, revoked_at
FROM refresh_tokens
WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > CURRENT_TIMESTAMP LIMIT 1;

-- name: RevokeRefreshToken :exec
UPDATE refresh_tokens
SET revoked_at = CURRENT_TIMESTAMP
WHERE token_hash = $1;

-- name: RevokeAllAccountRefreshTokens :exec
UPDATE refresh_tokens
SET revoked_at = CURRENT_TIMESTAMP
WHERE account_id = $1 AND revoked_at IS NULL;

-- name: CreatePasswordResetToken :one
INSERT INTO password_reset_tokens (account_id, token_hash, expires_at)
VALUES ($1, $2, $3)
    RETURNING *;

-- name: GetPasswordResetToken :one
SELECT id, account_id, token_hash, expires_at, used_at
FROM password_reset_tokens
WHERE token_hash = $1 AND used_at IS NULL AND expires_at > CURRENT_TIMESTAMP LIMIT 1;

-- name: MarkPasswordResetTokenAsUsed :exec
UPDATE password_reset_tokens
SET used_at = CURRENT_TIMESTAMP
WHERE id = $1;

-- name: InsertAuditLog :exec
INSERT INTO audit_logs (actor_id, action, resource, details, ip_address)
VALUES ($1, $2, $3, $4, $5);