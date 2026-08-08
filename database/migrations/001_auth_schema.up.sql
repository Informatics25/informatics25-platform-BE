CREATE TABLE accounts (
                          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                          nim VARCHAR(20) UNIQUE NOT NULL,
                          password_hash VARCHAR(255) NOT NULL,
                          role VARCHAR(50) NOT NULL DEFAULT 'MAHASISWA',
                          status VARCHAR(50) NOT NULL DEFAULT 'INVITED',
                          must_change_password BOOLEAN NOT NULL DEFAULT TRUE,
                          created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                          updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Tabel penampung Refresh Token untuk fitur Refresh Token & Logout
CREATE TABLE refresh_tokens (
                                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                                account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                                token_hash VARCHAR(255) NOT NULL UNIQUE,
                                expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
                                revoked_at TIMESTAMP WITH TIME ZONE,
                                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Tabel penampung Token Reset Password
CREATE TABLE password_reset_tokens (
                                       id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                                       account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                                       token_hash VARCHAR(255) NOT NULL UNIQUE,
                                       expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
                                       used_at TIMESTAMP WITH TIME ZONE,
                                       created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Tabel Audit Log
CREATE TABLE audit_logs (
                            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                            actor_id UUID REFERENCES accounts(id) ON DELETE SET NULL,
                            action VARCHAR(100) NOT NULL,
                            resource VARCHAR(100) NOT NULL,
                            details JSONB,
                            ip_address VARCHAR(45),
                            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexing untuk performa pencarian query
CREATE INDEX idx_refresh_tokens_account_id ON refresh_tokens(account_id);
CREATE INDEX idx_password_reset_tokens_account_id ON password_reset_tokens(account_id);