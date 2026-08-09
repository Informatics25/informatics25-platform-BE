-- backend/database/migrations/002_user_management.up.sql
CREATE TABLE profiles (
                          account_id UUID PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
                          full_name VARCHAR(255) NOT NULL,
                          nickname VARCHAR(100),
                          email VARCHAR(255) UNIQUE,
                          bio TEXT,
                          is_public BOOLEAN NOT NULL DEFAULT FALSE,
                          created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                          updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE admin_totp_secrets (
                                    account_id UUID PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
                                    totp_secret VARCHAR(255) NOT NULL,
                                    is_verified BOOLEAN NOT NULL DEFAULT FALSE,
                                    backup_codes JSONB NOT NULL,
                                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);