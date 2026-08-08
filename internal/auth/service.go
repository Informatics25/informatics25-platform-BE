package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Informatics25/informatics25-platform-BE/pkg/database"
	"github.com/google/uuid"
	"github.com/sqlc-dev/pqtype"
)

type Service struct {
	q      *database.Queries
	secret []byte
}

func NewService(q *database.Queries, secret []byte) *Service {
	return &Service{
		q:      q,
		secret: secret,
	}
}

func (s *Service) Login(ctx context.Context, nim, password, ipAddress string) (string, string, error) {
	account, err := s.q.GetAccountByNIM(ctx, nim)
	if err != nil {
		s.logAudit(ctx, nil, "LOGIN_FAILED", fmt.Sprintf("NIM tidak ditemukan: %s", nim), ipAddress)
		return "", "", errors.New("kredensial tidak valid")
	}

	match, err := VerifyPassword(password, account.PasswordHash)
	if err != nil || !match {
		s.logAudit(ctx, &account.ID, "LOGIN_FAILED", "Password salah", ipAddress)
		return "", "", errors.New("kredensial tidak valid")
	}

	accessToken, refreshToken, err := GenerateTokens(
		account.ID.String(),
		account.Nim,
		string(account.Role),
		account.MustChangePassword,
		s.secret,
	)
	if err != nil {
		return "", "", err
	}

	s.logAudit(ctx, &account.ID, "LOGIN_SUCCESS", "User berhasil login", ipAddress)

	return accessToken, refreshToken, nil
}

func (s *Service) ChangeFirstPassword(ctx context.Context, accountIDStr, newPassword, ipAddress string) error {
	accountID, err := uuid.Parse(accountIDStr)
	if err != nil {
		return errors.New("ID akun tidak valid")
	}

	newHash, err := HashPassword(newPassword)
	if err != nil {
		return err
	}

	err = s.q.UpdatePassword(ctx, database.UpdatePasswordParams{
		ID:           accountID,
		PasswordHash: newHash,
	})
	if err != nil {
		s.logAudit(ctx, &accountID, "FIRST_PASSWORD_CHANGE_FAILED", "Gagal memperbarui password di database", ipAddress)
		return err
	}

	s.logAudit(ctx, &accountID, "FIRST_PASSWORD_CHANGE_SUCCESS", "Berhasil mengganti password pertama kali", ipAddress)
	return nil
}

func (s *Service) Logout(ctx context.Context, accountIDStr, ipAddress string) error {
	accountID, err := uuid.Parse(accountIDStr)
	if err != nil {
		return nil
	}
	s.logAudit(ctx, &accountID, "LOGOUT", "User berhasil logout", ipAddress)
	return nil
}

func (s *Service) AdminResetPassword(ctx context.Context, targetAccountIDStr, defaultPassword, ipAddress string) error {
	targetID, err := uuid.Parse(targetAccountIDStr)
	if err != nil {
		return errors.New("ID akun target tidak valid")
	}

	hash, err := HashPassword(defaultPassword)
	if err != nil {
		return err
	}

	err = s.q.UpdatePassword(ctx, database.UpdatePasswordParams{
		ID:           targetID,
		PasswordHash: hash,
	})
	if err != nil {
		return err
	}

	s.logAudit(ctx, &targetID, "ADMIN_RESET_PASSWORD", "Password di-reset oleh Admin", ipAddress)
	return nil
}

func (s *Service) logAudit(ctx context.Context, accountID *uuid.UUID, action, details, ipAddress string) {
	var actorID uuid.NullUUID
	if accountID != nil {
		actorID = uuid.NullUUID{UUID: *accountID, Valid: true}
	}

	detailsJSON, _ := json.Marshal(map[string]string{"info": details})

	_ = s.q.InsertAuditLog(ctx, database.InsertAuditLogParams{
		ActorID:  actorID,
		Action:   action,
		Resource: "AUTH",
		Details: pqtype.NullRawMessage{
			RawMessage: detailsJSON,
			Valid:      true,
		},
		IpAddress: sql.NullString{
			String: ipAddress,
			Valid:  ipAddress != "",
		},
	})
}
