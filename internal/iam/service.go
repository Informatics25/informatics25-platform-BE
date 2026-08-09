package iam

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Informatics25/informatics25-platform-BE/internal/auth"
	"github.com/Informatics25/informatics25-platform-BE/pkg/database"
	"github.com/google/uuid"
	"github.com/sqlc-dev/pqtype"
)

type Service struct {
	q *database.Queries
}

func NewService(q *database.Queries) *Service {
	return &Service{
		q: q,
	}
}

func (s *Service) GetProfileByID(ctx context.Context, accountIDStr string) (*database.GetProfileByAccountIDRow, error) {
	accountID, err := uuid.Parse(accountIDStr)
	if err != nil {
		return nil, errors.New("ID akun tidak valid")
	}

	profile, err := s.q.GetProfileByAccountID(ctx, accountID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("profil tidak ditemukan")
		}
		return nil, err
	}

	return &profile, nil
}

type UpdateProfileRequest struct {
	FullName string `json:"full_name"`
	Nickname string `json:"nickname"`
	Bio      string `json:"bio"`
	IsPublic *bool  `json:"is_public"`
}

func (s *Service) UpdateProfile(ctx context.Context, accountIDStr string, req UpdateProfileRequest) error {
	accountID, err := uuid.Parse(accountIDStr)
	if err != nil {
		return errors.New("ID akun tidak valid")
	}

	var fullName, nickname, bio sql.NullString
	if req.FullName != "" {
		fullName = sql.NullString{String: req.FullName, Valid: true}
	}
	if req.Nickname != "" {
		nickname = sql.NullString{String: req.Nickname, Valid: true}
	}
	if req.Bio != "" {
		bio = sql.NullString{String: req.Bio, Valid: true}
	}

	var isPublic sql.NullBool
	if req.IsPublic != nil {
		isPublic = sql.NullBool{Bool: *req.IsPublic, Valid: true}
	}

	return s.q.UpdateProfile(ctx, database.UpdateProfileParams{
		AccountID: accountID,
		FullName:  fullName,
		Nickname:  nickname,
		Bio:       bio,
		IsPublic:  isPublic,
	})
}

func (s *Service) CreateMahasiswaAccount(ctx context.Context, nim, fullName string) (*database.CreateAccountRow, string, error) {
	tempPassword := generateRandomPassword(8)

	hashedPassword, err := auth.HashPassword(tempPassword)
	if err != nil {
		return nil, "", fmt.Errorf("gagal merancang password: %w", err)
	}

	newID := uuid.New()

	account, err := s.q.CreateAccount(ctx, database.CreateAccountParams{
		ID:                 newID,
		Nim:                nim,
		PasswordHash:       hashedPassword,
		Role:               RoleMahasiswa,
		Status:             "INVITED",
		MustChangePassword: true,
	})
	if err != nil {
		return nil, "", fmt.Errorf("gagal membuat akun di database: %w", err)
	}

	err = s.q.CreateProfile(ctx, database.CreateProfileParams{
		AccountID: newID,
		FullName:  fullName,
		Nickname:  sql.NullString{Valid: false},
		Email:     sql.NullString{Valid: false},
		IsPublic:  false,
	})
	if err != nil {
		return nil, "", fmt.Errorf("gagal membuat profil: %w", err)
	}

	return &account, tempPassword, nil
}

func (s *Service) SuspendMahasiswa(ctx context.Context, targetAccountIDStr string) error {
	targetID, err := uuid.Parse(targetAccountIDStr)
	if err != nil {
		return errors.New("ID akun target tidak valid")
	}

	return s.q.SuspendAccount(ctx, targetID)
}

func (s *Service) CreateAdministrator(ctx context.Context, nim, fullName string) (*database.CreateAccountRow, string, error) {
	tempPassword := generateRandomPassword(10)

	hashedPassword, err := auth.HashPassword(tempPassword)
	if err != nil {
		return nil, "", err
	}

	newID := uuid.New()

	account, err := s.q.CreateAccount(ctx, database.CreateAccountParams{
		ID:                 newID,
		Nim:                nim,
		PasswordHash:       hashedPassword,
		Role:               RoleAdministrator,
		Status:             "INVITED",
		MustChangePassword: true,
	})
	if err != nil {
		return nil, "", err
	}

	err = s.q.CreateProfile(ctx, database.CreateProfileParams{
		AccountID: newID,
		FullName:  fullName,
		IsPublic:  false,
	})
	if err != nil {
		return nil, "", err
	}

	return &account, tempPassword, nil
}

func (s *Service) ForceResetPassword(ctx context.Context, targetAccountIDStr string) (string, error) {
	targetID, err := uuid.Parse(targetAccountIDStr)
	if err != nil {
		return "", errors.New("ID akun target tidak valid")
	}

	newTempPassword := generateRandomPassword(8)
	hashedPassword, err := auth.HashPassword(newTempPassword)
	if err != nil {
		return "", err
	}

	err = s.q.UpdatePassword(ctx, database.UpdatePasswordParams{
		ID:           targetID,
		PasswordHash: hashedPassword,
	})
	if err != nil {
		return "", err
	}

	return newTempPassword, nil
}

func generateRandomPassword(length int) string {
	b := make([]byte, length)
	_, _ = rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)[:length]
}

func (s *Service) LogAudit(ctx context.Context, actorIDStr, action, details, ipAddress string) {
	var actorID uuid.NullUUID
	if id, err := uuid.Parse(actorIDStr); err == nil {
		actorID = uuid.NullUUID{UUID: id, Valid: true}
	}

	detailsJSON, _ := json.Marshal(map[string]string{"info": details})

	_ = s.q.InsertAuditLog(ctx, database.InsertAuditLogParams{
		ActorID:  actorID,
		Action:   action,
		Resource: "IAM",
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
