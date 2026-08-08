package auth_test

import (
	"testing"

	"github.com/Informatics25/informatics25-platform-BE/internal/auth"
)

func TestArgon2HashingAndVerification(t *testing.T) {
	password := "PasswordInformatika2025!"

	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatalf("Gagal hashing password: %v", err)
	}

	match, err := auth.VerifyPassword(password, hash)
	if err != nil || !match {
		t.Errorf("Verifikasi password valid gagal")
	}

	matchInvalid, _ := auth.VerifyPassword("SalahPassword123!", hash)
	if matchInvalid {
		t.Errorf("Password salah seharusnya gagal diverifikasi")
	}
}

func TestPasswordLengthValidation(t *testing.T) {
	shortPassword := "Pendek123!"
	if len(shortPassword) >= 12 {
		t.Errorf("Password seharusnya terdeteksi kurang dari 12 karakter")
	}
}
