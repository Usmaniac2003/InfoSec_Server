📦 src
│
├── 📁 config/
├── 📁 prisma/
├── 📁 common/
│
├── 📁 modules/
│   ├── user/
│   ├── auth/
│
│   ├── crypto/                 # ⬅ Digital signatures, HKDF, DH validation
│   ├── key-exchange/           # ⬅ Your custom E2EE protocol
│   ├── messages/               # ⬅ Encrypted messaging (ciphertext only)
│   ├── files/                  # ⬅ Client-side encrypted file uploads
│   ├── security/               # ⬅ Replay protection, logs, audits
│
├── app.module.ts
├── main.ts
│
└── prisma/schema.prisma
