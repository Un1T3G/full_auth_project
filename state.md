# Standard Architecture & Security Skill: Full-Auth-Project

Стандарт разработки, архитектуры и безопасности для высокозащищенного модуля аутентификации на базе **Next.js**, **GraphQL**, **Prisma (PostgreSQL)** и **Docker**.

---

## 1. Технологический стек

* **Framework:** Next.js (App Router, TypeScript Strict Mode)
* **API Layer:** GraphQL (Apollo Server / Yoga, Code-first или Schema-first)
* **ORM & Database:** Prisma ORM + PostgreSQL (с управлением сессиями и индексами)
* **Security & Auth:**
  * **Sessions:** Secure Session Management (HTTP-Only, SameSite, Secure Cookie)
  * **TPA (Third-Party Auth):** OAuth 2.0 / OIDC (Google, GitHub и др.)
  * **MFA / 2FA:** TOTP (Google Authenticator / Authy с использованием `otplib` и `qrcode`) + Резервные коды
  * **Email Verification:** Криптографические токены подтверждения с обменом по email
  * **Password Reset:** Токены одноразового сброса пароля с ограниченным TTL и Rate Limiting
* **Crypto & Hashing:** Argon2id / Bcrypt (соль не менее 12 раундов)
* **Containerization:** Docker & Docker Compose (Multi-stage build)

---

## 2. Архитектура безопасности и бизнес-процессы (Auth Flows)

### 2.1 Сессии пользователей (Session Management)
* Токен сессии создается при успешном входе или завершении MFA-чека.
* Сессия записывается в базу данных (таблица `Session`) с привязкой к IP-адресу и User-Agent.
* Идентификатор сессии передается клиенту строго через **HTTP-Only, Secure, SameSite=Lax/Strict** куки.
* Поддерживается принудительный отзыв сессий (Revoke session / Logout from all devices).

### 2.2 TPA (Third-Party Authentication / OAuth2)
* Авторизация через сторонних провайдеров создает или связывает запись в таблице `Account`.
* Если у пользователя включен MFA, после прохождения OAuth он направляется на шаг ввода 2FA-кода.

### 2.3 MFA / 2FA (Multi-Factor Authentication)
* **Setup Phase:** Генерация уникального TOTP-секрета (`otplib`), создание QR-кода, генерация 8-10 одноразовых резервных кодов (Backup Codes, хэшируются перед сохранением в БД).
* **Verification Phase:** Пользователь подтверждает привязку TOTP первично введенным 6-значным кодом, после чего статус MFA становится активным (`isMfaEnabled = true`).
* **Challenge Phase:** При входе пользователя с включенным MFA создается промежуточный токен (`MFA_PENDING`), который запрашивает 6-значный код или резервный код до выдачи основной сессии.

### 2.4 Подтвержденная регистрация (Email Verification)
* При регистрации создается пользователь со статусом `emailVerified = null`.
* На почту отправляется одноразовый токен с таймаутом (например, 24 часа).
* До подтверждения почты доступ к защищенным мутациям и GraphQL-запросам блокируется с ошибкой `UNVERIFIED_EMAIL`.

### 2.5 Сброс пароля (Password Reset)
* Запрос сброса генерирует криптографически стойкий random-токен (`PasswordResetToken`).
* Срок жизни токена — не более 15–30 минут.
* Все существующие активные сессии пользователя аннулируются при успешной смене пароля.

---

## 3. Структура проекта (Feature-Based & Layered Architecture)

```text
full-auth-project/
├── .github/                  # CI/CD пайплайны
├── docker/                   # Dockerfile и скрипты инициализации
│   ├── Dockerfile
│   └── docker-compose.yml
├── prisma/                   # Модели и миграции БД
│   ├── schema.prisma
│   └── seed.ts
├── src/
│   ├── app/                  # Next.js App Router (UI / Routes / GraphQL endpoint)
│   │   ├── api/
│   │   │   └── graphql/      # Endpoint обработчика GraphQL
│   │   └── (auth)/           # Страницы авторизации, MFA, сброса пароля
│   ├── common/               # Глобальные утилиты, мидлвары и константы
│   │   ├── guards/           # GraphQL Auth Guard, MFA Guard
│   │   └── errors/           # Кастомные GraphQLError исключения
│   ├── lib/                  # Настройки клиентов (Prisma, Mailer, Redis, TOTP)
│   │   ├── prisma.ts
│   │   ├── mailer.ts
│   │   └── totp.ts
│   └── modules/              # Модульный GraphQL слой
│       ├── auth/             # Мутации/квери аутентификации, сессий, OAuth
│       │   ├── auth.resolver.ts
│       │   ├── auth.service.ts
│       │   └── auth.typeDefs.ts
│       ├── mfa/              # Генерация и проверка TOTP / Backup-кодов
│       │   ├── mfa.resolver.ts
│       │   └── mfa.service.ts
│       ├── user/             # Управление профилем и пользователями
│       │   ├── user.resolver.ts
│       │   └── user.service.ts
│       └── mail/             # Отправка писем (Verification, Reset Password)
├── public/                   # Статические файлы
├── package.json
└── tsconfig.json
```

---

## 4. Каноническая схема базы данных (Prisma Schema)

```prisma
datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

generator client {
  provider = "prisma-client-js"
}

enum Role {
  USER
  ADMIN
}

model User {
  id                    String                 @id @default(uuid())
  email                 String                 @unique
  passwordHash          String?                // null при входе только через OAuth
  name                  String?
  role                  Role                   @default(USER)
  emailVerified         DateTime?
  isMfaEnabled          Boolean                @default(false)
  mfaSecret             String?                // Зашифрованный TOTP секрет
  mfaBackupCodes        String[]               // Захэшированные резервные коды
  accounts              Account[]
  sessions              Session[]
  verificationTokens    VerificationToken[]
  passwordResetTokens   PasswordResetToken[]
  createdAt             DateTime               @default(now())
  updatedAt             DateTime               @updatedAt
}

model Account {
  id                String   @id @default(uuid())
  userId            String
  provider          String   // e.g. "google", "github"
  providerAccountId String
  accessToken       String?  @db.Text
  refreshToken      String?  @db.Text
  expiresAt         Int?
  user              User     @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@unique([provider, providerAccountId])
}

model Session {
  id           String   @id @default(uuid())
  sessionToken String   @unique
  userId       String
  ipAddress    String?
  userAgent    String?
  expiresAt    DateTime
  user         User     @relation(fields: [userId], references: [id], onDelete: Cascade)
  createdAt    DateTime @default(now())
}

model VerificationToken {
  id        String   @id @default(uuid())
  token     String   @unique
  email     String
  expiresAt DateTime
  userId    String
  user      User     @relation(fields: [userId], references: [id], onDelete: Cascade)
  createdAt DateTime @default(now())
}

model PasswordResetToken {
  id        String   @id @default(uuid())
  token     String   @unique
  userId    String
  expiresAt DateTime
  user      User     @relation(fields: [userId], references: [id], onDelete: Cascade)
  createdAt DateTime @default(now())
}
```

---

## 5. GraphQL Операции (API Contract)

### Ключевые Квери и Мутации

```graphql
type User {
  id: ID!
  email: String!
  name: String
  role: String!
  emailVerified: Boolean!
  isMfaEnabled: Boolean!
  createdAt: String!
}

type AuthPayload {
  user: User
  requiresMfa: Boolean
  mfaTicket: String # Временный токен для прохождения MFA
}

type MfaSetupPayload {
  secret: String!
  qrCodeUrl: String!
  backupCodes: [String!]!
}

type Mutation {
  # Авторизация и регистрация
  register(input: RegisterInput!): Boolean!
  login(input: LoginInput!): AuthPayload!
  loginWithOAuth(provider: String!, code: String!): AuthPayload!
  logout: Boolean!

  # MFA
  setupMfa: MfaSetupPayload!
  enableMfa(totpCode: String!): Boolean!
  verifyMfaLogin(mfaTicket: String!, code: String!): AuthPayload!
  disableMfa(totpCode: String!): Boolean!

  # Email и Пароль
  verifyEmail(token: String!): Boolean!
  requestPasswordReset(email: String!): Boolean!
  resetPassword(token: String!, newPassword: String!): Boolean!
}

type Query {
  me: User
  mySessions: [Session!]!
}
```

---

## 6. Контейнеризация (Docker & Docker Compose)

### Docker Compose Configuration
Приложение поставляется вместе со связанными контейнерами БД PostgreSQL и Redis.

```yaml
version: '3.8'

services:
  app:
    build:
      context: .
      dockerfile: docker/Dockerfile
    ports:
      - "3000:3000"
    environment:
      - DATABASE_URL=postgresql://postgres:postgres_pass@postgres:5432/full_auth_db?schema=public
      - NODE_ENV=production
    depends_on:
      - postgres

  postgres:
    image: postgres:16-alpine
    restart: always
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres_pass
      POSTGRES_DB: full_auth_db
    ports:
      - "5432:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data

volumes:
  pgdata:
```

---

## 7. Правила для AI-Ассистента при генерации кода

При написании или рефакторинге кода в рамках проекта **Full-auth-project** соблюдайте следующие принципы:

1. **Безопасность превыше всего:**
   * Никогда не возвращайте `passwordHash`, `mfaSecret` или нехэшированные `mfaBackupCodes` в GraphQL ответах.
   * Проверяйте статус `emailVerified` и прохождение `MFA` перед предоставлением доступа к защищенным ресурсам.
2. **GraphQL контекст и контекстная безопасность:**
   * Всегда извлекайте текущего пользователя или сессию из `context` GraphQL-резолвера.
   * Выбрасывайте кастомные ошибки GraphQL (`GraphQLError`) с понятными кодами: `UNAUTHENTICATED`, `FORBIDDEN`, `MFA_REQUIRED`, `INVALID_TOKEN`.
3. **Строгая типизация:**
   * Все схемы Prisma, типы GraphQL и функции TypeScript должны быть жестко типизированы без применения `any`.
4. **Валидация входящих данных:**
   * Пароли должны валидироваться на сложность (минимум 8 символов, цифра, спецсимвол, заглавная буква).
   * Email адреса должны проходить проверку формата и нормализацию (lowercase).