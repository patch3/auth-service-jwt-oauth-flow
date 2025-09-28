# JWT Authentication Service

Сервис аутентификации и авторизации на основе JWT токенов с использованием механизма Access Token и Refresh Token по аналогии с OAuth.

## Общее описание

Данный сервис реализует современную схему аутентификации, где вместо сессий используются JSON Web Tokens (JWT). Система работает по принципу **двух токенов**:

- **Access Token** - короткоживущий токен для доступа к защищенным ресурсам
- **Refresh Token** - долгоживущий токен для обновления Access Token


## Технологии

- Java 25
- Spring Boot 3.5.6 (Spring: Security, Data JPA, Web)
- PostgreSQL
- Docker

## Функциональность

- JWT аутентификация (Access + Refresh токены)
- Ролевая авторизация
- Логаут с деактивацией токенов
- Автообновление Access Token

## API Endpoints

| Метод | Endpoint | Назначение |
|-------|----------|------------|
| POST | `/api/jwt/tokens` | Получить токены (Basic Auth) |
| PATCH | `/api/jwt/refresh` | Обновить Access Token |
| PATCH | `/api/jwt/logout` | Выйти из системы |
| GET | `/admin.html` | Требует роли ADMIN |

### Аутентификация

### Получение токенов
```http request
POST /api/jwt/tokens
Authorization: Basic base64(username:password)
```

### Ответ
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "access_token_expiry": "2025-09-01T12:00:00Z",
  "refresh_token": "eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0...",
  "refresh_token_expiry": "2025-09-15T12:00:00Z"
}
```

### Обновление Access Token
```http request
PATCH /api/jwt/refresh
Authorization: Bearer {refresh_token}
```

### Ответ:
Новый Access Token

### Выход из системы
```http request
PATCH /api/jwt/logout
Authorization: Bearer {access_token}
```

### Защищенный ресурс
```http request
PATCH /api/jwt/logout
Authorization: Bearer {access_token}
```
