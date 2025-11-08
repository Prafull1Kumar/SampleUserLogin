# Auth API

Lightweight in-memory authentication service built with Express. All data resets whenever the server restarts, so use it for demos and local development only.

## Base URL

```
http://localhost:3000
```

## Endpoints

### `POST /signup`

Creates a new user record.

#### Request Body (JSON)

```json
{
  "username": "jdoe",
  "name": "Jane Doe",
  "password": "superSecure123"
}
```

#### Success Response

```json
{
  "message": "user created",
  "user": {
    "id": "uuid-v4",
    "username": "jdoe",
    "name": "Jane Doe"
  }
}
```

### `POST /login`

Validates credentials and returns the sanitized user object.

#### Request Body

```json
{
  "username": "jdoe",
  "password": "superSecure123"
}
```

### `POST /reset-password`

Updates a user's password after verifying the current password.

#### Request Body

```json
{
  "username": "jdoe",
  "currentPassword": "superSecure123",
  "newPassword": "evenBetter456"
}
```

### `GET /users/:username`

Fetches a specific user by username (sanitized fields only).

### `GET /users`

Returns all users sorted by `createdAt` (newest first) with sanitized fields.

## Error Handling

- `400` – missing required fields.
- `401` – invalid credentials or incorrect current password.
- `404` – user not found.
- `409` – username already exists.
- `500` – unexpected server error.

## Notes

- Passwords are hashed with bcrypt before storage.
- Since the datastore is in-memory, restart the server to clear all users.
