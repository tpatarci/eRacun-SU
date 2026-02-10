# User Profile Page Specification

## Overview

The User Profile page allows authenticated users to view and manage their account information. Users can view their profile details, update their name and email, and change their password.

**API Endpoint:** `GET /api/v1/users/me` (fetch), `PUT /api/v1/users/me` (update)

**Accessibility:** Requires authentication (`authMiddleware`)

---

## Wireframe Description

### Desktop Layout (≥ 768px)

```
┌────────────────────────────────────────────────────────────────────────────┐
│  eRačun                                                  [Profile] [Logout] │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│  User Profile                                                              │
│  ──────────────────────────────────────────────────────────────────────   │
│                                                                            │
│  ┌──────────────────────────────────────────────────────────────────────┐ │
│  │  User Information                                                      │ │
│  │  ──────────────────────────────────────────────────────────────────  │ │
│  │                                                                        │ │
│  │  Email:    user@example.com                                          │ │
│  │  Name:     [John Doe                                          ]      │ │
│  │  Member Since: 2024-02-10                                             │ │
│  │  Last Updated: 2024-02-10                                            │ │
│  │                                                                        │ │
│  │  [ Save Changes ]                                                      │ │
│  └──────────────────────────────────────────────────────────────────────┘ │
│                                                                            │
│  ┌──────────────────────────────────────────────────────────────────────┐ │
│  │  Change Password                                                       │ │
│  │  ──────────────────────────────────────────────────────────────────  │ │
│  │                                                                        │ │
│  │  Current Password:   [••••••••••••••                      ]            │ │
│  │  New Password:       [                              ]                 │ │
│  │  Confirm Password:   [                              ]                 │ │
│  │                                                                        │ │
│  │  Password must be at least 8 characters long                          │ │
│  │                                                                        │ │
│  │  [ Update Password ]                                                   │ │
│  └──────────────────────────────────────────────────────────────────────┘ │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
```

### Mobile Layout (< 768px)

```
┌──────────────────────────────────────┐
│ ☰  eRačun                     [≡]    │
├──────────────────────────────────────┤
│                                      │
│ User Profile                        │
│ ──────────────────────────────      │
│                                      │
│ ┌────────────────────────────────┐  │
│ │ User Information               │  │
│ │ ─────────────────────────────  │  │
│ │                                │  │
│ │ Email:                         │  │
│ │ user@example.com               │  │
│ │                                │  │
│ │ Name:                          │  │
│ │ [John Doe              ]       │  │
│ │                                │  │
│ │ Member Since: 2024-02-10       │  │
│ │                                │  │
│ │ [ Save Changes ]               │  │
│ └────────────────────────────────┘  │
│                                      │
│ ┌────────────────────────────────┐  │
│ │ Change Password                │  │
│ │ ─────────────────────────────  │  │
│ │                                │  │
│ │ Current Password:              │  │
│ │ [••••••••••••         ]       │  │
│ │                                │  │
│ │ New Password:                  │  │
│ │ [                      ]       │  │
│ │                                │  │
│ │ Confirm Password:              │  │
│ │ [                      ]       │  │
│ │                                │  │
│ │ [ Update Password ]            │  │
│ └────────────────────────────────┘  │
│                                      │
└──────────────────────────────────────┘
```

---

## Form Fields

### User Information Section

| Field | Type | Editable | Validation | Notes |
|-------|------|----------|------------|-------|
| `email` | Text (email) | No | `emailSchema` | Display only. Email changes require separate verification flow (future enhancement) |
| `name` | Text | Yes | Min 1 character | Optional field. Defaults to empty string if not provided |
| `createdAt` | Date | No | - | Display as "Member Since: YYYY-MM-DD" |
| `updatedAt` | Date | No | - | Display as "Last Updated: YYYY-MM-DD" |

### Change Password Section

| Field | Type | Validation | Notes |
|-------|------|------------|-------|
| `currentPassword` | Password | Required, min 8 chars | Must match user's current password |
| `newPassword` | Password | Min 8 characters | Must be different from current password |
| `confirmPassword` | Password | Must match `newPassword` | Validation error if mismatch |

---

## Validation Requirements

### Client-Side Validation

1. **Email Display**
   - Show as read-only text
   - Mask as `u***@example.com` if privacy mode is enabled (future feature)

2. **Name Field**
   - Minimum length: 1 character
   - Maximum length: 255 characters (database constraint)
   - Trim whitespace before submission
   - Error message: "Name is required" if empty after trimming

3. **Password Fields**
   - **Current Password**: Required, min 8 characters
   - **New Password**: Required, min 8 characters
     - Cannot match current password
     - Error message: "Password must be at least 8 characters long"
   - **Confirm Password**: Required
     - Must exactly match New Password
     - Error message: "Passwords do not match"

### Server-Side Validation

The backend applies the following validations (defined in `src/api/schemas.ts`):

```typescript
// Email validation
emailSchema = z.string().min(1, 'Email is required').email('Invalid email format')

// Password validation
passwordSchema = z.string().min(8, 'Password must be at least 8 characters long')
```

**API Response Schema:**
```json
{
  "id": "uuid",
  "email": "user@example.com",
  "name": "John Doe",
  "createdAt": "2024-02-10T15:30:00.000Z",
  "updatedAt": "2024-02-10T15:30:00.000Z"
}
```

---

## Error Messages

### Field Validation Errors

| Scenario | Error Message |
|----------|---------------|
| Name is empty | "Name is required" |
| Name too long | "Name must not exceed 255 characters" |
| Current password missing | "Current password is required" |
| Current password incorrect | "Current password is incorrect" |
| New password too short | "Password must be at least 8 characters long" |
| Passwords don't match | "Passwords do not match" |
| New password same as current | "New password must be different from current password" |

### API Error Responses

| HTTP Status | Error | Message |
|-------------|-------|---------|
| 401 | Unauthorized | Authentication required |
| 400 | Bad Request | Validation errors (details in response body) |
| 500 | Internal Server Error | Failed to update user profile |

**Example Validation Error Response:**
```json
{
  "error": "Validation failed",
  "message": "Name is required",
  "requestId": "uuid"
}
```

---

## Success Messages

| Action | Success Message |
|--------|----------------|
| Profile updated | "Your profile has been updated successfully" |
| Password changed | "Your password has been changed successfully" |

---

## Responsive Design Notes

### Breakpoints

- **Mobile**: < 768px (stack vertically, full-width inputs)
- **Tablet**: 768px - 1024px (centered layout, max-width 600px)
- **Desktop**: > 1024px (centered layout, max-width 800px)

### Mobile Adaptations

1. **Navigation**
   - Use hamburger menu for profile/logout actions
   - Sticky header with back button navigation

2. **Form Layout**
   - Stack all fields vertically
   - Full-width input fields
   - Larger touch targets (min 44px height)
   - Virtual keyboard handling:
     - Dismissible keyboard on scroll
     - Maintain scroll position on focus

3. **Typography**
   - Base font size: 16px (prevents zoom on focus)
   - Headers: 20px - 24px
   - Line height: 1.5 for readability

### Desktop Enhancements

1. **Form Layout**
   - Two-column layout for longer forms (future)
   - Fixed max-width containers
   - Hover states on buttons and links

2. **Keyboard Navigation**
   - Tab order: Name → Current Password → New Password → Confirm Password → Save Button
   - Enter key submits form
   - Escape key closes modals (if any)

---

## Accessibility

### Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `Tab` | Move to next field |
| `Shift + Tab` | Move to previous field |
| `Enter` | Submit form |
| `Escape` | Cancel/close (future enhancement) |

### ARIA Labels

```html
<!-- Name field -->
<label for="name">Name</label>
<input
  id="name"
  name="name"
  type="text"
  aria-required="false"
  aria-describedby="name-hint"
/>
<span id="name-hint" class="hint">Optional field</span>

<!-- Password fields -->
<label for="current-password">Current Password</label>
<input
  id="current-password"
  name="currentPassword"
  type="password"
  aria-required="true"
  autocomplete="current-password"
/>
```

### Screen Reader Announcements

- Form validation errors announced via `aria-live="polite"`
- Success messages announced after form submission
- Loading states announced as "Updating profile..."

---

## State Management

### Loading States

| Action | Loading Indicator |
|--------|-------------------|
| Fetching profile | Full-page skeleton or spinner |
| Updating profile | Button shows spinner, disabled |
| Changing password | Button shows spinner, disabled |

### Idle States

| Scenario | Display |
|----------|---------|
| Profile loaded | Display form fields with current data |
| Profile not found | Show "Profile not found" error |
| Network error | Show "Unable to load profile. Retry?" button |

---

## Security Considerations

1. **Password Handling**
   - Never display passwords in plain text
   - Use `type="password"` for password fields
   - Include "Show Password" toggle (optional, user preference)

2. **Session Management**
   - Verify authentication status on page load
   - Redirect to login if session expired
   - Clear sensitive fields on logout

3. **Data Exposure**
   - Never expose `passwordHash` in UI (backend already excludes it)
   - Mask email in display if privacy mode enabled (future)

---

## API Integration

### Fetch Profile

```typescript
GET /api/v1/users/me
Authorization: Bearer <session-token>

Response 200:
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "name": "John Doe",
  "createdAt": "2024-02-10T15:30:00.000Z",
  "updatedAt": "2024-02-10T15:30:00.000Z"
}
```

### Update Profile

```typescript
PUT /api/v1/users/me
Authorization: Bearer <session-token>
Content-Type: application/json

{
  "name": "Jane Doe"
}

Response 200:
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "name": "Jane Doe",
  "createdAt": "2024-02-10T15:30:00.000Z",
  "updatedAt": "2024-02-10T16:45:00.000Z"
}
```

### Change Password

**Note:** Password change endpoint to be implemented in future enhancement. Current design assumes same endpoint with password field validation.

---

## Future Enhancements

1. **Email Verification Flow**
   - Allow email changes with verification
   - Send confirmation email with token
   - Update email only after verification

2. **Avatar Upload**
   - Profile picture upload
   - Image validation (size, format)
   - Storage integration (S3, local)

3. **Two-Factor Authentication**
   - Enable/disable 2FA
   - TOTP setup
   - Backup codes generation

4. **Account Deletion**
   - Request account deletion
   - Grace period with cancellation
   - Data retention policy

5. **Activity Log**
   - Login history
   - Profile changes
   - Configuration updates

---

## Related Documentation

- [FINA Configuration Page](./fina-config-page.md)
- [IMAP Configuration Page](./imap-config-page.md)
- [Configuration Dashboard](./config-dashboard.md)
- [Authentication API](../api/README.md)
