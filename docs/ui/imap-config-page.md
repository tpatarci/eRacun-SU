# IMAP Configuration Page Specification

## Overview

The IMAP Configuration page allows authenticated users to configure their email server credentials for automatic invoice ingestion. The system connects to the user's IMAP email server to poll for incoming invoices sent as attachments, enabling automated invoice processing from email sources.

**API Endpoint:** `GET /api/v1/users/me/config` (fetch), `PUT /api/v1/users/me/config/imap` (update), `DELETE /api/v1/users/me/config/imap` (remove)

**Accessibility:** Requires authentication (`authMiddleware`)

---

## Wireframe Description

### Desktop Layout (≥ 768px)

```
┌────────────────────────────────────────────────────────────────────────────┐
│  eRačun                                                  [Profile] [Logout] │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│  IMAP Configuration                                                        │
│  ──────────────────────────────────────────────────────────────────────   │
│                                                                            │
│  Configure your email server credentials for automatic invoice ingestion  │
│  from email attachments. The system will poll this mailbox for invoices.  │
│                                                                            │
│  ┌──────────────────────────────────────────────────────────────────────┐ │
│  │  Server Connection Settings                                           │ │
│  │  ──────────────────────────────────────────────────────────────────  │ │
│  │                                                                        │ │
│  │  IMAP Host:                                                            │ │
│  │  [imap.example.com                                             ]      │ │
│  │                                                                        │ │
│  │  Port:                                                                 │ │
│  │  [993                                                  ]               │ │
│  │                                                                        │ │
│  │  Common ports: 993 (IMAPS with SSL), 143 (IMAP with STARTTLS)        │ │
│  └──────────────────────────────────────────────────────────────────────┘ │
│                                                                            │
│  ┌──────────────────────────────────────────────────────────────────────┐ │
│  │  Authentication                                                        │ │
│  │  ──────────────────────────────────────────────────────────────────  │ │
│  │                                                                        │ │
│  │  Username:                                                             │ │
│  │  [user@example.com                                             ]      │ │
│  │                                                                        │ │
│  │  Password:                                                             │ │
│  │  [********************************                            ]  [👁️ Show] │ │
│  │                                                                        │ │
│  │  ⚠️ Use an app-specific password if 2FA is enabled on your account.   │ │
│  └──────────────────────────────────────────────────────────────────────┘ │
│                                                                            │
│  ┌──────────────────────────────────────────────────────────────────────┐ │
│  │  Connection Test                                                       │ │
│  │  ──────────────────────────────────────────────────────────────────  │ │
│  │                                                                        │ │
│  │  [ 🧪 Test Connection ]                                                │ │
│  │                                                                        │ │
│  │  Status: [✓ Connection successful]  [✗ Connection failed]             │ │
│  │                                                                        │ │
│  │  Last tested: 2024-02-10 16:45:00                                      │ │
│  │                                                                        │ │
│  │  Mailbox: [Invoices                                           ]       │ │
│  │  The mailbox to poll for invoice attachments (default: INBOX)         │ │
│  └──────────────────────────────────────────────────────────────────────┘ │
│                                                                            │
│  ┌──────────────────────────────────────────────────────────────────────┐ │
│  │  Polling Settings (Optional)                                          │ │
│  │  ──────────────────────────────────────────────────────────────────  │ │
│  │                                                                        │ │
│  │  Poll Interval:                                                        │ │
│  │  [1                                            ] minutes              │ │
│  │                                                                        │ │
│  │  ⚠️ Shorter intervals increase server load. Recommended: 1-5 minutes.  │ │
│  └──────────────────────────────────────────────────────────────────────┘ │
│                                                                            │
│  ┌──────────────────────────────────────────────────────────────────────┐ │
│  │  Actions                                                               │ │
│  │  ──────────────────────────────────────────────────────────────────  │ │
│  │                                                                        │ │
│  │  [ 💾 Save Configuration ]                                             │ │
│  │  [ 🗑️ Remove Configuration ]                                           │ │
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
│ IMAP Configuration                   │
│ ──────────────────────────────       │
│                                      │
│ Configure your email                 │
│ server for invoice ingestion...      │
│                                      │
│ ┌────────────────────────────────┐  │
│ │ Server Settings                │  │
│ │ ─────────────────────────────  │  │
│ │                                │  │
│ │ IMAP Host:                     │  │
│ │ [imap.example.com        ]     │  │
│ │                                │  │
│ │ Port:                          │  │
│ │ [993                    ]      │  │
│ └────────────────────────────────┘  │
│                                      │
│ ┌────────────────────────────────┐  │
│ │ Authentication                 │  │
│ │ ─────────────────────────────  │  │
│ │                                │  │
│ │ Username:                      │  │
│ │ [user@example.com       ]      │  │
│ │                                │  │
│ │ Password:                      │  │
│ │ [************          ]  [👁️]│  │
│ └────────────────────────────────┘  │
│                                      │
│ ┌────────────────────────────────┐  │
│ │ Connection Test                │  │
│ │ ─────────────────────────────  │  │
│ │                                │  │
│ │ [ 🧪 Test Connection ]         │  │
│ │                                │  │
│ │ Status: ✓ Success              │  │
│ └────────────────────────────────┘  │
│                                      │
│ [ 💾 Save ]  [ 🗑️ Remove ]          │
│                                      │
└──────────────────────────────────────┘
```

---

## Form Fields

### Server Connection Settings Section

| Field | Type | Required | Validation | Default | Notes |
|-------|------|----------|------------|---------|-------|
| `host` | Text | Yes | Non-empty string, valid hostname | - | IMAP server hostname or IP address |
| `port` | Number | Yes | Integer, 1-65535 | 993 | IMAP port. Common: 993 (IMAPS), 143 (IMAP+STARTTLS) |

### Authentication Section

| Field | Type | Required | Validation | Notes |
|-------|------|----------|------------|-------|
| `user` | Text | Yes | Non-empty string | IMAP username (often email address) |
| `password` | Password | Yes | Non-empty string | IMAP password or app-specific password |

### Connection Test Section

| Field | Type | Notes |
|-------|------|-------|
| `testButton` | Button | Triggers IMAP connection test endpoint (to be implemented) |
| `connectionStatus` | Read-only | Displays last test result: success, failed, or not tested |
| `lastTested` | Read-only | Timestamp of last connection test |
| `mailbox` | Text (optional) | Target mailbox for polling (default: INBOX) |

### Polling Settings Section (Optional)

| Field | Type | Validation | Default | Notes |
|-------|------|------------|---------|-------|
| `pollInterval` | Number | Integer, 1-60 minutes | 1 | How often to poll for new emails |

---

## Validation Requirements

### Client-Side Validation

1. **Host Field**
   - Required field
   - Minimum length: 1 character
   - Maximum length: 255 characters
   - Valid hostname format:
     - Domain name: `imap.example.com`
     - IP address: `192.168.1.1`
     - With port: `imap.example.com:993` (parse separately)
   - Trim whitespace before submission
   - Error messages:
     - "IMAP host is required"
     - "Invalid hostname format"

2. **Port Field**
   - Required field
   - Must be integer
   - Range: 1-65535 (valid TCP port)
   - Common IMAP ports:
     - 993 (IMAPS with SSL/TLS) - **Recommended**
     - 143 (IMAP with STARTTLS)
   - Error messages:
     - "Port is required"
     - "Port must be between 1 and 65535"

3. **Username Field**
   - Required field
   - Minimum length: 1 character
   - Maximum length: 255 characters
   - Trim whitespace before submission
   - Error messages:
     - "Username is required"

4. **Password Field**
   - Required field
   - Minimum length: 1 character
   - Show/hide toggle for visibility
   - Error messages:
     - "Password is required"

5. **Mailbox Field** (Optional)
   - If provided, must be valid IMAP mailbox name
   - Default: INBOX
   - Error messages:
     - "Invalid mailbox name"

6. **Poll Interval Field** (Optional)
   - If provided, must be integer
   - Range: 1-60 minutes
   - Show warning if < 1 minute: "Frequent polling may cause server load"
   - Error messages:
     - "Poll interval must be between 1 and 60 minutes"

### Server-Side Validation

The backend applies the following validations (defined in `src/api/schemas.ts`):

```typescript
// IMAP configuration schema
imapConfigSchema = z.object({
  host: z.string().min(1, 'IMAP host is required'),
  port: z.number().int().min(1).max(65535),
  user: z.string().min(1, 'Username is required'),
  password: z.string().min(1, 'Password is required'),
})
```

**API Response Schema:**
```json
{
  "serviceName": "imap",
  "config": {
    "host": "imap.example.com",
    "port": 993,
    "user": "user@example.com",
    "password": "encrypted-password"
  },
  "updatedAt": "2024-02-10T16:45:00.000Z"
}
```

---

## Error Messages

### Field Validation Errors

| Scenario | Error Message |
|----------|---------------|
| Host empty | "IMAP host is required" |
| Host invalid format | "Invalid hostname format" |
| Port empty | "Port is required" |
| Port out of range | "Port must be between 1 and 65535" |
| Username empty | "Username is required" |
| Password empty | "Password is required" |
| Poll interval too short | "Poll interval must be at least 1 minute" |
| Poll interval too long | "Poll interval must not exceed 60 minutes" |

### API Error Responses

| HTTP Status | Error | Message |
|-------------|-------|---------|
| 401 | Unauthorized | Authentication required |
| 400 | Bad Request | Validation errors (details in response body) |
| 500 | Internal Server Error | Failed to update configuration |
| 503 | Service Unavailable | Connection test failed |

**Example Validation Error Response:**
```json
{
  "error": "Validation failed",
  "errors": [
    {
      "field": "host",
      "message": "IMAP host is required"
    },
    {
      "field": "port",
      "message": "Port must be between 1 and 65535"
    }
  ],
  "requestId": "uuid"
}
```

### Test Connection Error Messages

| Scenario | Error Message |
|----------|---------------|
| Host unreachable | "Cannot connect to IMAP server. Check hostname and network connection" |
| Authentication failed | "Authentication failed. Check username and password" |
| Invalid credentials | "Invalid username or password" |
| Connection timeout | "Connection timed out. Server may be unreachable or firewall blocking connection" |
| SSL/TLS error | "SSL/TLS handshake failed. Server may not support secure connection" |
| Mailbox not found | "Specified mailbox not found. Check mailbox name or use default (INBOX)" |
| Permission denied | "Permission denied. User does not have access to specified mailbox" |

---

## Success Messages

| Action | Success Message |
|--------|----------------|
| Configuration saved | "IMAP configuration saved successfully" |
| Configuration removed | "IMAP configuration removed" |
| Connection test successful | "Connection test successful. Email server is accessible" |
| Email polling started | "Email polling started successfully" |
| Email polling stopped | "Email polling stopped" |

---

## Common Email Providers

### Preconfigured Provider Templates

| Provider | Host | Port | Notes |
|----------|------|------|-------|
| Gmail | `imap.gmail.com` | 993 | Requires App Password if 2FA enabled |
| Outlook/Office 365 | `outlook.office365.com` | 993 | May require App Password |
| Yahoo Mail | `imap.mail.yahoo.com` | 993 | Requires App Password |
| iCloud | `imap.mail.me.com` | 993 | Requires App Password |
| Fastmail | `imap.fastmail.com` | 993 | Standard authentication |

**UI Behavior:**
- Add "Quick Setup" dropdown with common providers
- Selecting a provider auto-fills host and port
- User can still manually modify values after selection
- Show provider-specific help text:
  - Gmail: "Use an App Password if 2FA is enabled. Generate at: https://myaccount.google.com/apppasswords"
  - Outlook: "Use App Password if modern authentication is enabled"

---

## Test Connection Feature

### Behavior

1. **Trigger:** User clicks "Test Connection" button
2. **Validation:** Client-side validation runs first
3. **API Call:** POST to `/api/v1/users/me/config/imap/test` (endpoint to be implemented)
4. **Loading State:** Button shows spinner, disabled during test
5. **Result Display:**
   - Success: Green checkmark, "Connection successful" message, mailbox info
   - Failure: Red X, specific error message from server
6. **Timestamp:** Update "Last tested" field

**Test Connection Request:**
```typescript
POST /api/v1/users/me/config/imap/test
Authorization: Bearer <session-token>
Content-Type: application/json

{
  "host": "imap.gmail.com",
  "port": 993,
  "user": "user@gmail.com",
  "password": "app-password",
  "mailbox": "INBOX"
}
```

**Test Connection Response (Success):**
```json
{
  "success": true,
  "message": "Connection successful",
  "details": {
    "server": "imap.gmail.com",
    "port": 993,
    "authentication": "OK",
    "mailbox": "INBOX",
    "totalMessages": 42,
    "unreadMessages": 5
  }
}
```

**Test Connection Response (Failure):**
```json
{
  "success": false,
  "message": "Authentication failed",
  "errorCode": "IMAP_AUTH_FAILED",
  "suggestion": "Check username and password. If using 2FA, use an app-specific password."
}
```

---

## Responsive Design Notes

### Breakpoints

- **Mobile**: < 768px (stack vertically, full-width inputs)
- **Tablet**: 768px - 1024px (centered layout, max-width 700px)
- **Desktop**: > 1024px (centered layout, max-width 900px)

### Mobile Adaptations

1. **Navigation**
   - Use hamburger menu for profile/logout actions
   - Back button to return to configuration dashboard

2. **Form Layout**
   - Stack all sections vertically
   - Full-width input fields
   - Port and poll interval fields with number stepper
   - Test connection button full-width for easier tapping

3. **Quick Setup Dropdown**
   - Native select element on mobile
   - Full-width for easier selection

---

## Accessibility

### Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `Tab` | Move to next field |
| `Shift + Tab` | Move to previous field |
| `Enter` | Submit form (if in input field) |
| `Escape` | Cancel form editing (future enhancement) |

### ARIA Labels

```html
<!-- Host field -->
<label for="imap-host">IMAP Host</label>
<input
  id="imap-host"
  name="host"
  type="text"
  aria-required="true"
  aria-describedby="host-hint"
  placeholder="imap.example.com"
/>
<span id="host-hint" class="hint">
  The IMAP server hostname or IP address
</span>

<!-- Port field -->
<label for="imap-port">Port</label>
<input
  id="imap-port"
  name="port"
  type="number"
  min="1"
  max="65535"
  aria-required="true"
  aria-describedby="port-hint"
  value="993"
/>
<span id="port-hint" class="hint">
  Common ports: 993 (IMAPS), 143 (IMAP+STARTTLS)
</span>

<!-- Username field -->
<label for="imap-user">Username</label>
<input
  id="imap-user"
  name="user"
  type="text"
  aria-required="true"
  aria-describedby="user-hint"
  placeholder="user@example.com"
  autocomplete="username"
/>
<span id="user-hint" class="hint">
  Your IMAP username (often your email address)
</span>

<!-- Password field with visibility toggle -->
<label for="imap-password">Password</label>
<div class="password-input">
  <input
    id="imap-password"
    name="password"
    type="password"
    aria-required="true"
    autocomplete="current-password"
  />
  <button
    type="button"
    aria-label="Show password"
    aria-pressed="false"
    id="toggle-password"
  >
    <span aria-hidden="true">👁️</span>
  </button>
</div>

<!-- Test connection button -->
<button
  type="button"
  id="test-connection"
  aria-describedby="test-status"
>
  🧪 Test Connection
</button>
<span id="test-status" aria-live="polite">
  Connection test not yet run
</span>
```

### Screen Reader Announcements

- Form validation errors announced via `aria-live="polite"`
- Test connection progress announced as "Testing connection to IMAP server..."
- Test connection results announced with success/failure status and details
- Provider selection announced as "Selected Gmail template, host set to imap.gmail.com, port set to 993"

---

## State Management

### Loading States

| Action | Loading Indicator |
|--------|-------------------|
| Fetching configuration | Full-page skeleton or spinner |
| Saving configuration | "Save" button shows spinner, all fields disabled |
| Testing connection | "Test Connection" button shows spinner, button disabled |
| Removing configuration | Confirmation modal with spinner after confirmation |
| Starting poller | "Start Polling" button shows spinner |

### Idle States

| Scenario | Display |
|----------|---------|
| Configuration loaded | Display form fields with current data |
| Configuration not found | Show empty form with "No IMAP configuration" message |
| Poller active | Show "Polling active" badge with interval |
| Poller inactive | Show "Polling inactive" badge |
| Poller error | Show error banner with last error message |

---

## Security Considerations

1. **Password Handling**
   - Always use `type="password"` for password field
   - Show/hide toggle is optional (user preference)
   - Never log password in plain text on client or server
   - Password is stored in database as plaintext JSONB (future enhancement: encrypt at rest)

2. **App Password Guidance**
   - Show help text for users with 2FA enabled
   - Provide links to app password generation for common providers:
     - Gmail: https://myaccount.google.com/apppasswords
     - Outlook: https://account.live.com/credappsv2
     - Yahoo: https://login.yahoo.com/account/security/app-passwords

3. **Connection Security**
   - Recommend port 993 (IMAPS with SSL/TLS) by default
   - Warn about unencrypted connections (port 143 without STARTTLS)
   - Add warning: "⚠️ Using unencrypted connection may expose your credentials"

4. **Host Validation**
   - Validate hostname format
   - Prevent SSRF (Server-Side Request Forgery) by restricting endpoints
   - Consider implementing whitelist of allowed email providers

5. **Session Management**
   - Require authentication before page access
   - Redirect to login if session expired
   - Clear sensitive fields on logout

---

## API Integration

### Fetch IMAP Configuration

```typescript
GET /api/v1/users/me/config
Authorization: Bearer <session-token>

Response 200:
{
  "configs": {
    "imap": {
      "host": "imap.gmail.com",
      "port": 993,
      "user": "user@gmail.com",
      "password": "user-password"
    }
  }
}
```

### Update IMAP Configuration

```typescript
PUT /api/v1/users/me/config/imap
Authorization: Bearer <session-token>
Content-Type: application/json

{
  "host": "imap.gmail.com",
  "port": 993,
  "user": "user@gmail.com",
  "password": "my-app-password"
}

Response 200:
{
  "serviceName": "imap",
  "config": {
    "host": "imap.gmail.com",
    "port": 993,
    "user": "user@gmail.com",
    "password": "my-app-password"
  },
  "updatedAt": "2024-02-10T16:45:00.000Z"
}
```

### Delete IMAP Configuration

```typescript
DELETE /api/v1/users/me/config/imap
Authorization: Bearer <session-token>

Response 204: No Content
```

### Test Connection (Proposed Endpoint)

```typescript
POST /api/v1/users/me/config/imap/test
Authorization: Bearer <session-token>
Content-Type: application/json

{
  "host": "imap.gmail.com",
  "port": 993,
  "user": "user@gmail.com",
  "password": "app-password",
  "mailbox": "INBOX"
}

Response 200 (Success):
{
  "success": true,
  "message": "Connection successful",
  "details": {
    "server": "imap.gmail.com",
    "port": 993,
    "authentication": "OK",
    "mailbox": "INBOX",
    "totalMessages": 42,
    "unreadMessages": 5
  }
}

Response 400 (Failure):
{
  "success": false,
  "message": "Authentication failed",
  "errorCode": "IMAP_AUTH_FAILED",
  "suggestion": "Check username and password. If using 2FA, use an app-specific password."
}
```

---

## Future Enhancements

1. **OAuth2 Authentication**
   - Support OAuth2 for providers like Gmail and Outlook
   - Eliminate need for app passwords
   - Implement OAuth flow with provider consent screens

2. **Multiple Mailboxes**
   - Configure multiple mailboxes for polling
   - Separate poller instances per mailbox
   - Independent polling intervals per mailbox

3. **Email Filtering**
   - Configure email filters to control which messages are processed
   - Filter by sender, subject, attachment type
   - Regex-based subject matching for invoice identification

4. **Polling Schedule**
   - Configure polling schedules (e.g., business hours only)
   - Pause polling during specific time periods
   - Adaptive polling based on email volume

5. **Attachment Processing Options**
   - Configure attachment file types to process (PDF, XML, etc.)
   - Set maximum attachment size limits
   - Configure virus scanning for attachments

6. **Connection History**
   - Show log of recent connection attempts with timestamps
   - Track connection success/failure rates
   - Export connection logs for troubleshooting

7. **Email Preview**
   - Show recent emails from configured mailbox
   - Preview attachments before processing
   - Manual trigger for specific email processing

---

## Related Documentation

- [User Profile Page](./user-profile-page.md)
- [FINA Configuration Page](./fina-config-page.md)
- [Configuration Dashboard](./config-dashboard.md)
- [Email Poller Implementation](../api/README.md#email-ingestion)
- [Authentication API](../api/README.md#authentication)
