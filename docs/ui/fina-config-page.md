# FINA Configuration Page Specification

## Overview

The FINA (Fiskalizacija) Configuration page allows authenticated users to configure their fiscalization service credentials. This includes the WSDL endpoint URL, the digital certificate file path, and the certificate passphrase required for secure communication with the Croatian Financial Agency (FINA) services.

**API Endpoint:** `GET /api/v1/users/me/config` (fetch), `PUT /api/v1/users/me/config/fina` (update), `DELETE /api/v1/users/me/config/fina` (remove)

**Accessibility:** Requires authentication (`authMiddleware`)

---

## Wireframe Description

### Desktop Layout (≥ 768px)

```
┌────────────────────────────────────────────────────────────────────────────┐
│  eRačun                                                  [Profile] [Logout] │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│  FINA Configuration                                                        │
│  ──────────────────────────────────────────────────────────────────────   │
│                                                                            │
│  Configure your fiscalization service credentials for invoice submission  │
│  to the Croatian Financial Agency (FINA).                                  │
│                                                                            │
│  ┌──────────────────────────────────────────────────────────────────────┐ │
│  │  Connection Settings                                                   │ │
│  │  ──────────────────────────────────────────────────────────────────  │ │
│  │                                                                        │ │
│  │  WSDL URL:                                                             │ │
│  │  [https://cistest.apis-it.hr:8449/FiskalizacijaServiceTest?wsdl]      │ │
│  │                                                                        │ │
│  │  Environment: [ ] Test  [ ] Production                                │ │
│  │                                                                        │ │
│  │  The WSDL URL defines the FINA service endpoint for fiscalization.    │ │
│  │  Test environment: cistest.apis-it.hr (for development)               │ │
│  │  Production: cis.apis-it.hr (for live fiscalization)                  │ │
│  └──────────────────────────────────────────────────────────────────────┘ │
│                                                                            │
│  ┌──────────────────────────────────────────────────────────────────────┐ │
│  │  Certificate Settings                                                  │ │
│  │  ──────────────────────────────────────────────────────────────────  │ │
│  │                                                                        │ │
│  │  Certificate File:                                                     │ │
│  │  [/path/to/certificate.p12                           ]  [Browse...]  │ │
│  │                                                                        │ │
│  │  Certificate Passphrase:                                               │ │
│  │  [************************                            ]  [👁️ Show]     │ │
│  │                                                                        │ │
│  │  ⚠️ The certificate file must be a .p12 (PKCS#12) format containing  │ │
│  │     your private key and certificate from FINA.                       │ │
│  │                                                                        │ │
│  │  Certificate Status: [🟢 Valid]  [🔴 Not Configured]                  │ │
│  └──────────────────────────────────────────────────────────────────────┘ │
│                                                                            │
│  ┌──────────────────────────────────────────────────────────────────────┐ │
│  │  Test Connection                                                       │ │
│  │  ──────────────────────────────────────────────────────────────────  │ │
│  │                                                                        │ │
│  │  [ 🧪 Test Connection ]                                                │ │
│  │                                                                        │ │
│  │  Status: [✓ Connection successful]  [✗ Connection failed]             │ │
│  │                                                                        │ │
│  │  Last tested: 2024-02-10 16:30:00                                      │ │
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
│ FINA Configuration                   │
│ ──────────────────────────────       │
│                                      │
│ Configure your fiscalization         │
│ service credentials...               │
│                                      │
│ ┌────────────────────────────────┐  │
│ │ Connection Settings            │  │
│ │ ─────────────────────────────  │  │
│ │                                │  │
│ │ WSDL URL:                      │  │
│ │ [https://cistest...]          │  │
│ │                                │  │
│ │ Environment:                   │  │
│ │ [ ] Test  [ ] Production       │  │
│ └────────────────────────────────┘  │
│                                      │
│ ┌────────────────────────────────┐  │
│ │ Certificate Settings           │  │
│ │ ─────────────────────────────  │  │
│ │                                │  │
│ │ Certificate File:              │  │
│ │ [/path/to/cert.p12 ]  [Browse]│  │
│ │                                │  │
│ │ Certificate Passphrase:        │  │
│ │ [************      ]  [👁️]    │  │
│ │                                │  │
│ │ [🧪 Test Connection]           │  │
│ │                                │  │
│ │ Status: ✓ Connection successful│  │
│ └────────────────────────────────┘  │
│                                      │
│ [ 💾 Save ]  [ 🗑️ Remove ]          │
│                                      │
└──────────────────────────────────────┘
```

---

## Form Fields

### Connection Settings Section

| Field | Type | Required | Validation | Notes |
|-------|------|----------|------------|-------|
| `wsdlUrl` | URL (text) | Yes | Valid URL format | WSDL endpoint for FINA service. Test: `https://cistest.apis-it.hr:8449/FiskalizacijaServiceTest?wsdl`, Production: `https://cis.apis-it.hr:8449/FiskalizacijaService?wsdl` |
| `environment` | Radio buttons | No | Must be "test" or "production" | UI helper for quick WSDL URL selection. Updates `wsdlUrl` field automatically |

### Certificate Settings Section

| Field | Type | Required | Validation | Notes |
|-------|------|----------|------------|-------|
| `certPath` | File input / Text | Yes | Non-empty string | Path to .p12 certificate file on server. Must be readable by application |
| `certPassphrase` | Password | Yes | Non-empty string | Passphrase to unlock the .p12 certificate. Show/hide toggle provided |

### Test Connection Section

| Field | Type | Notes |
|-------|------|-------|
| `testButton` | Button | Triggers validation endpoint (to be implemented) |
| `connectionStatus` | Read-only | Displays last test result: success, failed, or not tested |
| `lastTested` | Read-only | Timestamp of last connection test |

---

## Validation Requirements

### Client-Side Validation

1. **WSDL URL Field**
   - Required field
   - Must be valid URL format
   - Must start with `https://` (FINA requires secure connection)
   - Common patterns to validate:
     - Test environment: `https://cistest.apis-it.hr:8449/*.wsdl`
     - Production: `https://cis.apis-it.hr:8449/*.wsdl`
   - Error messages:
     - "WSDL URL is required"
     - "Invalid URL format"
     - "WSDL URL must use HTTPS"

2. **Certificate Path Field**
   - Required field
   - Minimum length: 1 character
   - Must end with `.p12` or `.pfx` extension
   - Trim whitespace before submission
   - Error messages:
     - "Certificate path is required"
     - "Certificate file must be .p12 or .pfx format"

3. **Certificate Passphrase Field**
   - Required field
   - Minimum length: 1 character
   - Show/hide toggle for visibility
   - Error messages:
     - "Certificate passphrase is required"

### Server-Side Validation

The backend applies the following validations (defined in `src/api/schemas.ts`):

```typescript
// FINA configuration schema
finaConfigSchema = z.object({
  wsdlUrl: z.string().url('Invalid WSDL URL format'),
  certPath: z.string().min(1, 'Certificate path is required'),
  certPassphrase: z.string().min(1, 'Certificate passphrase is required'),
})
```

**API Response Schema:**
```json
{
  "serviceName": "fina",
  "config": {
    "wsdlUrl": "https://cistest.apis-it.hr:8449/FiskalizacijaServiceTest?wsdl",
    "certPath": "/path/to/certificate.p12",
    "certPassphrase": "encrypted-passphrase"
  },
  "updatedAt": "2024-02-10T16:30:00.000Z"
}
```

---

## Error Messages

### Field Validation Errors

| Scenario | Error Message |
|----------|---------------|
| WSDL URL empty | "WSDL URL is required" |
| WSDL URL invalid | "Invalid WSDL URL format" |
| WSDL URL not HTTPS | "WSDL URL must use HTTPS protocol" |
| Certificate path empty | "Certificate path is required" |
| Certificate path invalid format | "Certificate file must be .p12 or .pfx format" |
| Passphrase empty | "Certificate passphrase is required" |

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
      "field": "wsdlUrl",
      "message": "Invalid WSDL URL format"
    },
    {
      "field": "certPassphrase",
      "message": "Certificate passphrase is required"
    }
  ],
  "requestId": "uuid"
}
```

### Test Connection Error Messages

| Scenario | Error Message |
|----------|---------------|
| Certificate file not found | "Certificate file not found at specified path" |
| Certificate expired | "Certificate has expired. Please renew with FINA" |
| Invalid passphrase | "Certificate passphrase is incorrect" |
| WSDL unreachable | "Cannot connect to WSDL endpoint. Check URL and network" |
| WSDL invalid | "WSDL endpoint returned invalid response" |

---

## Success Messages

| Action | Success Message |
|--------|----------------|
| Configuration saved | "FINA configuration saved successfully" |
| Configuration removed | "FINA configuration removed" |
| Connection test successful | "Connection test successful. Your credentials are valid" |

---

## Environment Quick-Select

### Predefined WSDL URLs

| Environment | WSDL URL | Usage |
|-------------|----------|-------|
| Test | `https://cistest.apis-it.hr:8449/FiskalizacijaServiceTest?wsdl` | Development and testing |
| Production | `https://cis.apis-it.hr:8449/FiskalizacijaService?wsdl` | Live fiscalization |

**UI Behavior:**
- Clicking "Test" radio button populates WSDL URL field with test environment URL
- Clicking "Production" radio button populates WSDL URL field with production URL
- User can still manually edit the WSDL URL after selection
- Add warning when selecting production: "⚠️ You are configuring production environment. Ensure your certificate is valid for production use."

---

## Test Connection Feature

### Behavior

1. **Trigger:** User clicks "Test Connection" button
2. **Validation:** Client-side validation runs first
3. **API Call:** POST to `/api/v1/users/me/config/fina/test` (endpoint to be implemented)
4. **Loading State:** Button shows spinner, disabled during test
5. **Result Display:**
   - Success: Green checkmark, "Connection successful" message
   - Failure: Red X, specific error message from server
6. **Timestamp:** Update "Last tested" field

**Test Connection Request:**
```typescript
POST /api/v1/users/me/config/fina/test
Authorization: Bearer <session-token>
Content-Type: application/json

{
  "wsdlUrl": "https://cistest.apis-it.hr:8449/FiskalizacijaServiceTest?wsdl",
  "certPath": "/path/to/cert.p12",
  "certPassphrase": "passphrase"
}
```

**Test Connection Response (Success):**
```json
{
  "success": true,
  "message": "Connection successful",
  "details": {
    "environment": "test",
    "certificateValidUntil": "2025-12-31",
    "wsdlVersion": "1.5"
  }
}
```

**Test Connection Response (Failure):**
```json
{
  "success": false,
  "message": "Certificate passphrase is incorrect",
  "errorCode": "CERT_INVALID_PASSPHRASE"
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
   - Environment radio buttons stacked vertically
   - Test connection button full-width for easier tapping

3. **File Input**
   - Large touch target for "Browse" button
   - Show full path in smaller font with truncation
   - Consider file upload alternative for mobile (future enhancement)

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
<!-- WSDL URL field -->
<label for="wsdl-url">WSDL URL</label>
<input
  id="wsdl-url"
  name="wsdlUrl"
  type="url"
  aria-required="true"
  aria-describedby="wsdl-hint"
/>
<span id="wsdl-hint" class="hint">
  The FINA service endpoint URL for fiscalization
</span>

<!-- Certificate path field -->
<label for="cert-path">Certificate File Path</label>
<input
  id="cert-path"
  name="certPath"
  type="text"
  aria-required="true"
  aria-describedby="cert-hint"
/>
<span id="cert-hint" class="hint">
  Path to .p12 certificate file on the server
</span>

<!-- Passphrase field with visibility toggle -->
<label for="cert-passphrase">Certificate Passphrase</label>
<div class="password-input">
  <input
    id="cert-passphrase"
    name="certPassphrase"
    type="password"
    aria-required="true"
  />
  <button
    type="button"
    aria-label="Show passphrase"
    aria-pressed="false"
    id="toggle-passphrase"
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
- Test connection progress announced as "Testing connection..."
- Test connection results announced with success/failure status
- Certificate validation warnings announced with role="alert"

---

## State Management

### Loading States

| Action | Loading Indicator |
|--------|-------------------|
| Fetching configuration | Full-page skeleton or spinner |
| Saving configuration | "Save" button shows spinner, all fields disabled |
| Testing connection | "Test Connection" button shows spinner, button disabled |
| Removing configuration | Confirmation modal with spinner after confirmation |

### Idle States

| Scenario | Display |
|----------|---------|
| Configuration loaded | Display form fields with current data |
| Configuration not found | Show empty form with "No FINA configuration" message |
| Certificate validation warning | Show warning banner with certificate expiry date |

---

## Security Considerations

1. **Passphrase Handling**
   - Always use `type="password"` for passphrase field
   - Show/hide toggle is optional (user preference)
   - Never log passphrase in plain text on client or server
   - Passphrase is stored in database as plaintext JSONB (future enhancement: encrypt at rest)

2. **Certificate Path Validation**
   - Validate path is within allowed directories
   - Prevent directory traversal attacks (e.g., `../../etc/passwd`)
   - Server should validate file exists and is readable

3. **WSDL URL Validation**
   - Must use HTTPS protocol only
   - Validate hostname against known FINA domains (optional)
   - Prevent SSRF (Server-Side Request Forgery) by restricting endpoints

4. **Session Management**
   - Require authentication before page access
   - Redirect to login if session expired
   - Clear sensitive fields on logout

---

## API Integration

### Fetch FINA Configuration

```typescript
GET /api/v1/users/me/config
Authorization: Bearer <session-token>

Response 200:
{
  "configs": {
    "fina": {
      "wsdlUrl": "https://cistest.apis-it.hr:8449/FiskalizacijaServiceTest?wsdl",
      "certPath": "/path/to/certificate.p12",
      "certPassphrase": "user-passphrase"
    }
  }
}
```

### Update FINA Configuration

```typescript
PUT /api/v1/users/me/config/fina
Authorization: Bearer <session-token>
Content-Type: application/json

{
  "wsdlUrl": "https://cistest.apis-it.hr:8449/FiskalizacijaServiceTest?wsdl",
  "certPath": "/path/to/certificate.p12",
  "certPassphrase": "my-secret-passphrase"
}

Response 200:
{
  "serviceName": "fina",
  "config": {
    "wsdlUrl": "https://cistest.apis-it.hr:8449/FiskalizacijaServiceTest?wsdl",
    "certPath": "/path/to/certificate.p12",
    "certPassphrase": "my-secret-passphrase"
  },
  "updatedAt": "2024-02-10T16:30:00.000Z"
}
```

### Delete FINA Configuration

```typescript
DELETE /api/v1/users/me/config/fina
Authorization: Bearer <session-token>

Response 204: No Content
```

### Test Connection (Proposed Endpoint)

```typescript
POST /api/v1/users/me/config/fina/test
Authorization: Bearer <session-token>
Content-Type: application/json

{
  "wsdlUrl": "https://cistest.apis-it.hr:8449/FiskalizacijaServiceTest?wsdl",
  "certPath": "/path/to/certificate.p12",
  "certPassphrase": "my-secret-passphrase"
}

Response 200 (Success):
{
  "success": true,
  "message": "Connection successful",
  "details": {
    "environment": "test",
    "certificateValidUntil": "2025-12-31",
    "wsdlVersion": "1.5"
  }
}

Response 400 (Failure):
{
  "success": false,
  "message": "Certificate passphrase is incorrect",
  "errorCode": "CERT_INVALID_PASSPHRASE"
}
```

---

## Future Enhancements

1. **Certificate Upload**
   - Allow users to upload .p12 files directly instead of specifying server path
   - Store uploaded certificates in user-isolated directory
   - Validate certificate format and expiration date on upload

2. **Certificate Expiry Warnings**
   - Display warning banner when certificate expires within 30 days
   - Send email notifications for upcoming expiry
   - Show certificate validity period on configuration page

3. **Multiple Certificate Support**
   - Allow multiple certificates for different environments (test, production)
   - Quick switching between certificates without reconfiguration

4. **Connection Test History**
   - Show log of recent connection tests with timestamps
   - Track connection success/failure rates
   - Export connection test logs for troubleshooting

5. **WSDL URL Discovery**
   - Auto-detect available WSDL endpoints based on environment selection
   - Cache WSDL responses to improve performance
   - Validate WSDL version compatibility

6. **Configuration Presets**
   - Save multiple configuration presets for different use cases
   - Quick switch between presets (e.g., "Development", "Staging", "Production")

---

## Related Documentation

- [User Profile Page](./user-profile-page.md)
- [IMAP Configuration Page](./imap-config-page.md)
- [Configuration Dashboard](./config-dashboard.md)
- [FINA Client Implementation](../api/README.md#fina-service)
- [Authentication API](../api/README.md#authentication)
