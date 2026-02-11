# Configuration Dashboard Specification

## Overview

The Configuration Dashboard is the central hub for users to manage their service integrations. It provides an at-a-glance view of all configured services (FINA fiscalization, IMAP email polling), their connection health status, and quick access to detailed configuration pages.

**API Endpoint:** `GET /api/v1/users/me/config` (fetch all configurations)

**Accessibility:** Requires authentication (`authMiddleware`)

---

## Wireframe Description

### Desktop Layout (≥ 768px)

```
┌────────────────────────────────────────────────────────────────────────────┐
│  eRačun                                                  [Profile] [Logout] │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│  Configuration Dashboard                                                   │
│  ──────────────────────────────────────────────────────────────────────   │
│                                                                            │
│  Overview of your service integrations and connection status               │
│                                                                            │
│  ┌──────────────────────────────────────────────────────────────────────┐ │
│  │  FINA Fiscalization Service                                           │ │
│  │  ──────────────────────────────────────────────────────────────────  │ │
│  │  Status: ● Configured (Last test: 2 hours ago)                        │ │
│  │                                                                        │ │
│  │  WSDL URL: https://cistest.apis-it.hr:8449/...                        │ │
│  │  Certificate: ./certs/fina.p12                                        │ │
│  │  Environment: Test                                                    │ │
│  │                                                                        │ │
│  │  [ View Details ] [ Test Connection ] [ Configure ]                    │ │
│  └──────────────────────────────────────────────────────────────────────┘ │
│                                                                            │
│  ┌──────────────────────────────────────────────────────────────────────┐ │
│  │  IMAP Email Polling Service                                           │ │
│  │  ──────────────────────────────────────────────────────────────────  │ │
│  │  Status: ● Configured (Last test: 5 minutes ago)                      │ │
│  │                                                                        │ │
│  │  Host: imap.gmail.com                                                 │ │
│  │  Port: 993                                                            │ │
│  │  Polling: Active (checks every 5 minutes)                             │ │
│  │                                                                        │ │
│  │  [ View Details ] [ Test Connection ] [ Configure ]                    │ │
│  └──────────────────────────────────────────────────────────────────────┘ │
│                                                                            │
│  ┌──────────────────────────────────────────────────────────────────────┐ │
│  │  Account Settings                                                      │ │
│  │  ──────────────────────────────────────────────────────────────────  │ │
│  │                                                                        │ │
│  │  Email: user@example.com                                              │ │
│  │  Name: John Doe                                                       │ │
│  │  Member Since: 2024-02-10                                             │ │
│  │                                                                        │ │
│  │  [ Manage Profile ]                                                   │ │
│  └──────────────────────────────────────────────────────────────────────┘ │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
```

### Desktop Layout with Unconfigured Services (≥ 768px)

```
┌────────────────────────────────────────────────────────────────────────────┐
│  eRačun                                                  [Profile] [Logout] │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│  Configuration Dashboard                                                   │
│  ──────────────────────────────────────────────────────────────────────   │
│                                                                            │
│  Overview of your service integrations and connection status               │
│                                                                            │
│  ┌──────────────────────────────────────────────────────────────────────┐ │
│  │  FINA Fiscalization Service                                           │ │
│  │  ──────────────────────────────────────────────────────────────────  │ │
│  │  Status: ○ Not Configured                                             │ │
│  │                                                                        │ │
│  │  Configure your FINA fiscalization credentials to submit invoices     │ │
│  │  to the Croatian fiscalization service.                               │ │
│  │                                                                        │ │
│  │  [ Configure FINA ]                                                   │ │
│  └──────────────────────────────────────────────────────────────────────┘ │
│                                                                            │
│  ┌──────────────────────────────────────────────────────────────────────┐ │
│  │  IMAP Email Polling Service                                           │ │
│  │  ──────────────────────────────────────────────────────────────────  │ │
│  │  Status: ○ Not Configured                                             │ │
│  │                                                                        │ │
│  │  Configure your email server to automatically import invoices from    │ │
│  │  email attachments.                                                   │ │
│  │                                                                        │ │
│  │  [ Configure IMAP ]                                                   │ │
│  └──────────────────────────────────────────────────────────────────────┘ │
│                                                                            │
│  ┌──────────────────────────────────────────────────────────────────────┐ │
│  │  Account Settings                                                      │ │
│  │  ──────────────────────────────────────────────────────────────────  │ │
│  │                                                                        │ │
│  │  Email: user@example.com                                              │ │
│  │  Name: John Doe                                                       │ │
│  │                                                                        │ │
│  │  [ Manage Profile ]                                                   │ │
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
│ Configuration Dashboard              │
│ ──────────────────────────────      │
│                                      │
│ ┌────────────────────────────────┐  │
│ │ FINA Fiscalization             │  │
│ │ ─────────────────────────────  │  │
│ │ ● Configured                   │  │
│ │ Last test: 2 hours ago         │  │
│ │                                │  │
│ │ WSDL: cistest.apis-it.hr       │  │
│ │ Env: Test                      │  │
│ │                                │  │
│ │ [ Test ] [ Configure ]         │  │
│ └────────────────────────────────┘  │
│                                      │
│ ┌────────────────────────────────┐  │
│ │ IMAP Email Polling             │  │
│ │ ─────────────────────────────  │  │
│ │ ● Configured                   │  │
│ │ Last test: 5 min ago           │  │
│ │                                │  │
│ │ Host: imap.gmail.com           │  │
│ │ Polling: Active                │  │
│ │                                │  │
│ │ [ Test ] [ Configure ]         │  │
│ └────────────────────────────────┘  │
│                                      │
│ ┌────────────────────────────────┐  │
│ │ Account Settings               │  │
│ │ ─────────────────────────────  │  │
│ │ Email: user@example.com        │  │
│ │                                │  │
│ │ [ Manage Profile ]             │  │
│ └────────────────────────────────┘  │
│                                      │
└──────────────────────────────────────┘
```

### Mobile Layout with Unconfigured Services (< 768px)

```
┌──────────────────────────────────────┐
│ ☰  eRačun                     [≡]    │
├──────────────────────────────────────┤
│                                      │
│ Configuration Dashboard              │
│ ──────────────────────────────      │
│                                      │
│ ┌────────────────────────────────┐  │
│ │ FINA Fiscalization             │  │
│ │ ─────────────────────────────  │  │
│ │ ○ Not Configured               │  │
│ │                                │  │
│ │ Configure your FINA            │  │
│ │ credentials to submit          │  │
│ │ invoices.                      │  │
│ │                                │  │
│ │ [ Configure FINA ]             │  │
│ └────────────────────────────────┘  │
│                                      │
│ ┌────────────────────────────────┐  │
│ │ IMAP Email Polling             │  │
│ │ ─────────────────────────────  │  │
│ │ ○ Not Configured               │  │
│ │                                │  │
│ │ Configure email server to      │  │
│ │ auto-import invoices.          │  │
│ │                                │  │
│ │ [ Configure IMAP ]             │  │
│ └────────────────────────────────┘  │
│                                      │
│ ┌────────────────────────────────┐  │
│ │ Account Settings               │  │
│ │ ─────────────────────────────  │  │
│ │ Email: user@example.com        │  │
│ │                                │  │
│ │ [ Manage Profile ]             │  │
│ └────────────────────────────────┘  │
│                                      │
└──────────────────────────────────────┘
```

---

## Service Cards

### FINA Fiscalization Service Card

| Element | Description | Behavior |
|---------|-------------|----------|
| **Status Indicator** | Colored dot with text | ● Configured (green), ○ Not Configured (gray), ⚠ Connection Failed (red) |
| **Last Tested** | Timestamp of last connection test | Displays "2 hours ago", "Never tested", or "5 minutes ago" |
| **WSDL URL** | Truncated URL display | Shows domain only (e.g., "cistest.apis-it.hr") when configured |
| **Environment** | Test or Production | Derived from WSDL URL or stored config |
| **Certificate Path** | File path (truncated) | Shows filename only when configured |
| **View Details** | Link/button | Navigates to FINA configuration page |
| **Test Connection** | Button | Triggers connection test, shows loading state, updates status |
| **Configure** | Button | Navigates to FINA configuration page (primary action when not configured) |

**States:**

1. **Configured + Healthy**
   - Green dot
   - "● Configured"
   - Shows WSDL domain and environment
   - "Last test: X ago" with successful timestamp

2. **Configured + Warning**
   - Yellow/Orange dot
   - "⚠ Connection Issue"
   - Shows last failure reason
   - "Last test: X ago" with failed timestamp

3. **Not Configured**
   - Gray dot
   - "○ Not Configured"
   - Helper text about what the service does
   - "Configure FINA" call-to-action button

### IMAP Email Polling Service Card

| Element | Description | Behavior |
|---------|-------------|----------|
| **Status Indicator** | Colored dot with text | ● Configured (green), ○ Not Configured (gray), ⚠ Connection Failed (red) |
| **Last Tested** | Timestamp of last connection test | Displays "5 minutes ago", "Never tested" |
| **Host** | IMAP server hostname | Shows hostname when configured |
| **Port** | IMAP port number | Shows port (typically 993) |
| **Polling Status** | Active/Inactive | Shows "Active (every X minutes)" or "Inactive" |
| **Mailbox** | Configured mailbox name | Shows mailbox (default: INBOX) |
| **View Details** | Link/button | Navigates to IMAP configuration page |
| **Test Connection** | Button | Triggers connection test, shows loading state, updates status |
| **Configure** | Button | Navigates to IMAP configuration page |

**States:**

1. **Configured + Polling Active**
   - Green dot
   - "● Configured"
   - Shows host and port
   - "Polling: Active (every 5 minutes)"

2. **Configured + Polling Inactive**
   - Yellow dot
   - "● Configured (Polling Paused)"
   - Shows host and port
   - "Polling: Inactive"

3. **Configured + Connection Failed**
   - Red dot
   - "⚠ Connection Failed"
   - Shows error message
   - "Last test: X ago"

4. **Not Configured**
   - Gray dot
   - "○ Not Configured"
   - Helper text about auto-importing invoices
   - "Configure IMAP" call-to-action button

### Account Settings Card

| Element | Description | Behavior |
|---------|-------------|----------|
| **Email** | User's email address | Read-only display |
| **Name** | User's display name | Read-only display |
| **Member Since** | Account creation date | Formatted as YYYY-MM-DD |
| **Manage Profile** | Button | Navigates to user profile page |

---

## Status Indicators

### Visual States

| Status | Icon | Color | Label |
|--------|------|-------|-------|
| Configured & Healthy | ● | Green (#10b981) | "Configured" |
| Configured & Warning | ⚠ | Yellow (#f59e0b) | "Connection Issue" |
| Not Configured | ○ | Gray (#9ca3af) | "Not Configured" |
| Connection Failed | ✕ | Red (#ef4444) | "Connection Failed" |
| Testing | ⟳ | Blue (#3b82f6) | "Testing..." |

### Status Transitions

- **Testing**: Spinner displays during connection test (2-10 seconds)
- **Success**: Transitions to "Configured" with green indicator
- **Failure**: Transitions to "Connection Failed" with red indicator and error message
- **Never Tested**: Shows "Never tested" if no test has been performed

---

## Connection Health Display

### Connection Test Results

When a connection test is performed:

1. **Initiation**
   - Button shows "Testing..." spinner
   - Status indicator changes to "Testing..." (blue)
   - Button is disabled during test

2. **Success Response**
   - Status indicator changes to green "● Configured"
   - "Last test: Just now" timestamp updates
   - Success toast/notification: "Connection test successful"
   - Service card details refresh with latest configuration

3. **Failure Response**
   - Status indicator changes to red "⚠ Connection Failed"
   - Error message displays below status (e.g., "Certificate expired", "Invalid credentials")
   - "Last test: Just now" timestamp updates
   - Error toast/notification: "Connection test failed: [reason]"

### Last Tested Display

| Time Elapsed | Display Format |
|--------------|----------------|
| < 1 minute | "Just now" |
| 1-59 minutes | "X minutes ago" |
| 1-23 hours | "X hours ago" |
| 1-6 days | "X days ago" |
| > 7 days | "YYYY-MM-DD" (actual date) |
| Never | "Never tested" |

---

## Quick Actions

### Test Connection Button

**Behavior:**
- Calls `POST /api/v1/users/me/config/:service/test` endpoint
- Shows loading spinner during request
- Disables button to prevent duplicate requests
- Updates status and timestamp on response
- Shows success/error toast notification

**API Contract:**
```typescript
POST /api/v1/users/me/config/fina/test
Authorization: Bearer <session-token>

Response 200:
{
  "success": true,
  "testedAt": "2024-02-10T16:45:00.000Z",
  "message": "Connection test successful"
}

Response 400:
{
  "error": "Connection failed",
  "message": "Certificate file not found",
  "requestId": "uuid"
}
```

### Configure Button

**Behavior:**
- Navigates to service-specific configuration page
- FINA: `/config/fina`
- IMAP: `/config/imap`
- Uses primary button style (more prominent)

### View Details Link

**Behavior:**
- Navigates to service-specific configuration page
- Shows as secondary action (link or outlined button)
- Provides more context than "Configure"

---

## Validation Requirements

### Client-Side Validation

1. **Configuration Status Detection**
   - Check if config exists in response data
   - Display appropriate state (configured/not configured)

2. **Timestamp Formatting**
   - Format ISO timestamps to relative time ("2 hours ago")
   - Handle "null" or undefined timestamps (show "Never tested")

3. **Error Handling**
   - Gracefully handle missing or malformed API responses
   - Show user-friendly error messages
   - Provide retry options

### Server-Side Validation

The backend applies the following validations (defined in `src/api/schemas.ts`):

```typescript
// Configuration retrieval
// GET /api/v1/users/me/config returns:
{
  "fina": {
    "wsdlUrl": "https://...",
    "certPath": "./certs/fina.p12",
    "certPassphrase": "***",
    "lastTestedAt": "2024-02-10T16:45:00.000Z"
  },
  "imap": {
    "host": "imap.gmail.com",
    "port": 993,
    "user": "user@gmail.com",
    "password": "***",
    "lastTestedAt": "2024-02-10T16:40:00.000Z"
  }
}
```

---

## Error Messages

### Dashboard Load Errors

| Scenario | Error Message | Action |
|----------|---------------|--------|
| Authentication failed | "Please log in to view your configurations" | Redirect to login |
| Network error | "Unable to load configurations. Please check your connection." | Retry button |
| Server error (500) | "Something went wrong. Please try again later." | Retry button |
| Empty response | "No configurations found. Get started by configuring a service." | Show empty state |

### Connection Test Errors

| Scenario | Error Message |
|----------|---------------|
| FINA certificate not found | "Certificate file not found. Please check the certificate path." |
| FINA invalid passphrase | "Certificate passphrase is invalid." |
| FINA WSDL unreachable | "Cannot reach FINA service. Please check the WSDL URL." |
| IMAP authentication failed | "IMAP authentication failed. Please check your username and password." |
| IMAP host unreachable | "Cannot reach IMAP server. Please check the host and port." |
| Network timeout | "Connection test timed out. Please try again." |
| Unknown error | "Connection test failed: [error details]" |

---

## Success Messages

| Action | Success Message |
|--------|----------------|
| FINA connection test | "FINA connection test successful" |
| IMAP connection test | "IMAP connection test successful" |
| Configuration saved (navigating back) | "Configuration saved successfully" |

---

## Responsive Design Notes

### Breakpoints

- **Mobile**: < 768px (stack cards vertically, compact layout)
- **Tablet**: 768px - 1024px (2-column grid for cards)
- **Desktop**: > 1024px (2-column or 3-column grid)

### Mobile Adaptations

1. **Card Layout**
   - Stack all service cards vertically
   - Full-width cards
   - Collapse less critical details on small screens

2. **Buttons**
   - Stack buttons vertically
   - Full-width primary action buttons
   - "Configure" button more prominent than "Test Connection"

3. **Typography**
   - Base font size: 16px
   - Card headers: 18px - 20px
   - Status text: 14px - 16px

4. **Touch Targets**
   - Minimum button height: 44px
   - Adequate spacing between interactive elements

### Desktop Enhancements

1. **Card Layout**
   - 2-column grid for service cards
   - Hover effects on cards (subtle shadow lift)
   - More detailed information display

2. **Quick Actions**
   - Inline buttons ("Test Connection", "Configure")
   - Hover states with tooltips
   - Keyboard navigation support

3. **Keyboard Shortcuts**
   - `Tab`: Navigate between service cards
   - `Enter`: Trigger primary action on focused card
   - `t`: Trigger connection test on focused service card

---

## Accessibility

### Keyboard Navigation

| Key | Action |
|-----|--------|
| `Tab` | Move to next service card or button |
| `Shift + Tab` | Move to previous service card or button |
| `Enter` | Trigger primary action on focused element |
| `Space` | Toggle button state (if applicable) |
| `t` | Trigger connection test for focused service |
| `c` | Navigate to configuration page for focused service |

### ARIA Labels

```html
<!-- Service card -->
<article
  class="service-card"
  role="region"
  aria-labelledby="fina-service-title"
>
  <h2 id="fina-service-title">FINA Fiscalization Service</h2>

  <!-- Status indicator -->
  <div role="status" aria-live="polite">
    <span class="status-icon" aria-label="Configured">●</span>
    <span>Configured</span>
    <span class="last-tested">Last test: 2 hours ago</span>
  </div>

  <!-- Test connection button -->
  <button
    type="button"
    aria-label="Test FINA connection"
    aria-describedby="fina-test-status"
  >
    Test Connection
  </button>
  <span id="fina-test-status" class="visually-hidden">
    Testing connection to FINA service
  </span>
</article>
```

### Screen Reader Announcements

- Connection test in progress: "Testing connection to FINA service..."
- Connection test success: "Connection test successful"
- Connection test failure: "Connection test failed. Certificate file not found."
- Status changes announced via `aria-live="polite"`
- Empty state announced: "No services configured. Configure FINA or IMAP to get started."

---

## State Management

### Loading States

| Action | Loading Indicator |
|--------|-------------------|
| Fetching configurations | Full-page skeleton with card placeholders |
| Testing connection | Button shows spinner, status shows "Testing..." |
| Navigating to config page | Navigation loading indicator |

### Empty States

| Scenario | Display |
|----------|---------|
| No services configured | Welcome message with setup guide links |
| FINA not configured | Empty FINA card with "Configure FINA" CTA |
| IMAP not configured | Empty IMAP card with "Configure IMAP" CTA |
| All services configured | Full dashboard with all cards populated |

### Refresh Behavior

- **Auto-refresh**: Dashboard refreshes every 60 seconds (optional feature)
- **Manual refresh**: Pull-to-refresh on mobile, refresh button on desktop
- **Background refresh**: Silently update connection status without UI disruption

---

## Security Considerations

1. **Credential Protection**
   - Never display passwords or passphrases in plain text
   - Mask sensitive fields with asterisks (`***`)
   - Show only non-sensitive config details (host, port, WSDL domain)

2. **Session Validation**
   - Verify authentication status on page load
   - Redirect to login if session expired
   - Clear sensitive data from memory on logout

3. **Error Message Sanitization**
   - Don't expose internal errors or stack traces
   - Sanitize error messages before displaying
   - Log detailed errors server-side for debugging

---

## API Integration

### Fetch All Configurations

```typescript
GET /api/v1/users/me/config
Authorization: Bearer <session-token>

Response 200:
{
  "fina": {
    "wsdlUrl": "https://cistest.apis-it.hr:8449/FiskalizacijaServiceTest?wsdl",
    "certPath": "./certs/fina.p12",
    "certPassphrase": "***",
    "lastTestedAt": "2024-02-10T14:30:00.000Z",
    "testStatus": "success"
  },
  "imap": {
    "host": "imap.gmail.com",
    "port": 993,
    "user": "user@gmail.com",
    "password": "***",
    "mailbox": "INBOX",
    "pollInterval": 300000,
    "lastTestedAt": "2024-02-10T14:25:00.000Z",
    "testStatus": "success",
    "pollingActive": true
  }
}

Response 401:
{
  "error": "Unauthorized",
  "message": "Authentication required",
  "requestId": "uuid"
}
```

### Test FINA Connection (Proposed Endpoint)

```typescript
POST /api/v1/users/me/config/fina/test
Authorization: Bearer <session-token>

Response 200:
{
  "success": true,
  "testedAt": "2024-02-10T16:45:00.000Z",
  "message": "Connection test successful",
  "details": {
    "wsdlUrl": "https://cistest.apis-it.hr:8449/...",
    "environment": "test"
  }
}

Response 400:
{
  "error": "Connection failed",
  "message": "Certificate file not found: ./certs/fina.p12",
  "requestId": "uuid"
}
```

### Test IMAP Connection (Proposed Endpoint)

```typescript
POST /api/v1/users/me/config/imap/test
Authorization: Bearer <session-token>

Response 200:
{
  "success": true,
  "testedAt": "2024-02-10T16:45:00.000Z",
  "message": "Connection test successful",
  "details": {
    "host": "imap.gmail.com",
    "port": 993,
    "mailbox": "INBOX"
  }
}

Response 400:
{
  "error": "Authentication failed",
  "message": "IMAP authentication failed. Check username and password.",
  "requestId": "uuid"
}
```

---

## User Flow

### First-Time Setup Flow

1. User logs in → Redirected to Configuration Dashboard
2. Dashboard shows "No services configured" state
3. FINA card shows "○ Not Configured" with setup guide
4. User clicks "Configure FINA"
5. Configures FINA credentials → Redirected back to Dashboard
6. Dashboard shows "● Configured" status
7. Repeat for IMAP if needed

### Returning User Flow

1. User logs in → Redirected to Dashboard (or last visited page)
2. Dashboard shows all configured services with status
3. User reviews connection health
4. User clicks "Test Connection" to verify services
5. User navigates to specific config page if updates needed

### Troubleshooting Flow

1. User sees "⚠ Connection Failed" status
2. Error message explains issue (e.g., "Certificate expired")
3. User clicks "Configure" to update credentials
4. User fixes issue and returns to Dashboard
5. User clicks "Test Connection" to verify fix
6. Status updates to "● Configured" on success

---

## Future Enhancements

1. **Real-Time Status Updates**
   - WebSocket connection for live status updates
   - Push notifications for connection failures
   - Auto-refresh without full page reload

2. **Connection Health History**
   - Graph showing uptime/availability over time
   - List of recent connection tests with timestamps
   - Error log for troubleshooting

3. **Configuration Templates**
   - Pre-configured templates for common email providers
   - One-click setup for popular services (Gmail, Outlook)
   - Import/export configuration for backup

4. **Service-Specific Metrics**
   - FINA: Number of invoices fiscalized, last fiscalization time
   - IMAP: Number of emails processed, last poll time
   - Activity charts and statistics

5. **Bulk Actions**
   - Test all connections at once
   - Enable/disable all polling with one toggle
   - Configuration reset to defaults

6. **Notification Preferences**
   - Configure alerts for connection failures
   - Email notifications for service issues
   - Customizable thresholds and conditions

---

## Related Documentation

- [User Profile Page](./user-profile-page.md)
- [FINA Configuration Page](./fina-config-page.md)
- [IMAP Configuration Page](./imap-config-page.md)
- [Authentication API](../api/README.md)
- [Configuration Management API](../api/README.md)
