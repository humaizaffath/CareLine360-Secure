# V4 – Socket.IO Room Authorization

**Owner:** Umair · **Branch:** `umair/v3-v4-auth-socket`
**Mapping:** CWE-862 (Missing Authorization), CWE-639 (Authorization Bypass Through User-Controlled Key) · OWASP Top 10 2021 A01 Broken Access Control

## Vulnerability

In `server/socket/chatSocket.js`:

- **`join_room`** called `socket.join(appointmentId)` for any authenticated user. The client-supplied appointment ID alone decided room membership.
- **`typing` and `stop_typing`** were relayed into any room ID the client named.
- **Result:** any logged-in user who knew or guessed an appointment ID could receive that consultation's live messages and typing events, and could inject typing indicators into it.
- **Deactivated users:** the socket handshake only verified the JWT, so a deactivated user with an unexpired token could still connect.

Chat history over REST (`GET /api/chat/:appointmentId`) and `send_message` already checked that the caller is the appointment's patient or doctor (`chatService.validateChatAccess`). The live-room path did not.

## Evidence (synthetic users, message text not recorded)

`poc-socket.js` runs the real handler with `socket.io-client`. Patient A emits `join_room` with patient B's appointment ID.

| | Before (`poc-before.json`) | After (`poc-after.json`) |
|---|---|---|
| A gets `room_joined` for B's room | yes | no (`join_error: Access denied`) |
| A receives B's live `new_message` | yes | no |
| A receives B's `user_typing` | yes | no |
| B sees a spoofed typing indicator from A | yes | no |
| Socket without a token | rejected | rejected |
| Deactivated user's socket | **connected** | rejected |

Reproduce: `npm install --prefix security-evidence/V4 --no-package-lock`, then `node security-evidence/V4/poc-socket.js <label>`.

## Fix

- `join_room` validates the appointment ID and runs the existing `validateChatAccess` rule (the appointment's patient or doctor) **before** `socket.join`. Otherwise it emits `join_error`.
- `typing` and `stop_typing` are relayed only into a room this socket successfully joined (`socket.rooms`).
- The handshake loads the user, rejects missing or deactivated accounts (matching the HTTP `authMiddleware`), and takes `role` from the database.
- `send_message` is unchanged; it already authorised the sender.

## Tests

```
cd server
npx jest tests/integration/security/v4-socket-authz.test.js --forceExit
```

The suite has 17 tests and runs against a real Socket.IO server. Against the pre-fix handler, 10 fail. The 7 that pass cover behaviour that was already correct: token rejection, `send_message` denial and normal chat.

## Known limitations

- Access is checked when a socket joins a room. A socket that is already connected is not disconnected if the account is later deactivated or the appointment is reassigned. The membership lasts until the socket leaves or disconnects.
- The handshake still accepts a token in the query string and returns JWT error text (behaviour unchanged).
