# kick-echo-cmd

Echo-bot do Kick: gdy na czacie pojawi się **5 takich samych** komend (zaczynających się od `!`), bot wyśle **tę samą** komendę.

## Szybki start (Render lub lokalnie)
1. Dodaj pliki `server.js`, `package.json`, `.env` (z `.env.example`).
2. Ustaw ENV:
   - `ALLOWED_SLUGS` – slugi kanałów, np. `rybsonlol`
   - `KICK_CLIENT_ID`, `KICK_CLIENT_SECRET`, `KICK_REDIRECT_URI`
   - (opcjonalnie) `BOT_USERNAME` – żeby nie liczyć wiadomości bota
3. Uruchom:
   ```bash
   npm install
   npm start
   ```
4. Wejdź na `https://host/auth/start`, zaloguj, zezwól na `chat:write`.

## Endpoints
- `GET /health` – ok
- `GET /stats` – ostatnie wykryte komendy per kanał

## Dodatkowe notatki
- Cooldown per-komenda (domyślnie 120s) chroni przed zapętlaniem spamu.
- Jeśli Twoje środowisko ma problem z pobraniem `chatroom_id` z API/HTML, ustaw `CHATROOM_ID_OVERRIDES`.
