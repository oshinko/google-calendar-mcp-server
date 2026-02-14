# Google Calendar MCP Server

Google Calendar を参照する MCP サーバーです。

## Setup

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.template .env
```

## Run (local)

```sh
dotenv run -- python app.py
```

デフォルトでは `http://127.0.0.1:5000` で起動します。

## OAuth 認証テスト（ACCESS_TOKEN 取得）

認可コード + PKCE フローで `ACCESS_TOKEN` を取得し、キャッシュJSONに保存します。スコープはMCPサーバーの `scopes_supported` を使用します。
`.env` には保存しません。

```sh
python scripts/test_oauth_authcode.py \
  --base-url http://127.0.0.1:5000 \
  --client-id YOUR_OAUTH_CLIENT_ID \
  --client-secret YOUR_OAUTH_CLIENT_SECRET \
  --redirect-uri http://127.0.0.1:8765/callback \
  --cache-file tmp/oauth_cache.json
```

実行後に表示される認可URLをブラウザで開き、リダイレクト後のURL全体を貼り付けてください。

## ChatGPT App 連携時の HTTPS 公開

ChatGPT のアプリ/コネクタとして使う場合、サーバーは HTTPS で公開されている必要があります。
開発時は ngrok を使う前提です。

### ngrok 起動例

別ターミナルで以下を実行します。

```sh
ngrok http 5000 --domain=<your-ngrok-domain>.ngrok-free.app
```

公開URL:

- `https://<your-ngrok-domain>.ngrok-free.app`

### .env 設定例

ngrok 経由で利用する場合は `.env` の `RESOURCE` を公開URLに合わせてください。

```env
RESOURCE=https://<your-ngrok-domain>.ngrok-free.app
```

必要に応じて `APP_HOST=0.0.0.0` で待ち受けます。

OAuth 認可エンドポイントのプロキシはデフォルトで無効です。
Dynamic Client Registration のみ必要な場合は、無効のままで問題ありません。
必要な場合のみ `.env` で有効化してください。

```env
ENABLE_AUTH_ENDPOINT_PROXY=true
```

## Main endpoints

- `POST /` : MCP JSON-RPC endpoint
- `GET /.well-known/oauth-authorization-server`
- `GET /.well-known/oauth-protected-resource`
- `GET /oauth/authorize`（`ENABLE_AUTH_ENDPOINT_PROXY=true` の場合のみ）

## Tools

- `google_calendar_list`
- `google_calendar_events`

## Docker

```sh
docker image build -t google-calendar-mcp-server .
docker container run --rm -p 80:80 --env-file .env google-calendar-mcp-server
```

コンテナ内では gunicorn（WSGI）で起動します。

`.env` の `RESOURCE` は公開URLに合わせて設定してください。
