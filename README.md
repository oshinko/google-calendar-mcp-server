# Google Calendar MCP Server

Google Calendar を参照する MCP サーバーです。

## ChatGPT で試す

本 MCP サーバーはただいまデモを公開中です。URL は次の通り。

`https://app-6365ec52-2150-4db3-8e62-a55cbbb83eef.ingress.apprun.sakura.ne.jp`

### 1. Google Cloud 側の準備

1. Google Cloud でプロジェクトを作成します。
2. Google Calendar API を有効化します。
3. 「API とサービス」に移動し、OAuth 2.0 クライアント（ウェブアプリケーション）を作成します。
4. 承認済みのリダイレクト URI に `https://chatgpt.com/connector_platform_oauth_redirect` を追加します。
5. 発行された Client ID / Client Secret を控えておきます。

### 2. ChatGPT 側でアプリを登録

1. ChatGPT で Developer mode を有効化します（管理者権限が必要な場合あり）。
2. `Apps -> Create` から新規アプリ（MCPコネクタ）を作成します。
3. Endpoint に本サーバーの URL を設定します。
4. OAuth を選択して設定を進めます。
5. 保存後、ドラフトでツール列挙と OAuth ログインをテストします。

### 公式ドキュメント

- [OpenAI: Developer mode, and MCP apps in ChatGPT [beta]](https://help.openai.com/en/articles/12584461-developer-mode-apps-and-full-mcp-connectors-in-chatgpt-beta)
- [OpenAI: MCP アプリで認証に OAuth を使用する場合](https://help.openai.com/ja-jp/articles/12584461-developer-mode-and-mcp-apps-in-chatgpt-beta#h_73fb68ebd5)
- [OpenAI: Building MCP servers for ChatGPT and API integrations](https://platform.openai.com/docs/mcp)
- [Google: Create access credentials (OAuth client ID)](https://developers.google.com/workspace/guides/create-credentials)
- [Google: Calendar API OAuth/consent setup](https://developers.google.com/calendar/api/guides/auth)
- [Google: OAuth 2.0 for Web Server Applications](https://developers.google.com/identity/protocols/oauth2/web-server) (`redirect_uri` 一致要件)

## 開発

### 準備

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.template .env
```

### 起動

```sh
dotenv run -- python app.py
```

デフォルトでは `http://127.0.0.1:5000` で起動します。

### Docker で起動

```sh
docker image build -t google-calendar-mcp-server .
docker container run --rm -p 80:80 --env-file .env google-calendar-mcp-server
```

コンテナ内では gunicorn（WSGI）で起動します。

`.env` の `RESOURCE` は公開URLに合わせて設定してください。

## 主なエンドポイント

- `POST /` : MCP JSON-RPC endpoint
- `GET /.well-known/oauth-authorization-server`
- `GET /.well-known/oauth-protected-resource`
- `GET /oauth/authorize`（`ENABLE_AUTH_ENDPOINT_PROXY=true` の場合のみ）
- `POST /oauth/token`（`ENABLE_TOKEN_ENDPOINT_PROXY=true` の場合のみ）

## Tools

- `google_calendar_list`
- `google_calendar_events`

## OAuth 認証テスト

認可コード + PKCE フローでトークンを取得し、キャッシュJSONに保存します。スコープはMCPサーバーの `scopes_supported` を使用します。
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
ngrok http 5000 --url https://<your-ngrok-domain>.ngrok-free.app
```

### .env 設定例

ngrok 経由で利用する場合は `.env` の `RESOURCE` を公開URLに合わせてください。

```env
RESOURCE=https://<your-ngrok-domain>.ngrok-free.app
```

必要に応じて `APP_HOST=0.0.0.0` で待ち受けます。

OAuth 認可サーバーのプロキシはデフォルトで無効です。
必要な場合のみ `.env` で有効化してください。

```env
ENABLE_AUTH_ENDPOINT_PROXY=true
ENABLE_TOKEN_ENDPOINT_PROXY=true
```

### offline_access と Google OAuth の注意点

ChatGPT の MCP アプリでリフレッシュトークン運用を安定させるには、認可リクエストで `offline_access` を扱えることが重要です。  
本サーバーは discovery metadata の `scopes_supported` に `offline_access` を含めています。

一方で Google OAuth は `scope=offline_access` をそのまま受け付けないため、`ENABLE_AUTH_ENDPOINT_PROXY=true` の場合に限り、`/oauth/authorize` プロキシ内で `offline_access` を除去し `access_type=offline` を付与して Google に中継します。

この変換を使わない場合、Google 側でリフレッシュトークンが返らず、アクセストークン期限切れごとに再認証が必要になることがあります。
