# ベースイメージ（Node.js 24）
FROM node:24-slim

# 作業ディレクトリを設定
WORKDIR /workspace

# package.jsonを先にコピーしてインストール（キャッシュ効率化）
COPY package*.json ./
RUN npm install --omit=dev

# ソースコードをすべてコピー
COPY . .

# Cloud Runが使うポートを宣言
EXPOSE 8080

# アプリを起動（ファイル名はapp.jsに合わせる）
CMD ["node", "app.js"]