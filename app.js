require('dotenv').config();         //.envファイルを読み込む
const express = require('express'); //expressフレームワークを読み込む
const bcrypt = require('bcrypt');   //パスワードを暗号化するためのライブラリ
const app = express();              //expressを使ってアプリ作成
const jwt = require('jsonwebtoken');    //jsonwebtokenを使うためのライブラリ
const JWT_SECRET = process.env.JWT_SECRET;  //暗号化の為の秘密のコードを.envファイルから引っ張る
if (!process.env.JWT_SECRET) throw new Error("JWT_SECRETが設定されていません");　　//エラー設定
const {Sequelize,DataTypes,Op} = require('sequelize');  //JSでSQLを使うためのライブラリ
const {OpenAI} = require('openai');               //OpenAI APIを使うためのライブラリ
const openai = new OpenAI({
    apiKey: process.env.OPENAI_API_KEY             //.envファイルからOPENAI_API_KEYを取り出す
});
const nodemailer = require('nodemailer')           //メール通知を使用するためのライブラリ
const transporter = nodemailer.createTransport({        //メール送信用アカウントの設定
    service: 'gmail',
    auth: {                                            //.envファイルから通知配信アカウントの情報を取得
        user: process.env.GMAIL_NOTIFY_USER,
        pass: process.env.GMAIL_NOTIFY_APP_PASSWORD
    }
});

const { google } = require('googleapis');          //Gmail　APIを使うためのライブラリ
const fs = require('fs');                          //File system　ファイルを操作(読む、保存など)する設定
const path = require('path');                      //path　ファイルpathを安全に整える


const cors = require('cors');                //Cross-Origin Resource Sharing
app.use(cors({ 
    origin: [                                    //origin:このURLからのアクセスだけ許可する
        'http://127.0.0.1:5500',
        'https://job-app--job-app-874ad.asia-east1.hosted.app'
    ],
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],        //method:'GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'などのメソッドを許可する
    allowedHeaders: ['Content-Type', 'Authorization']              // allowedHeaders:// AuthorizationヘッダーでJWTトークンを送ることを許可する
}));


app.use(express.static(path.join(__dirname, 'public')));　　//publicフォルダに入ったHTML、CSS、JSファイルをブラウザに配信するための設定


// OAuth2 クライアントを生成するヘルパー関数　（ホイスティング、巻き上げ）
function createOAuth2Client() {            //GoogleAPIを使う際のキーを生成
    return new google.auth.OAuth2(
        process.env.GOOGLE_CLIENT_ID,        //アプリのID
        process.env.GOOGLE_CLIENT_SECRET,    //アプリのシークレットキー
        process.env.GOOGLE_REDIRECT_URI      //承認後にGoogleが戻ってくるURL
    );
}





app.use(express.json()); // 送られてきたデータ(JSON)を受け取るための設定




// フロントの「Gmail連携」ボタンを押したときに、このURLにアクセスさせてGoogleのログイン画面に遷移
app.get('/api/auth/google/url', authenticateToken, (req, res) => {
    const oauth2Client = createOAuth2Client();                //createOAuth2Client()を呼び出し結果を変数に格納

    // ユーザーに許可を求める権限（スコープ）を設定
    const scopes = [
        'https://www.googleapis.com/auth/gmail.modify' // Gmailのmodify(開封、読み取り等)の権限
    ];

    // 認証画面のURLを生成
    const url = oauth2Client.generateAuthUrl({
        access_type: 'offline', // ユーザーが画面を閉じても、裏で永続的に自動取得するための「リフレッシュトークン」を貰う設定
        prompt: 'consent',     // 毎回確実にリフレッシュトークンを貰うために同意画面を強制
        scope: scopes,
        // stateにuserIdを含めることで、Googleから戻ってきたときに誰の連携か識別できるようにする
        state: String(req.user.userId) 
    });

    res.json({ url });        //ログインURLを生成してフロントに返す
});






// ユーザーがGoogleで許可を押すと、ここに自動で遷移
app.get('/api/auth/google/callback', async (req, res) => {
    try {
        const { code, state } = req.query; // Googleから渡されるコードと、仕込んでおいたuserId(state)

        if (!code) {
            return res.status(400).send("認証コードが見つかりませんでした。");
        }

        // stateからユーザーIDを復元
        const userId = parseInt(state, 10);

        const oauth2Client = createOAuth2Client();　 //createOAuth2Client()を呼び出し結果を変数に格納
        
        //一時的なコードを使って、Googleから「アクセストークン」と「リフレッシュトークン」を貰う
        const { tokens } = await oauth2Client.getToken(code);
        
        //※裏でずっと自動取得するために必要なリフレッシュトークン
        const refreshToken = tokens.refresh_token; 

        if (!refreshToken) {
            // すでに一度連携していて、prompt=consentが効いていない場合にnullになる場合あり
            console.log("【警告】リフレッシュトークンが取得できませんでした（再連携が必要です）");
        }

        //データベース（Userテーブル）にトークンを保存する
        const user = await User.findByPk(userId);           //findByPKはプライマリキーでDBを１件検索する関数
        if (!user) {
            return res.status(404).send("ユーザーが見つかりませんでした。");
        }

        // Userモデルに gmailRefreshToken というカラムを追加して保存する例
        await user.update({
            gmailRefreshToken: refreshToken || user.gmailRefreshToken // あれば更新
        });

        console.log(`[Gmail連携成功] ユーザーID: ${userId} のリフレッシュトークンを保存しました`);

        
        // 3. 連携完了画面へリダイレクト
        const FRONTEND_URL = 'https://job-app--job-app-874ad.asia-east1.hosted.app/applications.html';        //application.htmlを変数に格納
        res.redirect(`${FRONTEND_URL}?gmail_sync=success`);        //application.htmlにリダイレクト
    } catch (error) {
        console.error("[Googleコールバックエラー]:", error);
        res.status(500).send("Google認証の処理中にエラーが発生しました。");
    }
});




//Gmail連携を解除する
app.delete('/api/auth/google/disconnect',authenticateToken,async (req, res) => {
    try {
        const userId = req.user.userId;                //jsonwebtokenからuserIdを取り出す
        const user = await User.findByPk(userId);      //findbyPkでユーザーを取得

        if (!user) {
            return res.status(404).json({ message: "ユーザーが見つかりません。"});
        }
         await user.update({                      
             gmailRefreshToken: null,            //現在持っているgmailRefreshTakenをnull
             lastGmailSync: null               　//誤表示を防ぐため最終同期時間もnullに置き換える
         });

        res.json({message: "Gmail連携を解除しました。"});

    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "サーバー側でエラーが発生しました。"});
    }
});



//(ミドルウェア)共通のトークンチェッカー（ホイスティング、巻き上げ）
function authenticateToken(req,res,next){
    const authHeader = req.headers['authorization'];        //ヘッダーからトークンを取り出す
    const token = authHeader && authHeader.split(' ')[1];    //Bearer　トークンの　’トークン’　部分だけ抽出

    if (!token) {
        return res.status(401).json({message:"トークンが必要です。ログインしてください。"});
    }

    jwt.verify(token,JWT_SECRET,(err,decoded) => { //トークンの検証
        if (err){
            return res.status(403).json({message:"トークンが無効、または期限切れです。"});
        }
        //トークンが正しければ、中のユーザーIDをreq.userに入れて次の処理に進む
        req.user = decoded;
        next();
    });
}







// データベースの接続設定（Supabaseへの接続）
const sequelize = new Sequelize(process.env.DATABASE_URL, {        //.envファイルからデータベースURLを取得
    dialect: 'postgres',                                           //‘postgresSQL’を使用
    protocol: 'postgres',
    logging: false,                                                //SQLログをコンソールに表示しない
    dialectOptions: {
        ssl: {                                                     //暗号通信を必須にする
            require: true,                                        　//SSL証明書の検証を省略
            rejectUnauthorized: false,
            servername: process.env.SUPABASE_SERVERNAME            //接続先のサーバー名を.envファイルから引っ張る
        }
    }
});


//ユーザー情報のテーブル定義
const User = sequelize.define('User',{
    id:{type:DataTypes.INTEGER, primaryKey: true, autoIncrement: true},
    username:{type:DataTypes.STRING, allowNull:true},
    email:{type:DataTypes.STRING, allowNull:false, unique: true},
    password:{type:DataTypes.STRING, allowNull: false},
    gmailRefreshToken: { type: DataTypes.STRING, allowNull: true },
    lastGmailSync: { type: DataTypes.DATE, allowNull: true },
    notifyInterview: { type: DataTypes.BOOLEAN, defaultValue: true },
    notifyDocument: { type: DataTypes.BOOLEAN, defaultValue: true }
});

//応募データのテーブル定義
const Application = sequelize.define('Application',{
    id:{type:DataTypes.INTEGER, primaryKey: true, autoIncrement: true},    //id
    userId:{ type:DataTypes.INTEGER, allowNull: false},                    //ユーザーid
    companyName: { type: DataTypes.STRING, allowNull: false},              //会社名
    jobTitle:{ type: DataTypes.STRING, allowNull: false},                  //部署名
    status:{type: DataTypes.STRING, defaultValue:'応募中'},                //選考ステータス
    source:{ type: DataTypes.STRING,defaultValue:'その他' },               //どこから応募したか
    interviewDate:{ type: DataTypes.DATE, allowNull: true},               //面接日
    belongings:{ type: DataTypes.STRING, allowNull: true},                //必要なもの
    companyUrl:{ type: DataTypes.STRING, allowNull: true},                //応募先ホームページ
    ratingSalary:{type: DataTypes.INTEGER, defaultValue:0},               //給与評価
    ratingHoliday:{type: DataTypes.INTEGER, defaultValue:0},              //休日評価
    ratingLocation:{type: DataTypes.INTEGER, defaultValue:0},             //通勤距離
    ratingWork:{type: DataTypes.INTEGER, defaultValue:0},                 //働きやすさ
    deadlineDate:{ type: DataTypes.STRING, allowNull: true}               //締切日
    
});

sequelize.sync({alter: true})                    //alterは既存のテーブル構造を変える関数(柔軟にカラムを追加できる)
.then(() => console.log('データベースの準備が完了しました'))
.catch(err => console.error('データベースの接続エラー:',err));






//  ユーザー登録の窓口
app.post('/register', async (req, res) => {  //　/registerはURL,reqは入力情報、resは返信
    try{
        const { username, email, password} = req.body;        
        
        //データベースから同じメールアドレスの人がいないか探す
        const exists = await User.findOne({where:{email}});
        if (exists) {
            return res.status(400).json({message:"既に登録されているメールアドレスです。"});
        }
        
        //パスワードを安全に暗号化(ハッシュ化)する
        const hashedPassword = await bcrypt.hash(password,10);
        
        //データベース(userテーブル)に保存する
        await User.create({
            username:username,
            email:email,
            password:hashedPassword
        });
        
        res.status(201).json({message:"データベースにユーザー登録が完了しました"});
        
    } catch (err){
        console.error(err);
        res.status(500).json({message:"サーバー側でエラーが発生しました。"});
    }
});






//ユーザーログインの窓口
app.post('/login',async (req,res) =>{       //裏側で処理
    try{
        const {email,password} = req.body;
        
        //データベースから、入力された、メールアドレスのユーザーを１件探す
        const user = await User.findOne({where:{email}});
        
        //見つからなければ(401)承認エラーを返す
        if (!user){
            return res.status(401).json({message:"メールアドレス又はパスワードが違います"});
        }
        
        //入力されたパスワードと、データベースに保存されている暗号化パスワード(user.password)を比較する
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch){
            return res.status(401).json({message:"メールアドレス又はパスワードが違います"});
        }
        
        //パスワードがあっていれば、ユーザーIDを含めた「会員証(JWTトークン)」を発行する
        const token = jwt.sign({userId: user.id},JWT_SECRET,{expiresIn:'1h'});
        
        res.json({
            message:"ログインに成功しました！",
            token: token 
        });
    } catch (err){
        console.error(err);
        res.status(500).json({message:"サーバー側でエラーが発生しました。"});
    }
});






//ログイン後のホームページ
app.get ('/profile', authenticateToken, async (req,res) => {
    try{
        //authenticateTokenを使ってreq.user.userIdを取り出してデータベースから探す
        const user = await User.findByPk(req.user.userId,{
            attributes:['id','email','username','lastGmailSync','gmailRefreshToken'] //id,email,username,gmailrefreshtoken,最後にGmailに同期した時刻のデータをデータベースから取得
        });
        
        if(!user) {
            return res.status(404).json({message:"ユーザーが見つかりませんでした。"});
        }
        
        res.json({
            message:"マイページへようこそ",
            user: user //データベースからユーザーデータを探して返す
        });
    } catch (err){
        console.error(err);
        res.status(500).json({message:"サーバー側でエラーが発生しました。"});
    }
});






// メール本文からAI自動解析してDBに保存・更新するAPI（手動コピペ想定）
app.post('/api/applications/auto-import', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;      　  //jsonwebtokenからuserIdを取り出す
        const { emailBody } = req.body;         // 画面からメールの生テキストを受け取る
        
        if (!emailBody || emailBody.trim() === "") {            //メールが空なら早期リターン(無駄にaiAPIを叩かないため)
            return res.status(400).json({ message: "メール本文が空です" });
        }
        
        console.log(`[AI解析開始] ユーザーID: ${userId} のメールを解析中...`);
        
        // 1. OpenAI API を呼び出して構造化データを取得
        const response = await openai.chat.completions.create({
            model: "gpt-4o-mini",                    //AIモデルの指定
            messages: [
                {                        
                    role: "system",            //プロンプト
                    content: `あなたは優秀な就職活動アシスタントです。
                    提供されたメール本文を読み解き、指定されたJSON構造に必要な情報を正確に抽出してください。
                    
                    【ステータス（status）の判定ルール】
                    メールの内容から、以下のいずれかに分類して文字列で設定してください。
                    - "書類選考中" : 応募受付メールなど
                    - "面接待ち" : 面接や面談の日程調整、案内メール
                    - "不採用" : 選考見送り、お祈りメール
                    - "内定" : 内定通知メール
                    該当する情報がない項目や、メール内に記載がない項目はすべて「null」にしてください。`
                },
                {
                    role: "user",
                    content: emailBody        //解析する本文
                }
            ],
            response_format: {
                type: "json_schema",        //AIの返信をJson形式に強制(DBに保存しやすいように)
                json_schema: {
                    name: "application_auto_import",
                    strict: true,
                    schema: {
                        type: "object",
                        properties: {
                            companyName: { type: "string" },
                            jobTitle: { type: ["string", "null"] },
                            status: { type: "string" },
                            interviewDate: { type: ["string", "null"] },
                            belongings: { type: ["string", "null"] },
                            companyUrl: { type: ["string", "null"] },
                            deadlineDate: { type: ["string", "null"] }
                        },
                        required: ["companyName", "jobTitle", "status", "interviewDate", "belongings", "companyUrl", "deadlineDate"],
                        additionalProperties: false
                    }
                }
            }
        });
        
        // AIの解析結果（JSON）を整える(パース)
        const aiResult = JSON.parse(response.choices[0].message.content);
        const parseDate = (dateStr) => {
            if (!dateStr) return null;
            const parsed = new Date(dateStr);
            if (!isNaN(parsed.getTime())) return parsed;
            // 「2026年5月28日」のような日本語形式をパース(整形)
            const match = dateStr.match(/(\d{4})年(\d{1,2})月(\d{1,2})日/);
            if (match) return new Date(`${match[1]}-${match[2].padStart(2,'0')}-${match[3].padStart(2,'0')}`);
            return null;
        };
        aiResult.interviewDate = parseDate(aiResult.interviewDate);
        console.log("[AI解析完了] 結果:", aiResult);
        
        
        // 同じユーザーが、同じ企業名で既に登録しているか確認
        let application = await Application.findOne({        //findOneでApplicationテーブルから１件だけ探す
            where: {
                userId: userId,                               //ログイン中のユーザーのデータで
                companyName: aiResult.companyName            //AIが解析した会社名と一致するもの
            }
        });
        
        if (application) {                                     // 既存データがある場合ステータスや新しい情報を上書き更新（アップデート）
            console.log(`[DB更新] 既存の企業を発見したため、データを更新します: ${aiResult.companyName}`);
            
            await application.update({                // 情報がnullでなければ上書き、nullなら既存を維持
                jobTitle: aiResult.jobTitle || application.jobTitle, 
                status: aiResult.status, // ステータス（お祈りや面接待ちなど）は最新状態に更新
                interviewDate: aiResult.interviewDate || application.interviewDate,
                belongings: aiResult.belongings || application.belongings,
                companyUrl: aiResult.companyUrl || application.companyUrl,
                deadlineDate: aiResult.deadlineDate || application.deadlineDate
            });
            
            return res.json({
                message: `「${aiResult.companyName}」の情報を自動更新しました（ステータス: ${aiResult.status}）`,
                action: "update",
                application
            });
            
        } else {
            // 新規データの場合新しくデータを挿入（作成）
            console.log(`[DB新規登録] 新しい企業のため、新規登録します: ${aiResult.companyName}`);
            
            const newApplication = await Application.create({
                userId: userId,
                companyName: aiResult.companyName,
                jobTitle: aiResult.jobTitle || "職種不明",
                status: aiResult.status,
                source: "メール自動取り込み", 
                interviewDate: aiResult.interviewDate,
                belongings: aiResult.belongings,
                companyUrl: aiResult.companyUrl,
                deadlineDate: aiResult.deadlineDate
            });
            
            return res.status(201).json({
                message: `「${aiResult.companyName}」の情報を新規登録しました`,
                action: "create",
                application: newApplication
            });
        }
        
    } catch (error) {
        console.error("[自動取り込みエラー]:", error);
        res.status(500).json({ message: "メールの自動解析・登録中にエラーが発生しました。" });
    }
});





// Gmailから自動取得してAI解析・DB保存するAPI

app.post('/api/applications/sync-gmail', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;                    //jsonwebtokenからuserIdを取り出す
        const user = await User.findByPk(userId);          //findbyPkでユーザーを取得
        
        console.log("--- 【デバッグ】Gmail同期を試みたユーザー情報 ---");
        console.log("要求されたユーザーID (JWTの中身):", userId);
        if (user) {
            console.log("DB上のユーザーID:", user.id);
            console.log("DB上のメールアドレス:", user.email);
            console.log("DB上のリフレッシュトークン:", user.gmailRefreshToken ? "値あり(OK)" : "中身はnull(これが原因)");
        } else {
            console.log("そもそもDBにこのユーザーIDが存在しません。");
        }
        console.log("-----------------------------------------------");
        
        if (!user || !user.gmailRefreshToken) {
            return res.status(400).json({ message: "Gmail連携が設定されていません。先に連携を行ってください。" });
        }
        
        
        // Google APIの認証クライアントを設定
        const oauth2Client = createOAuth2Client();            //createOAuth2Client()を呼び出し結果を変数に格納
        oauth2Client.setCredentials({
            refresh_token: user.gmailRefreshToken            //OAuthクライアントにDBから取得したユーザーのリフレッシュトークンを設定
        });
        
        const gmail = google.gmail({ version: 'v1', auth: oauth2Client });        //GmailAPIを利用するクライアントを作成
        
        console.log(`[Gmail同期開始] ユーザーID: ${userId} の新着メールをスキャン中...`);
        
        // 未読（is:unread）で、選考・面接・内定・見送りなどの単語が含まれるメールを取得
        const searchQuery = 'is:unread ("選考" OR "面接" OR "内定" OR "見送り" OR "就職活動")';        //検索条件
        
        const listResponse = await gmail.users.messages.list({            //検索条件
            userId: 'me',            //承認している本人のGmailアカウント
            q: searchQuery,            //検索条件
            maxResults: 5 // 一度に処理する件数を安全のため最大5件に制限
        });
        
        const messages = listResponse.data.messages || [];        //Gmail連携を承認しているアカウントに来た未読メッセージの数を検索
        if (messages.length === 0) {                              //0件の場合
            await user.update({ lastGmailSync: new Date() });
            return res.json({ message: "新しい就活関連の未読メールは見つかりませんでした。", importedCount: 0 });
        }
        
        let importedCount = 0;            //インポートしたメールの数（はじめは0）
        let summaryMessages = [];        //更新メッセージをまとめるリスト
        
        // 見つかったメールを1件ずつ解析してDBへ保存していく
        for (const msgInfo of messages) {
            // メールの詳細（本文）を取得
            const msgDetails = await gmail.users.messages.get({
                userId: 'me',
                id: msgInfo.id,
                format: 'full'
            });
            
            // メールの本文（Body）をパース（デコード）する処理
            let emailBody = "";                //メール本文を格納する変数
            const payload = msgDetails.data.payload;        //メールの構造データを取得
            
            if (payload.parts) {
                // 複数パーツに分かれている場合（テキスト、HTMLなど）
                const textPart = payload.parts.find(part => part.mimeType === 'text/plain');
                if (textPart && textPart.body.data) {
                    emailBody = Buffer.from(textPart.body.data, 'base64').toString('utf8');        //base64形式でエンコードされたメール本文を普通の文字列(UTF-8)に変換
                }
            } else if (payload.body && payload.body.data) {
                // 単一パーツの場合
                emailBody = Buffer.from(payload.body.data, 'base64').toString('utf8');        //base64形式でエンコードされたメール本文を普通の文字列(UTF-8)に変換
            }
            
            if (!emailBody || emailBody.trim() === "") continue;                //本文が取得できなかった、または空白の場合はこのメールをスキップ(continue)、trim()はスペースや改行だけの意味のないスペースを除外
            
            // OpenAIの解析処理
            const aiResponse = await openai.chat.completions.create({
                model: "gpt-4o-mini",
                messages: [
                    {
                        role: "system",                    //プロンプト
                        content: `あなたは優秀な就職活動アシスタントです。提供されたメール本文を読み解き、指定されたJSON構造に必要な情報を正確に抽出してください。
                        【ステータス（status）の判定ルール】
                        - "書類選考中" : 応募受付メールなど
                        - "面接待ち" : 面接や面談の日程調整、案内メール
                        - "不採用" : 選考見送り、お祈りメール
                        - "内定" : 内定通知メール
                        該当情報がない項目はすべて「null」にしてください。`
                    },
                    { role: "user", content: emailBody }
                ],
                response_format: {
                    type: "json_schema",
                    json_schema: {
                        name: "gmail_auto_import",
                        strict: true,
                        schema: {
                            type: "object",
                            properties: {
                                companyName: { type: "string" },
                                jobTitle: { type: ["string", "null"] },
                                status: { type: "string" },
                                interviewDate: { type: ["string", "null"] },
                                belongings: { type: ["string", "null"] },
                                companyUrl: { type: ["string", "null"] },
                                deadlineDate: { type: ["string", "null"] }
                            },
                            required: ["companyName", "jobTitle", "status", "interviewDate", "belongings", "companyUrl", "deadlineDate"],
                            additionalProperties: false
                        }
                    }
                }
            });

            let aiResult;            //AIの解析結果を格納する変数
            try {
                aiResult = JSON.parse(aiResponse.choices[0].message.content);        //jsonで帰ってきたAIのレスポンスをJavaScriptのオブジェクトに変換
                const parseDate = (dateStr) => {                                     //日付の表記ずれを防ぐために整形（パース）
                    if (!dateStr) return null;
                    const parsed = new Date(dateStr);
                    if (!isNaN(parsed.getTime())) return parsed;
                    // 「yyyy年MM月dd日」のような日本語形式をパース
                    const match = dateStr.match(/(\d{4})年(\d{1,2})月(\d{1,2})日/);
                    if (match) return new Date(`${match[1]}-${match[2].padStart(2,'0')}-${match[3].padStart(2,'0')}`);        // padStart(2,'0') は "5" → "05" のようにゼロ埋めする処理
                    return null;
                };

                 aiResult.interviewDate = parseDate(aiResult.interviewDate);            //AIが返した面接日の文字列を上の関数でDateオブジェクトに変換して上書き
                 
            } catch (parseError) {
                console.error("[AIレスポンスのパースに失敗]:", aiResponse.choices[0].message.content);
                // ループ内なら continue、通常のAPIなら res.status(500) などのエラーハンドリングを行う
                continue; 
            }
            
            // DBへ保存、または更新（アップデート）
            let application = await Application.findOne({
                where: { userId: userId, companyName: aiResult.companyName }            // データベースから「同じユーザー＆同じ会社名」の応募データを検索する
            });
            
            if (application) {
                await application.update({                                            //レコードがすでにある場合、更新する
                    jobTitle: aiResult.jobTitle || application.jobTitle,
                    status: aiResult.status,
                    interviewDate: aiResult.interviewDate || application.interviewDate,
                    belongings: aiResult.belongings || application.belongings,
                    companyUrl: aiResult.companyUrl || application.companyUrl,
                    deadlineDate: aiResult.deadlineDate || application.deadlineDate
                });
                summaryMessages.push(`「${aiResult.companyName}」を更新（${aiResult.status}）`);        //更新した旨をメッセージで通知
            } else {
                await Application.create({                                                //レコードがなかった場合新規作成する
                    userId: userId,
                    companyName: aiResult.companyName,
                    jobTitle: aiResult.jobTitle || "職種不明",
                    status: aiResult.status,
                    source: "Gmail自動同期", // 同期元を識別
                    interviewDate: aiResult.interviewDate,
                    belongings: aiResult.belongings,
                    companyUrl: aiResult.companyUrl,
                    deadlineDate: aiResult.deadlineDate
                });
                summaryMessages.push(`「${aiResult.companyName}」を新規登録（${aiResult.status}）`);        //新規作成完了の旨をメッセージで通知
            }
            
            // 処理が成功したメールを「既読（UNREADラベルを削除）」にして、次回二重に取り込まないようにする
            await gmail.users.messages.batchModify({
                userId: 'me',
                requestBody: { 
                ids: [msgInfo.id], // 既読にしたいメッセージIDの配列
                removeLabelIds: ['UNREAD'] // 未読ラベルを削除（既読にする）
                }
            });
        
        importedCount++;        //保存成功で+１
    }

        //同期成功時刻を記録
    await user.update({ lastGmailSync: new Date() });
        
    res.json({
        message: `Gmail同期が完了しました。${importedCount}件のメールを処理しました。`,
            importedCount,
            details: summaryMessages
        });
        
    } catch (error) {
        console.error("[Gmail同期エラー]:", error);
        res.status(500).json({ message: "Gmailからの自動取得・解析中にエラーが発生しました。" });
    }
});


// GETリクエスト：応募データの集計情報を返すエンドポイント
app.get('/api/applications/analytics/source', authenticateToken, async(req,res) => {        // authenticateToken：JWTトークンを検証するミドルウェア（ログイン済みか確認）
    try{
        const userId = req.user.userId

        //データベースから「ログイン中のユーザーの応募データ」だけをすべて取得
        const myApplications = await Application.findAll({
            where:{ userId: userId}
        });

        //媒体ごとの件数を集計する
        const sourceCounts ={};        //集計結果を入れるオブジェクト(キー:名前、値:件数)
        const statusCounts ={};

        myApplications.forEach(app => {                //応募データをforEachで一件ずつ処理して集計
            //媒体の集計
            const sourceName = app.source || "その他";
            sourceCounts[sourceName] = (sourceCounts[sourceName] || 0) + 1;

            //ステータスの集計
            const statusName = app.status || "応募中";
            statusCounts[statusName] = (statusCounts[statusName] || 0) + 1;
        });

        res.json({
            message:"データの集計に成功しました！",
            totalCount: myApplications.length,
            analytics: {
                bySource: sourceCounts,
                byStatus: statusCounts,   
            }
        });
    } catch (err){
        console.error(err);
        res.status(500).json({message:"サーバー側でエラーが発生しました。"});
    }
});




//自分の応募一覧を取得するエンドポイント
app.get('/api/applications',authenticateToken, async(req, res) => {            //authenticateTokenでログイン済みか確認
    try {
        const userId = req.user.userId;
        
        //DBから「自分のユーザーID」に一致する応募データをすべて取得する
        //登録が新しい順(idが降順:DESC)で並べ替えて取得する
        const myApplications = await Application.findAll({
            where: {userId: userId},
            order: [['id', 'DESC']]
        });
        res.json({
            message: "応募情報の一覧を取得しました",
            count: myApplications.length,
            applications: myApplications
        });
    } catch (err){
        console.error(err);
        res.status(500).json({message:"サーバー側でエラーが発生しました。"});
    }
});





//新規応募を受け付ける窓口
app.post('/api/applications',authenticateToken, async(req,res) =>{
    try{
        
        //authenticationTokenを使用してユーザーIDを呼び出す
        const userId = req.user.userId;

        //画面やAIから送られてきた応募データを取得
        const { companyName, jobTitle, source, interviewDate, belongings, companyUrl,
        ratingSalary, ratingHoliday, deadlineDate} = req.body;
        
        //必須項目のチェック
        if (!companyName || !jobTitle) {
            return res.status(400).json({message:"企業と職種が見つかりません。"});
        }

        //データベースから同じ「人・企業・職種」を探す
        const exists = await Application.findOne({
            where:{
                userId: userId,
                companyName: companyName,
                jobTitle: jobTitle
            }
        });

        //重複してたらエラーを返す
        if (exists) {
            return res.status(400).json({message: "エラー:この企業・職種はすでに応募済みです"})
        }
        //重複がなければ、データベースに新規保存(create)する
        const newApp = await Application.create({
            userId,
            companyName,
            jobTitle,
            source,
            interviewDate,
            belongings,
            companyUrl,
            ratingSalary,
            ratingHoliday,
            deadlineDate
        });
        res.status(201).json({message: "応募情報が正常に登録されました", application: newApp});
    } catch (err) {
        console.error(err);
        res.status(500).json({message: "サーバー側でエラーが発生しました。"});
    }
});




//特定の応募データを更新するエンドポイント
app.put('/api/applications/:id',authenticateToken, async(req,res) =>{
   try{
    const userId = req.user.userId;                          //ユーザーIDの取得
    const applicationId = Number(req.params.id);          // URLの ":id" 部分を数値に変換
       // リクエストボディから更新したい項目を取り出す
    const {companyName, jobTitle, status, source, interviewDate, belongings, companyUrl, ratingSalary, 
        ratingHoliday, ratingLocation, ratingWork, deadlineDate } = req.body;

    const application = await Application.findOne({            //指定されたIdかつ自分のデータを検索
        where: { id: applicationId, userId: userId}            //userIdを含むことで他人のデータを編集できないようにする
    });

    if (!application) {
        return res.status(404).json({message:"該当する情報が見つかりません"});
    }
    //送られてきたデータ(undifined以外)があれば空文字でも数値の０でもすべて更新
    await application.update({
        companyName: companyName !== undefined ? companyName : application.companyName,
            jobTitle: jobTitle !== undefined ? jobTitle : application.jobTitle,
            status: status !== undefined ? status : application.status,
            source: source !== undefined ? source : application.source,
            interviewDate: interviewDate !== undefined ? interviewDate : application.interviewDate,
            belongings: belongings !== undefined ? belongings : application.belongings,
            companyUrl: companyUrl !== undefined ? companyUrl : application.companyUrl,
            ratingSalary: ratingSalary !== undefined ? ratingSalary : application.ratingSalary,
            ratingHoliday: ratingHoliday !== undefined ? ratingHoliday : application.ratingHoliday,
            ratingLocation: ratingLocation !== undefined ? ratingLocation : application.ratingLocation,
            ratingWork: ratingWork !== undefined ? ratingWork : application.ratingWork,
            deadlineDate: deadlineDate !== undefined ? deadlineDate : application.deadlineDate
    });

        res.json({message: "応募情報を更新しました", application});
   } catch (err) {
        console.error(err);
        res.status(500).json({message: "サーバー側でエラーが発生しました。"});
   }
});





// 企業評価・比較API（給与・休日満足度でのソート一覧取得）
app.get('/api/applications/ranking', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        const { sortBy } = req.query; // 画面から送られてきたソート条件（salary または holiday）

        let orderCondition = [['id', 'DESC']]; // デフォルトは登録が新しい順
        
        if (sortBy === 'salary') {
            orderCondition = [['ratingSalary', 'DESC']]; // 給与評価が高い順
        } else if (sortBy === 'holiday') {
            orderCondition = [['ratingHoliday', 'DESC']]; // 休日評価が高い順
        }

        // ログイン中のユーザーの応募データだけを、指定された順序で取得
        const rankedApplications = await Application.findAll({
            where: { userId: userId },
            order: orderCondition
        });

        res.json({
            message: "評価順に並び替えた応募情報を取得しました",
            sortBy: sortBy || 'default',
            count: rankedApplications.length,
            applications: rankedApplications
        });
    } catch (err) {
        console.error("[ランキング取得エラー]:", err);
        res.status(500).json({ message: "サーバー側でエラーが発生しました。" });
    }
});





// 期日アラートロジック（提出期限・面接などが近いタスクの抽出）
// 選考中（不採用・内定以外）で、かつ deadlineDate が入力されているものを期限が近い順に返す
app.get('/api/applications/alerts', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;

        // 💡 期限が迫っている未完了の選考データを抽出
        const urgentApplications = await Application.findAll({
            where: {
                userId: userId,
                status: { [Op.notIn]: ['不採用', '内定'] }, // 既に終了したステータスは除外
                deadlineDate: { [Op.not]: null }            // 期限がちゃんと設定されているもの
            },
            // deadlineDate は文字列（"2026-06-01"など）でも昇順（ASC）で並べれば日付が近い順
            order: [['deadlineDate', 'ASC']] 
        });

        res.json({
            message: "期限管理対象のアラートデータを取得しました",
            count: urgentApplications.length,
            alerts: urgentApplications
        });
    } catch (err) {
        console.error("[期限アラート取得エラー]:", err);
        res.status(500).json({ message: "サーバー側でエラーが発生しました。" });
    }
});




//プロフィールのデータを更新
app.put('/api/user/update',authenticateToken, async(req,res) => {
    try {
        const userId =req.user.userId;                    // トークンから取得したログイン中のユーザーID
        const { username, email, newPassword } =req.body;        //リクエストボディから変更したい項目を取り出す

        const user = await User.findByPk(userId);            //Pkでユーザー検索
        if (!user) {
            return res.status(404).json({message:"ユーザーが見つかりませんでした。"});
        }
        //メールアドレスを変更する場合は重複チェック
        if (email && email !== user.email) {
            const exists = await User.findOne({ where: { email } });
            if (exists) {
                return res.status(400).json({message: "そのメールアドレスは既に使用されています。"});
            }
        }
        
        //更新するデータをオブジェクトにまとめる、undefined でなければ新しい値、undefined なら既存の値を保持
        const updateData = {            
            username: username !== undefined ? username : user.username,
            email: email !== undefined ? email : user.email
        };
        //新しいパスワードが入力されている場合はハッシュ化して更新
        if (newPassword && newPassword.trim() !== "") {
            updateData.password = await bcrypt.hash(newPassword, 10);
        }

        await user.update(updateData);

        res.json({ message: "アカウント情報を更新しました。"});

    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "サーバー側でエラーが発生しました。"});
    }
});




// 通知設定を保存する
app.put('/api/notifications/settings', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        const { notifyInterview, notifyDocument } = req.body;

        const user = await User.findByPk(userId);
        if (!user) {
            return res.status(404).json({ message: "ユーザーが見つかりませんでした。" });
        }

        await user.update({
            notifyInterview: notifyInterview !== undefined ? notifyInterview : user.notifyInterview,
            notifyDocument:  notifyDocument  !== undefined ? notifyDocument  : user.notifyDocument
        });

        res.json({ message: "通知設定を保存しました。" });

    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "サーバー側でエラーが発生しました。" });
    }
});




// 通知設定を取得する
app.get('/api/notifications/settings', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;

        const user = await User.findByPk(userId, {
            attributes: ['notifyInterview', 'notifyDocument']
        });
        if (!user) {
            return res.status(404).json({ message: "ユーザーが見つかりませんでした。" });
        }

        res.json({
            notifyInterview: user.notifyInterview,
            notifyDocument:  user.notifyDocument
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "サーバー側でエラーが発生しました。" });
    }
});



//指定した応募情報を削除
app.delete('/api/applications/:id', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId
        const applicationId = Number(req.params.id);  //URLの:idの部分(消したい応募ID)

        //データベースから「自分のもの」かつ「指定された応募ID」のデータを１件探す
        const application = await Application.findOne({
            where: {id: applicationId, userId: userId}
        });

        //データが見つからない場合
        if (!application) {
            return res.status(404).json({ message: "該当する応募情報が見つかりません(または削除権限がありません)"});
        }

        //データベースから完全に削除
        await application.destroy();

        res.json({
            message: "応募情報が正常に削除されました",
            applicationId: applicationId,
            companyName: application.companyName
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "サーバー側でエラーが発生しました。"});
    }
});






//アカウントを削除
app.delete('/api/user', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        const user = await User.findByPk(userId);
        if (!user) {
            return res.status(404).json({ message: "ユーザーが見つかりませんでした。" });
        }

        // 先に応募データを全削除(アカウントが消えてもアカウントに紐づく応募データだけ残ってしまうため)
        await Application.destroy({
            where: { userId: userId }
        });

        // 次にユーザー本体を削除
        await user.destroy();

        res.json({ message: "アカウントと全応募データを削除しました。" });

    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "サーバー側でエラーが発生しました。" });
    }
});


//メールを用いたリマインド機能
app.post('/api/notifications/daily-check', async (req,res) => {
    
        const secret = req.headers['x-cron-secret'];        //リクエストヘッダーから秘密鍵を取り出す
        //デバック用ログ
        // console.log('[デバック]受信したsecret:',secret);
        // console.log('[デバック]環境変数のCRON_SECRET:',process.env.CRON_SECRET);
        // console.log('[デバック]一致しているか:', secret === process.env.CRON_SECRET);

    
        if (secret !== process.env.CRON_SECRET) {                            //環境変数に保存した正しいキーと一致しない場合は不正アクセスとして拒否
            return res.status(401).json({message:'不正なアクセスです。'});
        }
        // interviewDate（日時型）の検索に使う
        try {                                                                  //今日の日付を定義00:00:00→23:59:59:999
            const todayStart = new Date();
            todayStart.setHours(0,0,0,0);
            const todayEnd = new Date();
            todayEnd.setHours(23,59,59,999);
            const todayStr = todayStart.toISOString().split('T')[0];



            // // デバッグ用（確認後に削除）
            // console.log('[デバッグ] 今日の範囲:', todayStart, '〜', todayEnd);
            // console.log('[デバッグ] 今日の文字列:', todayStr);
            // const allApps = await Application.findAll({ where: { userId: { [Op.not]: null } } });
            // console.log('[デバッグ] 全応募データ:', JSON.stringify(allApps.map(a => ({
            //     id: a.id,
            //     companyName: a.companyName,
            //     interviewDate: a.interviewDate,
            //     deadlineDate: a.deadlineDate,
            //     status: a.status
            // }))));


            //通知対象の応募データを検索する
             //条件「不採用','内定以外」かつ「今日が面接日 または 今日が提出締め切り日」
            const urgentApps = await Application.findAll({
                where:{
                    [Op.and]: [
                        {status: { [Op.notIn]: ['不採用','内定'] } },         // 選考が終わったものは除外する      
                        {
                            [Op.or] : [
                                {interviewDate: { [Op.between]: [todayStart, todayEnd] } },        // 面接日が今日の範囲内（日時型なのでbetweenで範囲検索）
                                {deadlineDate: todayStr }                                           //締切日が今日
                                ]
                        }
                        ]
                }
            });

            if (urgentApps.length === 0) {                                                //通知対象がなければここで終了
                console.log('[日時通知]本日の通知対象はありませんでした');
                return res.json({message:'本日の通知対象はありません',sentCount:0 });
            }

            //ユーザーIDごとにグループ化(同じユーザーに複数の通知がある場合、1通のメールにまとめて送るため)
            const appsByUser = {};
            urgentApps.forEach(app => {
                if(!appsByUser[app.userId]) appsByUser[app.userId] = [];
                appsByUser[app.userId].push(app);
            });

            let sentCount = 0;

            
            //ユーザーごとにメールを送信する
            for (const[userId, apps] of Object.entries(appsByUser)) {
               const user = await User.findByPk(userId, {
                    attributes: ['email', 'username', 'notifyInterview', 'notifyDocument']
                });
                if (!user) continue;                                        // ユーザーが削除済みなどの場合はスキップ

                // 通知設定がOFFのユーザーはスキップ
                const hasInterview = apps.some(a => a.interviewDate);
                const hasDeadline  = apps.some(a => a.deadlineDate === todayStr);
                
                if (hasInterview && !user.notifyInterview) continue;
                if (hasDeadline  && !user.notifyDocument)  continue;

                //件名を内容に応じて動的に生成
                const interviewCount = apps.filter(a => a.interviewDate).length;
                const deadlineCount = apps.filter(a => a.deadlineDate === todayStr).length;
                const subjectParts =[];
                if (interviewCount > 0) subjectParts.push(`面接${interviewCount}件`);
                if (deadlineCount > 0) subjectParts.push(`書類提出締め切り${deadlineCount}件`);
                const subject =
                              `【JobTracker】本日のリマインド:${subjectParts.join('・')}`;

                //メール本文のリスト部分を生成
                const itemList = apps.map(app => {
                    const lines = [`${app.companyName} (${app.jobTitle})` ];
                    if (app.interviewDate) {
                        const d = new Date(app.interviewDate);
                        const h = d.getHours();
                        const m = String(d.getMinutes()).padStart(2,'0');
                        lines.push(`面接時刻:${h}:${m}`);
                    }
                    if (app.deadlineDate === todayStr) {
                        lines.push(`提出期限:本日`);
                    }
                    if (app.belongings) {
                        lines.push(`持ち物:${app.belongings}`);
                    }
                    if (app.companyUrl) {
                        lines.push (`企業URL: ${app.companyUrl}`);
                    }
                    return lines.join('\n');
                }).join('\n\n');                                    // 応募1件につき複数行を作り、"\n\n"で区切って並べる


                // Nodemailerでメールを送信する
                await transporter.sendMail({
                    from: `"JobTracker" <${process.env.GMAIL_NOTIFY_USER}>`,
                    to: user.email,
                    subject: subject,
                    text:
                        `${user.username || 'ユーザー'}さん、おはようございます。
                        
                        本日の就活スケジュールをお知らせします。
                        ${itemList}
                        
                        -----------------------------------
                        頑張ってください！
                        JobTracker より`
                });

                console.log(`[日時通知] ${user.email}にメールを送信しました。`);
                sentCount++;
            }

            res.json({
                message: `${sentCount}名にリマインドメールを送信しました。`,
                sentCount
            });

        } catch (error) {
            console.error(`[日時通知エラー]:`,error);
            res.status(500).json({message:'メール送信中にエラーが発生しました。'});
        }
});
    
            
                    
            

// サーバーを起動する
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`サーバーが立ち上がりました！ポート ${PORT} で待機中です。`);
});

// テストコードから app を読み込めるようにエクスポート
module.exports = app;
