const express = require('express');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'kyungdong-compliment-2026-secret';
const SITE_DOMAIN = 'kyungdongcompliment2026.com';

const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// ==========================================
// 1. 욕설 및 나쁜 말 필터 (서버 2차 검증)
// ==========================================
const BAD_WORDS = [
  '시발', '씨발', 'ㅅㅂ', 'ㅆㅂ', '병신', 'ㅂㅅ', '빙신', '지랄', 'ㅈㄹ',
  '개새', '새끼', '개같', '미친', 'ㅁㅊ', '꺼져', '닥쳐', '죽어', '뒤져',
  '바보', '멍청', '등신', '찐따', '찌질', '왕따', '한심', '짜증', '혐오',
  '돼지', '못생', '냄새', '꼴값', '썅', '존나', 'ㅈㄴ', '개빡', '빡치',
  '엿먹', '재수없', '극혐', '느금', '니미', '엠창', '호구', '쪼다'
];

function containsBadWord(text) {
  if (!text) return false;
  const lower = text.toLowerCase();
  const normalized = lower.replace(/[\s0-9!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~`]/g, '');
  return BAD_WORDS.some(word => lower.includes(word) || normalized.includes(word));
}

// ==========================================
// 2. 영구 저장소(data/db.json) 초기화 및 관리
// ==========================================
function initDB() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
  if (!fs.existsSync(DB_FILE)) {
    const initialData = {
      users: [],
      posts: [
        {
          id: 1,
          fromUserId: 'demo_1',
          fromGrade: '4', fromClass: '2', fromName: '김하늘',
          toGrade: '4', toClass: '2', toName: '박준서',
          category: '도움의 손길',
          content: '오늘 체육 시간에 넘어졌을 때 준서가 바로 달려와서 보건실까지 같이 가주었어. 정말 고마워!',
          likedUserIds: ['demo_2', 'demo_3', 'demo_4'],
          createdAt: '2026-05-10 10:20'
        },
        {
          id: 2,
          fromUserId: 'demo_2',
          fromGrade: '5', fromClass: '3', fromName: '최민지',
          toGrade: '5', toClass: '3', toName: '정우진',
          category: '성실과 노력',
          content: '우진이는 매일 아침 일찍 와서 교실 창문을 열고 칠판도 깨끗이 지워 놓아. 묵묵히 우리 반을 위해 노력하는 모습이 최고야!',
          likedUserIds: ['demo_1', 'demo_3', 'demo_4', 'demo_5'],
          createdAt: '2026-05-11 08:40'
        }
      ]
    };
    fs.writeFileSync(DB_FILE, JSON.stringify(initialData, null, 2), 'utf8');
  }
}

function readDB() {
  return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
}

function writeDB(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2), 'utf8');
}

initDB();

// ==========================================
// 3. 인증 미들웨어
// ==========================================
function authenticate(req, res, next) {
  const token = req.cookies.token;
  if (!token) {
    return res.status(401).json({ error: '로그인이 필요합니다.' });
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ error: '로그인이 만료되었습니다. 다시 로그인해 주세요.' });
  }
}

function formatNow() {
  const now = new Date();
  return `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')} ${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}`;
}

// ==========================================
// 4. 회원가입 / 로그인 / 내 정보 API
// ==========================================
app.post('/api/auth/register', (req, res) => {
  const { username, password, name, grade, classNum } = req.body;

  if (!username || !password || !name || !grade || !classNum) {
    return res.status(400).json({ error: '모든 칸을 입력해 주세요.' });
  }
  if (username.trim().length < 3) {
    return res.status(400).json({ error: '아이디는 3자 이상으로 만들어 주세요.' });
  }
  if (password.length < 4) {
    return res.status(400).json({ error: '비밀번호는 4자 이상으로 만들어 주세요.' });
  }
  if (containsBadWord(username) || containsBadWord(name)) {
    return res.status(400).json({ error: '아이디나 이름에 나쁜 말을 사용할 수 없습니다.' });
  }

  const db = readDB();
  const exists = db.users.find(u => u.username === username.trim());
  if (exists) {
    return res.status(409).json({ error: '이미 사용 중인 아이디입니다. 다른 아이디를 입력해 주세요.' });
  }

  const newUser = {
    id: 'user_' + Date.now(),
    username: username.trim(),
    passwordHash: bcrypt.hashSync(password, 10),
    name: name.trim(),
    grade: String(grade),
    classNum: String(classNum),
    createdAt: formatNow()
  };

  db.users.push(newUser);
  writeDB(db);

  const token = jwt.sign(
    { id: newUser.id, username: newUser.username, name: newUser.name, grade: newUser.grade, classNum: newUser.classNum },
    JWT_SECRET,
    { expiresIn: '7d' }
  );

  res.cookie('token', token, { httpOnly: true, sameSite: 'lax', maxAge: 7 * 24 * 60 * 60 * 1000 });
  res.json({
    message: '회원가입이 완료되었습니다!',
    user: { id: newUser.id, username: newUser.username, name: newUser.name, grade: newUser.grade, classNum: newUser.classNum }
  });
});

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  const db = readDB();
  const user = db.users.find(u => u.username === (username || '').trim());

  if (!user || !bcrypt.compareSync(password || '', user.passwordHash)) {
    return res.status(401).json({ error: '아이디 또는 비밀번호가 맞지 않습니다.' });
  }

  const token = jwt.sign(
    { id: user.id, username: user.username, name: user.name, grade: user.grade, classNum: user.classNum },
    JWT_SECRET,
    { expiresIn: '7d' }
  );

  res.cookie('token', token, { httpOnly: true, sameSite: 'lax', maxAge: 7 * 24 * 60 * 60 * 1000 });
  res.json({
    user: { id: user.id, username: user.username, name: user.name, grade: user.grade, classNum: user.classNum }
  });
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ ok: true });
});

app.get('/api/auth/me', (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.json({ user: null });
  try {
    const user = jwt.verify(token, JWT_SECRET);
    res.json({ user });
  } catch {
    res.json({ user: null });
  }
});

// ==========================================
// 5. 칭찬 게시판 & 공감 API
// ==========================================
app.get('/api/posts', (req, res) => {
  const db = readDB();
  let currentUserId = null;
  if (req.cookies.token) {
    try {
      currentUserId = jwt.verify(req.cookies.token, JWT_SECRET).id;
    } catch {}
  }

  const posts = db.posts.map(p => ({
    id: p.id,
    fromGrade: p.fromGrade,
    fromClass: p.fromClass,
    fromName: p.fromName,
    toGrade: p.toGrade,
    toClass: p.toClass,
    toName: p.toName,
    category: p.category,
    content: p.content,
    likes: p.likedUserIds.length,
    likedByMe: currentUserId ? p.likedUserIds.includes(currentUserId) : false,
    createdAt: p.createdAt
  }));

  res.json({ posts });
});

app.post('/api/posts', authenticate, (req, res) => {
  const { toGrade, toClass, toName, category, content } = req.body;

  if (!toGrade || !toClass || !toName || !category || !content) {
    return res.status(400).json({ error: '칭찬받을 친구 정보와 내용을 모두 입력해 주세요.' });
  }

  if (containsBadWord(toName) || containsBadWord(content)) {
    return res.status(400).json({ error: '욕설이나 나쁜 말은 작성할 수 없습니다. 고운 말을 사용해 주세요!' });
  }

  if (content.trim().length < 10) {
    return res.status(400).json({ error: '칭찬 내용은 10자 이상 정성껏 적어주세요!' });
  }

  if (
    String(toGrade) === req.user.grade &&
    String(toClass) === req.user.classNum &&
    toName.trim() === req.user.name
  ) {
    return res.status(400).json({ error: '다른 멋진 친구를 칭찬해 주세요!' });
  }

  const db = readDB();
  const newPost = {
    id: Date.now(),
    fromUserId: req.user.id,
    fromGrade: req.user.grade,
    fromClass: req.user.classNum,
    fromName: req.user.name,
    toGrade: String(toGrade),
    toClass: String(toClass),
    toName: toName.trim(),
    category,
    content: content.trim(),
    likedUserIds: [],
    createdAt: formatNow()
  };

  db.posts.unshift(newPost);
  writeDB(db);

  res.status(201).json({ message: '칭찬 게시판에 공유되었습니다!', post: newPost });
});

app.post('/api/posts/:id/like', authenticate, (req, res) => {
  const postId = Number(req.params.id);
  const db = readDB();
  const post = db.posts.find(p => p.id === postId);

  if (!post) {
    return res.status(404).json({ error: '게시글을 찾을 수 없습니다.' });
  }

  const idx = post.likedUserIds.indexOf(req.user.id);
  if (idx === -1) {
    post.likedUserIds.push(req.user.id);
  } else {
    post.likedUserIds.splice(idx, 1);
  }

  writeDB(db);
  res.json({ likes: post.likedUserIds.length, likedByMe: idx === -1 });
});

// ==========================================
// 6. 칭찬상 TOP 5 선정 API
// ==========================================
app.get('/api/awards/top5', (req, res) => {
  const db = readDB();
  const senderMap = {};

  db.posts.forEach(p => {
    const key = p.fromUserId || `${p.fromGrade}-${p.fromClass}-${p.fromName}`;
    if (!senderMap[key]) {
      senderMap[key] = {
        grade: p.fromGrade,
        classNum: p.fromClass,
        name: p.fromName,
        count: 0,
        totalLength: 0,
        totalLikes: 0,
        recipients: new Set(),
        score: 0
      };
    }

    const s = senderMap[key];
    const len = p.content.trim().length;
    const likes = p.likedUserIds.length;
    const recipientKey = `${p.toGrade}-${p.toClass}-${p.toName}`;
    const isNewRecipient = !s.recipients.has(recipientKey);

    s.count += 1;
    s.totalLength += len;
    s.totalLikes += likes;
    s.recipients.add(recipientKey);

    const lengthBonus = Math.min(20, Math.floor(len / 5));
    const diversityBonus = isNewRecipient ? 5 : 0;
    const likeBonus = likes * 2;

    s.score += (10 + lengthBonus + diversityBonus + likeBonus);
  });

  const top5 = Object.values(senderMap)
    .map(s => ({
      grade: s.grade,
      classNum: s.classNum,
      name: s.name,
      count: s.count,
      recipientCount: s.recipients.size,
      totalLength: s.totalLength,
      totalLikes: s.totalLikes,
      score: s.score
    }))
    .sort((a, b) => b.score - a.score || b.totalLength - a.totalLength)
    .slice(0, 5);

  res.json({ top5, domain: SITE_DOMAIN });
});

app.listen(PORT, () => {
  console.log(`🏫 경동초등학교 칭찬 우체통 서버가 실행 중입니다!`);
  console.log(`🌐 로컬 접속: http://localhost:${PORT}`);
  console.log(`🔗 연결 예정 도메인: https://${SITE_DOMAIN}`);
});