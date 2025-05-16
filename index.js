// index.js
require('dotenv').config();

const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// PostgreSQL Pool 설정
const pool = new Pool({
  host: process.env.PGHOST,
  user: process.env.PGUSER,
  password: process.env.PGPASSWORD,
  database: process.env.PGDATABASE,
  port: process.env.PGPORT,
  ssl: {
    rejectUnauthorized: false
  }
});

// 기본 페이지: 로그인 페이지로 리다이렉트
app.get('/', (req, res) => {
  res.redirect('/login.html');
});

// 회원가입 API
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: '아이디와 비밀번호를 모두 입력해주세요.' });
    }
    const hashed = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO users (username, password) VALUES ($1, $2)',
      [username, hashed]
    );
    res.status(201).json({ message: '회원가입이 완료되었습니다.' });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: '이미 사용 중인 아이디입니다.' });
    }
    console.error(err);
    res.status(500).json({ error: '서버 에러가 발생했습니다.' });
  }
});

// 로그인 API
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: '아이디와 비밀번호를 모두 입력해주세요.' });
    }
    const result = await pool.query(
      'SELECT id, password FROM users WHERE username = $1',
      [username]
    );
    const user = result.rows[0];
    if (!user) {
      return res.status(401).json({ error: '로그인 정보가 일치하지 않습니다.' });
    }
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ error: '로그인 정보가 일치하지 않습니다.' });
    }
    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: '서버 에러가 발생했습니다.' });
  }
});

// 인증 미들웨어
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.redirect('/login.html');
  jwt.verify(token, process.env.JWT_SECRET, (err, payload) => {
    if (err) return res.redirect('/login.html');
    req.userId = payload.userId;
    next();
  });
}

// 포인트 조회 API
app.get('/points', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT points FROM users WHERE id = $1',
      [req.userId]
    );
    res.json({ points: result.rows[0].points });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: '서버 에러가 발생했습니다.' });
  }
});

// 포인트 변경 API
app.post('/points', authenticateToken, async (req, res) => {
  try {
    const { amount } = req.body;
    if (typeof amount !== 'number') {
      return res.status(400).json({ error: 'amount는 숫자여야 합니다.' });
    }
    await pool.query(
      'UPDATE users SET points = points + $1 WHERE id = $2',
      [amount, req.userId]
    );
    res.json({ message: '포인트가 업데이트되었습니다.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: '서버 에러가 발생했습니다.' });
  }
});

// 서버 시작
app.listen(port, () => {
  console.log(`🚀 서버 실행 중: http://localhost:${port}`);
});
