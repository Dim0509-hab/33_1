// backend/server.js
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const cors = require('cors');
const { Server } = require('socket.io');
const http = require('http');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const SECRET = 'my_secret_key';

// ======= Настройка базы данных =======
const db = new sqlite3.Database('./database.sqlite');
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password TEXT,
    nickname TEXT UNIQUE,
    avatar TEXT,
    show_email INTEGER DEFAULT 1,
    is_verified INTEGER DEFAULT 0
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER,
    receiver_id INTEGER,
    text TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
});

// ======= Хранилище аватаров =======
const storage = multer.diskStorage({
  destination: './uploads',
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage });

// ======= Регистрация =======
app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  const hash = await bcrypt.hash(password, 10);
  try {
    db.run(`INSERT INTO users (email, password) VALUES (?, ?)`, [email, hash], function (err) {
      if (err) return res.status(400).json({ error: 'Email уже используется' });

      // Генерация ссылки подтверждения
      const token = jwt.sign({ email }, SECRET, { expiresIn: '1d' });
      const link = `http://localhost:3000/verify?token=${token}`;

      // Имитация отправки письма
      console.log(`📧 Ссылка для подтверждения регистрации: ${link}`);

      res.json({ message: 'Пользователь зарегистрирован. Ссылка подтверждения в консоли сервера.' });
    });
  } catch {
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// ======= Подтверждение почты =======
app.get('/verify', (req, res) => {
  try {
    const { token } = req.query;
    const { email } = jwt.verify(token, SECRET);
    db.run(`UPDATE users SET is_verified = 1 WHERE email = ?`, [email], function () {
      res.send('✅ Email подтверждён. Теперь вы можете войти в систему.');
    });
  } catch {
    res.status(400).send('❌ Неверная или устаревшая ссылка.');
  }
});

// ======= Вход =======
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, user) => {
    if (!user) return res.status(400).json({ error: 'Пользователь не найден' });
    if (!user.is_verified) return res.status(400).json({ error: 'Email не подтверждён' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: 'Неверный пароль' });

    const token = jwt.sign({ id: user.id }, SECRET, { expiresIn: '1d' });
    res.json({ token, userId: user.id });
  });
});

// ======= Профиль =======
app.get('/profile', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  try {
    const { id } = jwt.verify(token, SECRET);
    db.get(`SELECT email, nickname, avatar, show_email FROM users WHERE id = ?`, [id], (err, user) => {
      res.json(user);
    });
  } catch {
    res.status(401).json({ error: 'Не авторизован' });
  }
});

// ======= Список чатов пользователя =======
app.get('/chats', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  try {
    const { id } = jwt.verify(token, SECRET);

    db.all(`
      SELECT u.id as user_id, u.nickname, u.avatar, u.email, u.show_email,
             m.text as last_message, m.created_at
      FROM users u
      JOIN (
        SELECT
          CASE 
            WHEN sender_id = ? THEN receiver_id
            ELSE sender_id
          END as other_id,
          MAX(created_at) as last_time
        FROM messages
        WHERE sender_id = ? OR receiver_id = ?
        GROUP BY other_id
      ) last_chats
      ON u.id = last_chats.other_id
      LEFT JOIN messages m
      ON (
        (m.sender_id = ? AND m.receiver_id = u.id)
        OR (m.sender_id = u.id AND m.receiver_id = ?)
      ) AND m.created_at = last_chats.last_time
      ORDER BY m.created_at DESC
    `, [id, id, id, id, id], (err, rows) => {
      if (err) return res.status(500).json({ error: 'Ошибка сервера' });
      res.json(rows);
    });

  } catch {
    res.status(401).json({ error: 'Не авторизован' });
  }
});


app.put('/profile', upload.single('avatar'), (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  try {
    const { id } = jwt.verify(token, SECRET);
    const { nickname, show_email } = req.body;
    const avatar = req.file ? `/uploads/${req.file.filename}` : null;

    // Проверка уникальности nickname
    db.get(`SELECT id FROM users WHERE nickname = ? AND id != ?`, [nickname, id], (err, row) => {
      if (row) return res.status(400).json({ error: 'Никнейм уже занят' });

      db.run(
        `UPDATE users SET nickname = ?, show_email = ?, avatar = COALESCE(?, avatar, '/uploads/default.png') WHERE id = ?`,
        [nickname, show_email, avatar, id],
        () => res.json({ message: 'Профиль обновлён' })
      );
    });

  } catch {
    res.status(401).json({ error: 'Не авторизован' });
  }
});


// ======= Получение сообщений =======
app.get('/messages/:withUserId', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  try {
    const { id } = jwt.verify(token, SECRET);
    const otherId = parseInt(req.params.withUserId);
    db.all(
      `SELECT * FROM messages 
       WHERE (sender_id = ? AND receiver_id = ?) 
       OR (sender_id = ? AND receiver_id = ?) 
       ORDER BY created_at ASC`,
      [id, otherId, otherId, id],
      (err, rows) => res.json(rows)
    );
  } catch {
    res.status(401).json({ error: 'Не авторизован' });
  }
});

// ======= WebSocket для чата =======
const onlineUsers = {};

io.on('connection', (socket) => {
  socket.on('join', (userId) => {
    onlineUsers[userId] = socket.id;
  });

  socket.on('send_message', (data) => {
    const { sender_id, receiver_id, text } = data;
    db.run(`INSERT INTO messages (sender_id, receiver_id, text) VALUES (?, ?, ?)`,
      [sender_id, receiver_id, text]);

    if (onlineUsers[receiver_id]) {
      io.to(onlineUsers[receiver_id]).emit('receive_message', data);
    }
  });

  socket.on('disconnect', () => {
    for (let uid in onlineUsers) {
      if (onlineUsers[uid] === socket.id) delete onlineUsers[uid];
    }
  });
});

server.listen(3000, () => console.log('✅ Backend запущен на порту 3000'));
