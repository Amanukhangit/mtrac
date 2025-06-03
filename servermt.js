const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public')); // Serve frontend files

// Initialize SQLite Database
const db = new sqlite3.Database('./medicine_tracker.db');

// Create tables if they don't exist
db.serialize(() => {
  // Users table
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    email TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Medicines table
  db.run(`CREATE TABLE IF NOT EXISTS medicines (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    dose TEXT NOT NULL,
    time TEXT NOT NULL,
    frequency TEXT DEFAULT 'daily',
    notes TEXT,
    active BOOLEAN DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
  )`);

  // Medicine history table
  db.run(`CREATE TABLE IF NOT EXISTS medicine_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    medicine_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    taken_at DATETIME NOT NULL,
    status TEXT DEFAULT 'taken', -- taken, missed, skipped
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (medicine_id) REFERENCES medicines (id),
    FOREIGN KEY (user_id) REFERENCES users (id)
  )`);

  // Reminders table
  db.run(`CREATE TABLE IF NOT EXISTS reminders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    medicine_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    reminder_time TIME NOT NULL,
    enabled BOOLEAN DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (medicine_id) REFERENCES medicines (id),
    FOREIGN KEY (user_id) REFERENCES users (id)
  )`);
});

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.userId = decoded.userId;
    next();
  });
};

// AUTH ROUTES

// Register user
app.post('/api/auth/register', async (req, res) => {
  const { username, password, email } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    
    db.run(
      'INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
      [username, hashedPassword, email],
      function(err) {
        if (err) {
          if (err.code === 'SQLITE_CONSTRAINT') {
            return res.status(400).json({ error: 'Username already exists' });
          }
          return res.status(500).json({ error: 'Database error' });
        }
        
        const token = jwt.sign({ userId: this.lastID }, JWT_SECRET, { expiresIn: '24h' });
        res.status(201).json({
          message: 'User created successfully',
          token,
          user: { id: this.lastID, username, email }
        });
      }
    );
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Login user
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  db.get(
    'SELECT * FROM users WHERE username = ?',
    [username],
    async (err, user) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }

      if (!user) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      try {
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
          return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '24h' });
        res.json({
          message: 'Login successful',
          token,
          user: { id: user.id, username: user.username, email: user.email }
        });
      } catch (error) {
        res.status(500).json({ error: 'Server error' });
      }
    }
  );
});

// MEDICINE ROUTES

// Get all medicines for user
app.get('/api/medicines', verifyToken, (req, res) => {
  db.all(
    'SELECT * FROM medicines WHERE user_id = ? AND active = 1 ORDER BY time',
    [req.userId],
    (err, medicines) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      res.json(medicines);
    }
  );
});

// Add new medicine
app.post('/api/medicines', verifyToken, (req, res) => {
  const { name, dose, time, frequency, notes } = req.body;

  if (!name || !dose || !time) {
    return res.status(400).json({ error: 'Name, dose, and time are required' });
  }

  db.run(
    'INSERT INTO medicines (user_id, name, dose, time, frequency, notes) VALUES (?, ?, ?, ?, ?, ?)',
    [req.userId, name, dose, time, frequency || 'daily', notes],
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      
      res.status(201).json({
        id: this.lastID,
        user_id: req.userId,
        name,
        dose,
        time,
        frequency: frequency || 'daily',
        notes,
        active: 1
      });
    }
  );
});

// Update medicine
app.put('/api/medicines/:id', verifyToken, (req, res) => {
  const { name, dose, time, frequency, notes } = req.body;
  const medicineId = req.params.id;

  db.run(
    'UPDATE medicines SET name = ?, dose = ?, time = ?, frequency = ?, notes = ? WHERE id = ? AND user_id = ?',
    [name, dose, time, frequency, notes, medicineId, req.userId],
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      
      if (this.changes === 0) {
        return res.status(404).json({ error: 'Medicine not found' });
      }
      
      res.json({ message: 'Medicine updated successfully' });
    }
  );
});

// Delete medicine (soft delete)
app.delete('/api/medicines/:id', verifyToken, (req, res) => {
  const medicineId = req.params.id;

  db.run(
    'UPDATE medicines SET active = 0 WHERE id = ? AND user_id = ?',
    [medicineId, req.userId],
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      
      if (this.changes === 0) {
        return res.status(404).json({ error: 'Medicine not found' });
      }
      
      res.json({ message: 'Medicine deleted successfully' });
    }
  );
});

// MEDICINE HISTORY ROUTES

// Record medicine intake
app.post('/api/medicines/:id/record', verifyToken, (req, res) => {
  const medicineId = req.params.id;
  const { status, notes, taken_at } = req.body;

  const takenAt = taken_at || new Date().toISOString();

  db.run(
    'INSERT INTO medicine_history (medicine_id, user_id, taken_at, status, notes) VALUES (?, ?, ?, ?, ?)',
    [medicineId, req.userId, takenAt, status || 'taken', notes],
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      
      res.status(201).json({
        id: this.lastID,
        medicine_id: medicineId,
        user_id: req.userId,
        taken_at: takenAt,
        status: status || 'taken',
        notes
      });
    }
  );
});

// Get medicine history
app.get('/api/history', verifyToken, (req, res) => {
  const { date_from, date_to, medicine_id } = req.query;

  let query = `
    SELECT mh.*, m.name as medicine_name, m.dose 
    FROM medicine_history mh 
    JOIN medicines m ON mh.medicine_id = m.id 
    WHERE mh.user_id = ?
  `;
  let params = [req.userId];

  if (date_from) {
    query += ' AND DATE(mh.taken_at) >= ?';
    params.push(date_from);
  }

  if (date_to) {
    query += ' AND DATE(mh.taken_at) <= ?';
    params.push(date_to);
  }

  if (medicine_id) {
    query += ' AND mh.medicine_id = ?';
    params.push(medicine_id);
  }

  query += ' ORDER BY mh.taken_at DESC';

  db.all(query, params, (err, history) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(history);
  });
});

// Get statistics
app.get('/api/stats', verifyToken, (req, res) => {
  const queries = {
    totalMedicines: 'SELECT COUNT(*) as count FROM medicines WHERE user_id = ? AND active = 1',
    totalDosesTaken: 'SELECT COUNT(*) as count FROM medicine_history WHERE user_id = ? AND status = "taken"',
    totalDosesMissed: 'SELECT COUNT(*) as count FROM medicine_history WHERE user_id = ? AND status = "missed"',
    adherenceRate: `
      SELECT 
        ROUND(
          (COUNT(CASE WHEN status = 'taken' THEN 1 END) * 100.0 / COUNT(*)), 2
        ) as rate 
      FROM medicine_history 
      WHERE user_id = ? AND DATE(taken_at) >= DATE('now', '-30 days')
    `
  };

  const stats = {};
  let completed = 0;

  Object.keys(queries).forEach(key => {
    db.get(queries[key], [req.userId], (err, result) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      
      stats[key] = result.count !== undefined ? result.count : result.rate || 0;
      completed++;
      
      if (completed === Object.keys(queries).length) {
        res.json(stats);
      }
    });
  });
});

// Get daily medicine schedule
app.get('/api/schedule/today', verifyToken, (req, res) => {
  const today = new Date().toISOString().split('T')[0];
  
  const query = `
    SELECT 
      m.*,
      CASE 
        WHEN mh.id IS NOT NULL THEN 1 
        ELSE 0 
      END as taken_today
    FROM medicines m
    LEFT JOIN medicine_history mh ON m.id = mh.medicine_id 
      AND DATE(mh.taken_at) = ? 
      AND mh.status = 'taken'
    WHERE m.user_id = ? AND m.active = 1
    ORDER BY m.time
  `;

  db.all(query, [today, req.userId], (err, schedule) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(schedule);
  });
});

// Serve frontend
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Start server
app.listen(PORT, () => {
  console.log(Server running on http://localhost:${PORT});
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\nShutting down gracefully...');
  db.close((err) => {
    if (err) {
      console.error(err.message);
    } else {
      console.log('Database connection closed.');
    }
    process.exit(0);
  });
});