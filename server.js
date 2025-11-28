const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// MongoDB connection
const MONGODB_URI = process.env.MONGODB_URI;
if (!MONGODB_URI) {
  console.error('MONGODB_URI not set. Set it in environment variables.');
  process.exit(1);
}

mongoose.connect(MONGODB_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => {
    console.error('MongoDB connection error:', err);
    process.exit(1);
  });

// User schema and model
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true },   // email used for login
  passwordHash: String,

  // profile fields
  displayName: String,
  fullName: String,
  dateOfBirth: String,      // keep as string "YYYY-MM-DD" from <input type="date">
  gender: String,           // "male", "female", "nonbinary", "unspecified"
  avatarType: String,       // same as gender for now
  company: String,
  university: String,
  profession: String,       // Student, Working professional, etc.

  profileCompleted: { type: Boolean, default: false }
}, { timestamps: true });



const User = mongoose.model('User', userSchema);

// Routes

// Signup
app.post('/api/signup', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ success: false, message: 'Missing username or password' });

  try {
    const existing = await User.findOne({ username });
    if (existing) return res.status(409).json({ success: false, message: 'Username already exists' });

    const passwordHash = await bcrypt.hash(password, 10);
    const user = new User({ username, passwordHash });
    await user.save();

    return res.status(201).json({ success: true });
  } catch (err) {
    console.error('Signup error:', err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ success: false, message: 'Missing username or password' });

  try {
    const user = await User.findOne({ username });
    if (!user) return res.json({ success: false, message: 'Invalid username or password' });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.json({ success: false, message: 'Invalid username or password' });

    return res.json({ success: true });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Save / update profile
app.post('/api/profile', async (req, res) => {
  const { username, fullName, country, role, interests } = req.body;

  if (!username) {
    return res.status(400).json({ success: false, message: 'Missing username (email).' });
  }

  try {
    const user = await User.findOneAndUpdate(
      { username },
      {
        fullName,
        country,
        currentRole: role,
        interests,
        profileCompleted: true
      },
      { new: true }
    );

    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found.' });
    }

    return res.json({ success: true });
  } catch (err) {
    console.error('Profile update error:', err);
    return res.status(500).json({ success: false, message: 'Server error.' });
  }
});


// Serve frontend
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
