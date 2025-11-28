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
  dateOfBirth: String,      // "YYYY-MM-DD"
  gender: String,           // "male", "female", "nonbinary", "unspecified"
  avatarType: String,       // for now same as gender
  company: String,
  university: String,
  profession: String,       // Student, Working professional, Business, etc.

  profileCompleted: { type: Boolean, default: false }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

// ---------- Auth routes ----------

// Signup
app.post('/api/signup', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ success: false, message: 'Missing username or password' });
  }

  try {
    const existing = await User.findOne({ username });
    if (existing) {
      return res.status(409).json({ success: false, message: 'Username already exists' });
    }

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
  if (!username || !password) {
    return res.status(400).json({ success: false, message: 'Missing username or password' });
  }

  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res.json({ success: false, message: 'Invalid username or password' });
    }

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) {
      return res.json({ success: false, message: 'Invalid username or password' });
    }

    return res.json({ success: true });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ---------- Profile routes ----------

// Get profile
app.get('/api/profile', async (req, res) => {
  const { username } = req.query;
  if (!username) {
    return res.status(400).json({ success: false, message: 'Missing username.' });
  }

  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found.' });
    }

    return res.json({
      success: true,
      profile: {
        email: user.username,
        displayName: user.displayName || '',
        fullName: user.fullName || '',
        dateOfBirth: user.dateOfBirth || '',
        gender: user.gender || 'unspecified',
        avatarType: user.avatarType || '',
        company: user.company || '',
        university: user.university || '',
        profession: user.profession || '',
        profileCompleted: !!user.profileCompleted
      }
    });
  } catch (err) {
    console.error('Profile fetch error:', err);
    return res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// Save / update profile
app.post('/api/profile', async (req, res) => {
  const {
    username,
    displayName,
    fullName,
    dateOfBirth,
    gender,
    avatarType,
    company,
    university,
    profession
  } = req.body;

  if (!username) {
    return res.status(400).json({ success: false, message: 'Missing username.' });
  }

  try {
    const user = await User.findOneAndUpdate(
      { username },
      {
        displayName,
        fullName,
        dateOfBirth,
        gender,
        avatarType,
        company,
        university,
        profession,
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

// Change password
app.post('/api/change-password', async (req, res) => {
  const { username, currentPassword, newPassword } = req.body;

  if (!username || !currentPassword || !newPassword) {
    return res.status(400).json({ success: false, message: 'Missing fields.' });
  }

  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found.' });
    }

    const ok = await bcrypt.compare(currentPassword, user.passwordHash);
    if (!ok) {
      return res.status(400).json({ success: false, message: 'Current password is incorrect.' });
    }

    const newHash = await bcrypt.hash(newPassword, 10);
    user.passwordHash = newHash;
    await user.save();

    return res.json({ success: true });
  } catch (err) {
    console.error('Change password error:', err);
    return res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// ---------- Frontend ----------

app.get('/', (req, res) =>
  res.sendFile(path.join(__dirname, 'public', 'index.html'))
);

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
