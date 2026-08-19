const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const refreshTokenSchema = new mongoose.Schema({
  tokenHash: { type: String, required: true },
  sessionVersion: { type: Number, default: 0 },
  createdAt: { type: Date, required: true },
  expiresAt: { type: Date, required: true },
}, { _id: false });

const alumniSchema = new mongoose.Schema({
  firstName: {
    type: String,
    required: true
  },
  lastName: {
    type: String,
    required: true
  },
  email: {
    type: String,
    required: true,
    unique: true
  },
  password: {
    type: String,
    required: function() {
      return !this.passwordHash;
    }
  },
  passwordHash: {
    type: String,
    required: function() {
      return !this.password;
    }
  },
  role: {
    type: String,
    default: 'alumni',
    enum: ['student', 'alumni']
  },
  studentId: {
    type: String,
    unique: true
  },
  course: {
    type: String,
    default: ''
  },
  yearLevel: {
    type: String,
    default: ''
  },
  profilePic: {
    type: String,
    default: ''
  },
  phoneNumber: {
    type: String,
    default: ''
  },
  status: {
    type: String,
    enum: ['Active', 'Inactive'],
    default: 'Inactive'
  },
  refreshTokens: {
    type: [refreshTokenSchema],
    default: []
  },
  sessionVersion: {
    type: Number,
    default: 0
  },
  tokensValidAfter: Date
}, { timestamps: true });

// Hash password before saving
alumniSchema.pre('save', async function() {
  if (!this.isModified('password')) return;
  this.password = await bcrypt.hash(this.password, 10);
  this.passwordHash = undefined;
  if (!this.isNew) {
    this.refreshTokens = [];
    this.sessionVersion = Number(this.sessionVersion || 0) + 1;
    this.tokensValidAfter = new Date();
  }
});

// Method to compare password
alumniSchema.methods.comparePassword = async function(candidatePassword) {
  const hash = this.passwordHash || this.password;
  if (!hash) return false;
  return bcrypt.compare(candidatePassword, hash);
};

module.exports = mongoose.model('Alumni', alumniSchema, 'alumni');
