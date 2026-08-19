const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const refreshTokenSchema = new mongoose.Schema({
  tokenHash: { type: String, required: true },
  sessionVersion: { type: Number, default: 0 },
  createdAt: { type: Date, required: true },
  expiresAt: { type: Date, required: true },
}, { _id: false });

const registrarSchema = new mongoose.Schema({
  registrarId: {
    type: String,
    required: true,
    unique: true
  },
  name: {
    type: String,
    required: true
  },
  email: {
    type: String,
    required: true,
    unique: true
  },
  role: {
    type: String,
    default: 'Registrar Staff'
  },
  password: {
    type: String,
    required: true
  },
  profilePic: {
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
registrarSchema.pre('save', async function() {
  if (!this.isModified('password')) return;
  this.password = await bcrypt.hash(this.password, 10);
  if (!this.isNew) {
    this.refreshTokens = [];
    this.sessionVersion = Number(this.sessionVersion || 0) + 1;
    this.tokensValidAfter = new Date();
  }
});

// Method to compare password
registrarSchema.methods.comparePassword = async function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

module.exports = mongoose.model('Registrar', registrarSchema);
