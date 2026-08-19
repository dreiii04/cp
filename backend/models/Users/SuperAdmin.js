const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const refreshTokenSchema = new mongoose.Schema({
  tokenHash: { type: String, required: true },
  sessionVersion: { type: Number, default: 0 },
  createdAt: { type: Date, required: true },
  expiresAt: { type: Date, required: true },
}, { _id: false });

const superAdminSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true
  },
  password: {
    type: String,
    required: true
  },
  role: {
    type: String,
    default: 'super admin'
  },
  name: {
    type: String,
    default: 'Super Admin'
  },
  profilePic: {
    type: String,
    default: ''
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
superAdminSchema.pre('save', async function() {
  if (!this.isModified('password')) return;
  this.password = await bcrypt.hash(this.password, 10);
  if (!this.isNew) {
    this.refreshTokens = [];
    this.sessionVersion = Number(this.sessionVersion || 0) + 1;
    this.tokensValidAfter = new Date();
  }
});

// Method to compare password
superAdminSchema.methods.comparePassword = async function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

module.exports = mongoose.model('SuperAdmin', superAdminSchema);
