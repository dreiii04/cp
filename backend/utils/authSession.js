const { createHash, randomBytes } = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const ACCESS_TOKEN_TTL_SECONDS = 24 * 60 * 60;
const REFRESH_TOKEN_TTL_DAYS = 30;
const BCRYPT_HASH_PATTERN = /^\$2[aby]\$\d{2}\$/;

const inactiveAccountValues = new Set([
  '0',
  'banned',
  'blocked',
  'deactivated',
  'disabled',
  'false',
  'in_active',
  'inactive',
  'locked',
  'no',
  'not_active',
  'off',
  'stopped',
  'suspended',
]);

const getJwtSecret = () => {
  const secret = String(process.env.JWT_SECRET || '').trim();
  if (!secret) throw new Error('JWT_SECRET is not configured');
  return secret;
};

const normalizeStatus = (value) => String(value || '')
  .trim()
  .toLowerCase()
  .replace(/[\s-]+/g, '_');

const isInactiveAccountValue = (value) => {
  if (value === false || value === 0) return true;
  return inactiveAccountValues.has(normalizeStatus(value));
};

const isAccountInactive = (user) => {
  if (!user) return false;
  return [
    user.accountStatus,
    user.account_status,
    user.status,
    user.activeStatus,
    user.isActive,
    user.is_active,
    user.active,
    user.enabled,
  ].some(isInactiveAccountValue);
};

const getPasswordHash = (user) => {
  const hash = String(user?.passwordHash || user?.password || '').trim();
  return BCRYPT_HASH_PATTERN.test(hash) ? hash : '';
};

const comparePassword = async (user, candidatePassword) => {
  const hash = getPasswordHash(user);
  if (!hash || typeof candidatePassword !== 'string') return false;
  return bcrypt.compare(candidatePassword, hash);
};

const userDisplayName = (user) => user.name
  || `${user.firstName || ''} ${user.lastName || ''}`.trim()
  || 'User';

const generateAccessToken = (user, modelName) => jwt.sign(
  {
    id: user._id,
    email: user.email,
    role: user.role,
    name: userDisplayName(user),
    modelName,
    tokenType: 'access',
  },
  getJwtSecret(),
  { expiresIn: ACCESS_TOKEN_TTL_SECONDS },
);

const makeRefreshToken = () => randomBytes(48).toString('hex');

const hashRefreshToken = (refreshToken) => createHash('sha256')
  .update(refreshToken)
  .digest('hex');

const buildRefreshTokenRecord = (refreshToken, user) => {
  const now = new Date();
  return {
    tokenHash: hashRefreshToken(refreshToken),
    sessionVersion: Number(user.sessionVersion || 0),
    createdAt: now,
    expiresAt: new Date(
      now.getTime() + REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60 * 1000,
    ),
  };
};

const isRefreshTokenRecordValid = (record, user) => Boolean(
  record
  && new Date(record.expiresAt).getTime() > Date.now()
  && Number(record.sessionVersion || 0) === Number(user.sessionVersion || 0),
);

module.exports = {
  ACCESS_TOKEN_TTL_SECONDS,
  buildRefreshTokenRecord,
  comparePassword,
  generateAccessToken,
  getJwtSecret,
  hashRefreshToken,
  isAccountInactive,
  isRefreshTokenRecordValid,
  makeRefreshToken,
  userDisplayName,
};
