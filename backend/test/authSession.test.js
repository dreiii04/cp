const assert = require('node:assert/strict');
const test = require('node:test');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const {
  ACCESS_TOKEN_TTL_SECONDS,
  buildRefreshTokenRecord,
  comparePassword,
  generateAccessToken,
  getJwtSecret,
  hashRefreshToken,
  isAccountInactive,
  isRefreshTokenRecordValid,
  makeRefreshToken,
} = require('../utils/authSession');

test('password comparison accepts web and mobile password fields', async () => {
  const hash = await bcrypt.hash('CorrectHorse9!', 4);

  assert.equal(await comparePassword({ password: hash }, 'CorrectHorse9!'), true);
  assert.equal(
    await comparePassword({ passwordHash: hash }, 'CorrectHorse9!'),
    true,
  );
  assert.equal(await comparePassword({ passwordHash: hash }, 'wrong'), false);
  assert.equal(await comparePassword({}, 'CorrectHorse9!'), false);
});

test('inactive account values are normalized consistently', () => {
  for (const value of [
    'Inactive',
    'stopped',
    'DEACTIVATED',
    'not-active',
    false,
    0,
  ]) {
    assert.equal(isAccountInactive({ status: value }), true, String(value));
  }

  assert.equal(isAccountInactive({ status: 'Active' }), false);
  assert.equal(isAccountInactive({}), false);
});

test('refresh token records are hashed, scoped, and expire', () => {
  const user = { sessionVersion: 2 };
  const refreshToken = makeRefreshToken();
  const record = buildRefreshTokenRecord(refreshToken, user);

  assert.match(refreshToken, /^[a-f0-9]{96}$/);
  assert.equal(record.tokenHash, hashRefreshToken(refreshToken));
  assert.notEqual(record.tokenHash, refreshToken);
  assert.equal(isRefreshTokenRecordValid(record, user), true);
  assert.equal(
    isRefreshTokenRecordValid(record, { sessionVersion: 3 }),
    false,
  );
  assert.equal(
    isRefreshTokenRecordValid({ ...record, expiresAt: new Date(0) }, user),
    false,
  );
});

test('access token exposes the web and mobile session identity', () => {
  const previousSecret = process.env.JWT_SECRET;
  process.env.JWT_SECRET = 'unit-test-secret-with-sufficient-entropy';

  try {
    const token = generateAccessToken({
      _id: '507f1f77bcf86cd799439011',
      email: 'student@example.com',
      role: 'student',
      firstName: 'Test',
      lastName: 'Student',
    }, 'Student');
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    assert.equal(decoded.id, '507f1f77bcf86cd799439011');
    assert.equal(decoded.modelName, 'Student');
    assert.equal(decoded.tokenType, 'access');
    assert.equal(decoded.exp - decoded.iat, ACCESS_TOKEN_TTL_SECONDS);
  } finally {
    if (previousSecret === undefined) delete process.env.JWT_SECRET;
    else process.env.JWT_SECRET = previousSecret;
  }
});

test('JWT signing fails closed when JWT_SECRET is missing', () => {
  const previousSecret = process.env.JWT_SECRET;
  delete process.env.JWT_SECRET;

  try {
    assert.throws(() => getJwtSecret(), /JWT_SECRET is not configured/);
  } finally {
    if (previousSecret !== undefined) process.env.JWT_SECRET = previousSecret;
  }
});
