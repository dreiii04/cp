const assert = require('node:assert/strict');
const test = require('node:test');
const bcrypt = require('bcryptjs');
const express = require('express');

process.env.JWT_SECRET = 'route-test-secret-with-sufficient-entropy';

const Student = require('../models/Users/Student');
const Alumni = require('../models/Users/Alumni');
const SuperAdmin = require('../models/Users/SuperAdmin');
const Registrar = require('../models/Registrar');
const ActivityLog = require('../models/ActivityLog');
const LoginLockout = require('../models/LoginLockout');
const authRoutes = require('../routes/auth');
const { buildRefreshTokenRecord } = require('../utils/authSession');

const originals = {
  studentFindOne: Student.findOne,
  alumniFindOne: Alumni.findOne,
  superAdminFindOne: SuperAdmin.findOne,
  registrarFindOne: Registrar.findOne,
  activityCreate: ActivityLog.create,
  lockoutFindOne: LoginLockout.findOne,
  lockoutCreate: LoginLockout.create,
  lockoutDeleteOne: LoginLockout.deleteOne,
};

test.after(() => {
  Student.findOne = originals.studentFindOne;
  Alumni.findOne = originals.alumniFindOne;
  SuperAdmin.findOne = originals.superAdminFindOne;
  Registrar.findOne = originals.registrarFindOne;
  ActivityLog.create = originals.activityCreate;
  LoginLockout.findOne = originals.lockoutFindOne;
  LoginLockout.create = originals.lockoutCreate;
  LoginLockout.deleteOne = originals.lockoutDeleteOne;
});

const makeUser = ({ hash, status = 'Active' }) => ({
  _id: '507f1f77bcf86cd799439011',
  email: 'mobile@example.com',
  firstName: 'Mobile',
  lastName: 'User',
  role: 'student',
  status,
  passwordHash: hash,
  refreshTokens: [],
  sessionVersion: 0,
  constructor: {
    updateOne: async () => ({ matchedCount: 1, modifiedCount: 1 }),
  },
});

const postJson = async (baseUrl, path, body) => {
  const response = await fetch(`${baseUrl}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { response, json: await response.json() };
};

test('mobile passwordHash login returns both web and mobile tokens', async () => {
  const hash = await bcrypt.hash('CorrectHorse9!', 4);
  let currentUser = makeUser({ hash });

  Student.findOne = async ({ email }) => (
    email === currentUser.email ? currentUser : null
  );
  Alumni.findOne = async () => null;
  SuperAdmin.findOne = async () => null;
  Registrar.findOne = async () => null;
  ActivityLog.create = async () => ({});
  LoginLockout.findOne = async () => null;
  LoginLockout.create = async () => ({});
  LoginLockout.deleteOne = async () => ({ deletedCount: 1 });

  const app = express();
  app.use(express.json());
  app.use('/api/auth', authRoutes);
  const server = app.listen(0);

  try {
    const address = server.address();
    const baseUrl = `http://127.0.0.1:${address.port}`;
    const loggedIn = await postJson(baseUrl, '/api/auth/login', {
      email: currentUser.email,
      password: 'CorrectHorse9!',
    });

    assert.equal(loggedIn.response.status, 200);
    assert.equal(loggedIn.json.success, true);
    assert.equal(loggedIn.json.token, loggedIn.json.accessToken);
    assert.match(loggedIn.json.refreshToken, /^[a-f0-9]{96}$/);
    assert.equal(loggedIn.json.expiresInSeconds, 86400);

    currentUser.refreshTokens = [
      buildRefreshTokenRecord(loggedIn.json.refreshToken, currentUser),
    ];
    const refreshed = await postJson(baseUrl, '/api/auth/refresh', {
      email: currentUser.email,
      refreshToken: loggedIn.json.refreshToken,
    });
    assert.equal(refreshed.response.status, 200);
    assert.equal(refreshed.json.success, true);
    assert.equal(refreshed.json.token, refreshed.json.accessToken);
    assert.notEqual(refreshed.json.refreshToken, loggedIn.json.refreshToken);

    currentUser = makeUser({ hash, status: 'Inactive' });
    const inactive = await postJson(baseUrl, '/api/auth/login', {
      email: currentUser.email,
      password: 'CorrectHorse9!',
    });
    assert.equal(inactive.response.status, 403);
    assert.match(inactive.json.message, /inactive/i);

    const hiddenStatus = await postJson(baseUrl, '/api/auth/login', {
      email: currentUser.email,
      password: 'incorrect',
    });
    assert.equal(hiddenStatus.response.status, 401);
    assert.equal(hiddenStatus.json.message, 'Invalid credentials');
  } finally {
    await new Promise((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
  }
});
