const jwt = require('jsonwebtoken');
const Student = require('../models/Users/Student');
const Alumni = require('../models/Users/Alumni');
const Registrar = require('../models/Registrar');
const SuperAdmin = require('../models/Users/SuperAdmin');
const { getJwtSecret, isAccountInactive } = require('../utils/authSession');

const modelByName = {
  Student,
  Alumni,
  Registrar,
  SuperAdmin,
};

const findTokenUser = async (decoded) => {
  const preferredModel = modelByName[decoded.modelName];
  if (preferredModel) {
    const user = await preferredModel.findById(decoded.id);
    if (user) return user;
  }

  for (const model of [Student, Alumni, Registrar, SuperAdmin]) {
    if (model === preferredModel) continue;
    const user = await model.findById(decoded.id);
    if (user) return user;
  }
  return null;
};

const protect = async (req, res, next) => {
  let token;

  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  }

  if (!token) {
    console.log('No token provided');
    return res.status(401).json({ message: 'Not authorized, no token' });
  }

  try {
    const decoded = jwt.verify(token, getJwtSecret());
    if (decoded.tokenType && decoded.tokenType !== 'access') {
      return res.status(401).json({
        success: false,
        message: 'Not authorized, token failed',
      });
    }
    console.log('Token decoded:', decoded);

    // Re-check the database on every protected request. Deactivating an
    // account therefore invalidates its existing access token immediately.
    const dbUser = await findTokenUser(decoded);
    if (!dbUser) {
      return res.status(401).json({
        success: false,
        message: 'Not authorized, user not found',
      });
    }
    if (isAccountInactive(dbUser)) {
      return res.status(403).json({
        success: false,
        message: 'Account is currently inactive. Please contact an administrator.',
      });
    }

    // Dynamic database name resolution prevents stale "User" labels.
    if (!decoded.name || decoded.name === 'User') {
      decoded.name = dbUser.name
        || `${dbUser.firstName || ''} ${dbUser.lastName || ''}`.trim();
    }

    if (!decoded.name) {
      decoded.name = 'User';
    }

    req.user = decoded;
    next();
  } catch (error) {
    console.error('Token verification failed:', error);
    res.status(401).json({ message: 'Not authorized, token failed' });
  }
};

const superAdminOnly = (req, res, next) => {
  console.log('Checking super admin access. User role:', req.user?.role);
  if (req.user && req.user.role === 'super admin') {
    console.log('Super admin access granted');
    next();
  } else {
    console.log('Super admin access denied');
    res.status(403).json({ message: 'Not authorized as Super Admin' });
  }
};

const registrarOrSuperAdmin = (req, res, next) => {
  if (req.user && (req.user.role === 'registrar' || req.user.role === 'super admin')) {
    next();
  } else {
    res.status(403).json({ message: 'Not authorized, role insufficient' });
  }
};

module.exports = { protect, superAdminOnly, registrarOrSuperAdmin };
