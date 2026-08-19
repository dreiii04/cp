const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { protect } = require('../middleware/authMiddleware');
const { validate, registerValidation, loginValidation, updateProfileValidation } = require('../middleware/validationMiddleware');
const { registerLimiter, loginProgressiveLimiter } = require('../middleware/rateLimiterMiddleware');

const Student = require('../models/Users/Student');
const Alumni = require('../models/Users/Alumni');
const SuperAdmin = require('../models/Users/SuperAdmin');
const Registrar = require('../models/Registrar');
const ActivityLog = require('../models/ActivityLog');
const {
  ACCESS_TOKEN_TTL_SECONDS,
  buildRefreshTokenRecord,
  comparePassword,
  generateAccessToken,
  hashRefreshToken,
  isAccountInactive,
  isRefreshTokenRecordValid,
  makeRefreshToken,
  userDisplayName,
} = require('../utils/authSession');

// In-memory OTP store: { email: { otp, expiresAt, modelName } }
const otpStore = {};

// Nodemailer transporter (Gmail)
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.SMTP_EMAIL,
    pass: process.env.SMTP_PASSWORD,
  },
});

const userModels = [
  { modelName: 'Student', model: Student },
  { modelName: 'Alumni', model: Alumni },
  { modelName: 'SuperAdmin', model: SuperAdmin },
  { modelName: 'Registrar', model: Registrar },
];

const findUserByEmail = async (email) => {
  for (const entry of userModels) {
    const user = await entry.model.findOne({ email });
    if (user) return { ...entry, user };
  }
  return null;
};

const issueSession = async (user, modelName) => {
  const refreshToken = makeRefreshToken();
  const refreshRecord = buildRefreshTokenRecord(refreshToken, user);
  const result = await user.constructor.updateOne(
    { _id: user._id },
    {
      $push: {
        refreshTokens: {
          $each: [refreshRecord],
          $slice: -5,
        },
      },
    },
  );

  if (result.matchedCount !== 1) {
    throw new Error('Unable to persist refresh session');
  }

  const accessToken = generateAccessToken(user, modelName);
  return {
    // Keep `token` for the existing web client while exposing the names used
    // by the Flutter client.
    token: accessToken,
    accessToken,
    refreshToken,
    expiresInSeconds: ACCESS_TOKEN_TTL_SECONDS,
  };
};

const removeRefreshToken = async (user, tokenHash) => user.constructor.updateOne(
  { _id: user._id, 'refreshTokens.tokenHash': tokenHash },
  { $pull: { refreshTokens: { tokenHash } } },
);

const logSuccessfulLogin = async (user) => {
  try {
    await ActivityLog.create({
      userEmail: user.email,
      userName: userDisplayName(user),
      action: 'Login',
      type: '------',
      status: 'Successful',
      details: `${user.role} logged into the system`,
    });
  } catch (error) {
    console.error('Unable to write login activity:', error.message);
  }
};

const clearLoginLockout = async (clientIp) => {
  if (!clientIp) return;
  try {
    const LoginLockout = require('../models/LoginLockout');
    await LoginLockout.deleteOne({ ip: clientIp });
  } catch (error) {
    console.error('Unable to clear login lockout:', error.message);
  }
};

// @route   POST /api/auth/register
// @desc    Register a new student/alumni
router.post('/register', registerLimiter, registerValidation, validate, async (req, res) => {
  try {
    const { firstName, lastName, email, password, role, studentId, course, yearLevel, phoneNumber } = req.body;

    // Check if user already exists
    const existingStudent = await Student.findOne({ email });
    if (existingStudent) {
      return res.status(400).json({ success: false, message: 'Email already registered' });
    }

    if (studentId) {
      const existingIdStudent = await Student.findOne({ studentId });
      const existingIdAlumni = await Alumni.findOne({ studentId });
      if (existingIdStudent || existingIdAlumni) {
        return res.status(400).json({ success: false, message: 'Student ID already registered' });
      }
    }

    const isAlumni = role === 'alumni';
    const UserModel = isAlumni ? Alumni : Student;

    // Create new user
    const user = await UserModel.create({
      firstName,
      lastName,
      email,
      password, // Model pre-save hook hashes this
      role: role || 'student',
      studentId: studentId || null,
      course: course || '',
      yearLevel: yearLevel || '',
      phoneNumber: phoneNumber || ''
    });

    const token = generateAccessToken(user, isAlumni ? 'Alumni' : 'Student');

    res.status(201).json({
      success: true,
      message: 'Registration successful',
      token,
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
        studentId: user.studentId || '',
        course: user.course || '',
        yearLevel: user.yearLevel || '',
        phoneNumber: user.phoneNumber || ''
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ success: false, message: 'Server error', error: error.message });
  }
});

// @route   POST /api/auth/login
// @desc    Authenticate user and get token
router.post('/login', loginProgressiveLimiter, loginValidation, validate, async (req, res) => {
  try {
    const { email, password } = req.body;
    const result = await findUserByEmail(email);

    if (!result) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    const { user, modelName } = result;

    // Student and alumni records created by the mobile API use
    // `passwordHash`; records created by the web API use `password`.
    const isMatch = await comparePassword(user, password);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    // Check the status only after validating the password so callers cannot
    // use the response to discover inactive accounts.
    if (isAccountInactive(user)) {
      return res.status(403).json({
        success: false,
        message: 'Account is currently inactive. Please contact an administrator.',
      });
    }

    const session = await issueSession(user, modelName);

    // Audit and lockout cleanup must not turn a valid login into a 500.
    await logSuccessfulLogin(user);
    await clearLoginLockout(req.clientIp);

    res.json({
      success: true,
      message: 'Logged in successfully',
      ...session,
      user: {
        id: user._id,
        email: user.email,
        role: user.role,
        firstName: user.firstName,
        lastName: user.lastName,
        name: user.name,
        studentId: user.studentId || '',
        course: user.course || '',
        yearLevel: user.yearLevel || '',
        phoneNumber: user.phoneNumber || ''
      }
    });
  } catch (error) {
    console.error('Login error:', error.message);
    console.error('Login error stack:', error.stack);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

router.post('/refresh', async (req, res) => {
  try {
    const email = String(req.body?.email || '').trim().toLowerCase();
    const refreshToken = String(req.body?.refreshToken || '').trim();

    if (!email || !/^[a-f0-9]{96}$/.test(refreshToken)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid email or refresh token.',
      });
    }

    const result = await findUserByEmail(email);
    if (!result) {
      return res.status(401).json({
        success: false,
        message: 'Invalid refresh session.',
      });
    }
    const { user, modelName } = result;

    if (isAccountInactive(user)) {
      return res.status(403).json({
        success: false,
        message: 'Account is currently inactive. Please contact an administrator.',
      });
    }

    const tokenHash = hashRefreshToken(refreshToken);
    const record = Array.isArray(user.refreshTokens)
      ? user.refreshTokens.find((item) => item.tokenHash === tokenHash)
      : null;

    if (!isRefreshTokenRecordValid(record, user)) {
      await removeRefreshToken(user, tokenHash);
      return res.status(401).json({
        success: false,
        message: 'Invalid refresh session.',
      });
    }

    // Consume before issuing the replacement so concurrent replays fail.
    const consumed = await removeRefreshToken(user, tokenHash);
    if (consumed.modifiedCount !== 1) {
      return res.status(401).json({
        success: false,
        message: 'Invalid refresh session.',
      });
    }

    const session = await issueSession(user, modelName);
    return res.json({
      success: true,
      message: 'Session refreshed.',
      ...session,
    });
  } catch (error) {
    console.error('Refresh error:', error.message);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

router.post('/logout', async (req, res) => {
  try {
    const email = String(req.body?.email || '').trim().toLowerCase();
    const refreshToken = String(req.body?.refreshToken || '').trim();

    if (!email || !/^[a-f0-9]{96}$/.test(refreshToken)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid email or refresh token.',
      });
    }

    const result = await findUserByEmail(email);
    if (result) {
      await removeRefreshToken(result.user, hashRefreshToken(refreshToken));
    }

    return res.json({ success: true, message: 'Logged out.' });
  } catch (error) {
    console.error('Logout error:', error.message);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

router.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ success: false, message: 'Email is required' });

    let user = null;
    let modelName = '';

    user = await Student.findOne({ email });
    if (user) modelName = 'Student';
    
    if (!user) {
      user = await Alumni.findOne({ email });
      if (user) modelName = 'Alumni';
    }

    if (!user) {
      user = await SuperAdmin.findOne({ email });
      if (user) modelName = 'SuperAdmin';
    }

    if (!user) {
      user = await Registrar.findOne({ email });
      if (user) modelName = 'Registrar';
    }

    if (!user) {
      return res.status(404).json({ success: false, message: 'No account found with that email' });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = Date.now() + 10 * 60 * 1000;

    otpStore[email] = { otp, expiresAt, modelName };

    await transporter.sendMail({
      from: `"VeriFitor System" <${process.env.SMTP_EMAIL}>`,
      to: email,
      subject: 'VeriFitor - Password Reset OTP',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 480px; margin: 0 auto; padding: 20px;">
          <h2 style="color: #2f3947;">Password Reset Request</h2>
          <p>You requested to reset your password. Use the OTP below:</p>
          <div style="background: #f4f4f4; padding: 20px; text-align: center; border-radius: 8px; margin: 20px 0;">
            <span style="font-size: 32px; font-weight: bold; letter-spacing: 8px; color: #2f3947;">${otp}</span>
          </div>
          <p style="color: #666;">This OTP expires in <strong>10 minutes</strong>.</p>
          <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
          <p style="color: #999; font-size: 11px; text-align: center;">VeriFitor — Document Verification System</p>
        </div>
      `
    });

    res.json({ success: true, message: 'OTP sent to your email' });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ success: false, message: 'Error sending OTP email' });
  }
});

router.post('/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    const stored = otpStore[email];
    if (!stored || Date.now() > stored.expiresAt || stored.otp !== otp) {
      return res.status(400).json({ success: false, message: 'Invalid or expired OTP' });
    }

    const resetToken = jwt.sign(
      { email, modelName: stored.modelName },
      process.env.JWT_SECRET,
      { expiresIn: '15m' }
    );

    delete otpStore[email];
    res.json({ success: true, message: 'OTP verified successfully', resetToken });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

router.post('/reset-password', async (req, res) => {
  try {
    const { resetToken, newPassword, password } = req.body;
    const decoded = jwt.verify(resetToken, process.env.JWT_SECRET);
    const { email, modelName } = decoded;

    const targetPassword = newPassword || password;
    if (!targetPassword) {
      return res.status(400).json({ success: false, message: 'New password is required' });
    }

    let userModel;
    if (modelName === 'Student') userModel = Student;
    else if (modelName === 'Alumni') userModel = Alumni;
    else if (modelName === 'SuperAdmin') userModel = SuperAdmin;
    else userModel = Registrar;

    const user = await userModel.findOne({ email });
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });

    user.password = targetPassword;
    await user.save();

    await ActivityLog.create({
      userEmail: email,
      userName: 'User',
      action: 'Password Reset',
      type: '------',
      status: 'Successful',
      details: `Password reset completed for ${email}`
    });

    res.json({ success: true, message: 'Password reset successfully' });
  } catch (error) {
    console.error('Password reset error:', error);
    res.status(500).json({ success: false, message: 'Error resetting password' });
  }
});

router.get('/profile', protect, async (req, res) => {
  try {
    let user = null;
    const role = (req.user.role || '').toLowerCase();
    if (role === 'super admin') {
      user = await SuperAdmin.findById(req.user.id);
    } else if (role.includes('registrar')) {
      user = await Registrar.findById(req.user.id);
    } else if (role === 'alumni') {
      user = await Alumni.findById(req.user.id);
    } else {
      user = await Student.findById(req.user.id);
    }

    if (!user) return res.status(404).json({ message: 'User not found' });

    res.json({
      id: user._id,
      email: user.email,
      role: user.role,
      name: user.name || `${user.firstName || ''} ${user.lastName || ''}`.trim() || 'User',
      firstName: user.firstName,
      lastName: user.lastName,
      profilePic: user.profilePic || '',
      studentId: user.studentId || '',
      course: user.course || '',
      yearLevel: user.yearLevel || '',
      phoneNumber: user.phoneNumber || ''
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

router.put('/profile', protect, updateProfileValidation, validate, async (req, res) => {
  try {
    const { name, firstName, lastName, profilePic, course, yearLevel, phoneNumber } = req.body;
    
    let userModel;
    const role = (req.user.role || '').toLowerCase();
    if (role === 'super admin') userModel = SuperAdmin;
    else if (role.includes('registrar')) userModel = Registrar;
    else if (role === 'alumni') userModel = Alumni;
    else userModel = Student;

    const updateData = {};
    if (name) {
      updateData.name = name;
      if (req.user.role === 'student' || req.user.role === 'alumni') {
        const parts = name.trim().split(' ');
        updateData.firstName = parts[0];
        updateData.lastName = parts.slice(1).join(' ') || ' ';
      }
    }
    if (firstName) updateData.firstName = firstName;
    if (lastName) updateData.lastName = lastName;
    if (profilePic) updateData.profilePic = profilePic;
    if (course) updateData.course = course;
    if (yearLevel) updateData.yearLevel = yearLevel;
    if (phoneNumber) updateData.phoneNumber = phoneNumber;

    const updatedUser = await userModel.findByIdAndUpdate(req.user.id, updateData, { new: true });
    res.json(updatedUser);
  } catch (error) {
    res.status(500).json({ message: 'Error updating profile' });
  }
});

router.put('/change-password', protect, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    
    let userModel;
    const role = (req.user.role || '').toLowerCase();
    if (role === 'super admin') userModel = SuperAdmin;
    else if (role.includes('registrar')) userModel = Registrar;
    else if (role === 'alumni') userModel = Alumni;
    else userModel = Student;

    const user = await userModel.findById(req.user.id);
    const isMatch = await user.comparePassword(currentPassword);
    if (!isMatch) return res.status(400).json({ message: 'Current password incorrect' });

    user.password = newPassword;
    await user.save();

    res.json({ message: 'Password updated successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error updating password' });
  }
});

module.exports = router;
