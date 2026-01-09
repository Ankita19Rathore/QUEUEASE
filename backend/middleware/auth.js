const jwt = require('jsonwebtoken');
const User = require('../models/User');

const auth = async (req, res, next) => {
  try {
    const authHeader = req.header('Authorization');
    const token = authHeader?.replace('Bearer ', '');
    
    console.log('Auth middleware:', {
      hasAuthHeader: !!authHeader,
      hasToken: !!token,
      path: req.path,
      method: req.method
    });
    
    if (!token) {
      console.error('No token provided');
      return res.status(401).json({ message: 'No token, authorization denied' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret_key_change_this_in_production');
    console.log('Token decoded:', { userId: decoded.userId });
    
    const user = await User.findById(decoded.userId).select('-password');
    
    if (!user) {
      console.error(`User not found for userId: ${decoded.userId}`);
      return res.status(401).json({ message: 'User not found' });
    }

    console.log('User authenticated:', {
      id: user._id.toString(),
      email: user.email,
      role: user.role
    });

    req.user = user;
    next();
  } catch (error) {
    console.error('Auth error:', error.message);
    res.status(401).json({ message: 'Token is not valid', error: error.message });
  }
};

const requireRole = (...roles) => {
  return (req, res, next) => {
    console.log('requireRole check:', {
      hasUser: !!req.user,
      userId: req.user?._id,
      userEmail: req.user?.email,
      userRole: req.user?.role,
      requiredRoles: roles
    });
    
    if (!req.user) {
      console.error('No user in request object');
      return res.status(401).json({ message: 'Authentication required' });
    }
    
    if (!roles.includes(req.user.role)) {
      const errorDetails = {
        message: 'Access denied',
        required: roles,
        current: req.user.role,
        userId: req.user._id.toString(),
        userEmail: req.user.email
      };
      console.error('Access denied:', errorDetails);
      return res.status(403).json(errorDetails);
    }
    
    console.log('Role check passed, allowing access');
    next();
  };
};

module.exports = { auth, requireRole };

