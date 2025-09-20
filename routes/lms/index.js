var server = module.exports = require('express')();
var crypto = require('crypto');
var path = require('path');
var fs = require('fs');

// Core Adapt utilities
var configuration = require('../../lib/configuration');
var helpers = require('../../lib/helpers');
var logger = require('../../lib/logger');
var usermanager = require('../../lib/usermanager');
var outputmanager = require('../../lib/outputmanager');
var permissions = require('../../lib/permissions');
var Constants = outputmanager.Constants;

// Add middleware to log all LMS route hits
server.use('/api/lms', function(req, res, next) {
  logger.log('info', 'LMS route hit:', req.method, req.url, 'from', req.ip);
  next();
});

// Public ping endpoint (no auth required)
permissions.ignoreRoute(/^\/api\/lms\/ping(?:\?.*)?$/);
server.get('/api/lms/ping', function(req, res) {
  return res.status(200).json({ ok: true, timestamp: Date.now(), message: 'LMS routes are working' });
});

// Secret-based token endpoint (bypasses auth middleware for testing)
permissions.ignoreRoute(/^\/api\/lms\/service-token\/open(?:\?.*)?$/);
server.get('/api/lms/service-token/open', function(req, res) {
  try {
    var secret = req.query.secret;
    if (secret !== 'lms-integration-test-2025') {
      return res.status(401).json({ success: false, message: 'Invalid secret' });
    }
    
    // For testing, create a mock user token
    var mockUserId = 'test-user-' + Date.now();
    var mockTenantId = 'test-tenant';
    var issued = _issueToken(mockUserId, mockTenantId, DEFAULT_TTL_MS);
    
    logger.log('info', 'Generated test token for LMS integration');
    return res.status(200).json({ 
      success: true, 
      token: issued.token, 
      userId: issued.userId, 
      tenantId: issued.tenantId, 
      expiresAt: issued.expiresAt,
      note: 'This is a test token for LMS integration'
    });
  } catch (e) {
    return _handleError(res, e);
  }
});

// In-memory service token store (no DB/schema changes)
// token -> { userId, tenantId, expMs }
var _tokens = new Map();
var DEFAULT_TTL_MS = 15 * 60 * 1000; // 15 minutes

function _issueToken(userId, tenantId, ttlMs) {
  var token = crypto.randomBytes(24).toString('hex');
  var expMs = Date.now() + (ttlMs || DEFAULT_TTL_MS);
  _tokens.set(token, { userId: userId, tenantId: tenantId, expMs: expMs });
  return { token: token, userId: userId, tenantId: tenantId, expiresAt: new Date(expMs).toISOString() };
}

function _resolveAuth(req, res) {
  try {
    logger.log('info', 'LMS auth: starting _resolveAuth');
    
    // Prefer request-bound user (session-authenticated requests under /api)
    if (req && req.user && req.user._id && req.user.tenant && req.user.tenant._id) {
      logger.log('info', 'LMS auth: using req.user');
      return { userId: req.user._id, tenantId: req.user.tenant._id, user: req.user };
    }
    logger.log('info', 'LMS auth: req.user not available, checking usermanager');

    // Try to get user from global usermanager as fallback
    var currentUser = null;
    try {
      if (usermanager.getCurrentUser && typeof usermanager.getCurrentUser === 'function') {
        currentUser = usermanager.getCurrentUser();
        logger.log('info', 'LMS auth: usermanager.getCurrentUser() returned:', currentUser ? 'user object' : 'null');
      }
    } catch (e) {
      logger.log('error', 'LMS auth: usermanager error:', e);
    }
    if (currentUser && currentUser._id && currentUser.tenant && currentUser.tenant._id) {
      logger.log('info', 'LMS auth: using usermanager');
      return { userId: currentUser._id, tenantId: currentUser.tenant._id, user: currentUser };
    }
    logger.log('info', 'LMS auth: usermanager not available, checking service token');

    // Fallback to service token header
    var hdr = req.headers['x-adapt-service-token'];
    logger.log('info', 'LMS auth: service token header:', hdr ? 'present' : 'missing');
    if (!hdr || typeof hdr !== 'string') {
      logger.log('info', 'LMS auth: no service token');
      return null;
    }
    var rec = _tokens.get(hdr);
    logger.log('info', 'LMS auth: token lookup result:', rec ? 'found' : 'not found');
    if (!rec) {
      logger.log('info', 'LMS auth: invalid service token');
      return null;
    }
    if (Date.now() > rec.expMs) {
      _tokens.delete(hdr);
      logger.log('info', 'LMS auth: expired service token');
      return null;
    }
    // Lazy purge on use: if close to expiry, keep as-is; caller can request a new token via service-token endpoint
    logger.log('info', 'LMS auth: using service token, userId:', rec.userId, 'tenantId:', rec.tenantId);
    return { userId: rec.userId, tenantId: rec.tenantId, user: null };
  } catch (e) {
    logger.log('error', 'LMS auth: _resolveAuth error:', e);
    return null;
  }
}

function _handleError(res, error, status) {
  logger.log('error', 'LMS Error:', error);
  return res.status(status || 500).json({ success: false, error: (error && error.message) || String(error) });
}

// Allow whoami through permission guard
permissions.ignoreRoute(/^\/api\/lms\/whoami(?:\?.*)?$/);
// Allow metadata/export endpoints through guard (we do explicit checks inside)
permissions.ignoreRoute(/^\/api\/lms\/course\/[^/]+\/metadata(?:\?.*)?$/);
permissions.ignoreRoute(/^\/api\/lms\/[^/]+\/course\/[^/]+\/metadata(?:\?.*)?$/);
permissions.ignoreRoute(/^\/api\/lms\/export(?:\?.*)?$/);
permissions.ignoreRoute(/^\/api\/lms\/export\/download(?:\?.*)?$/);
// GET /api/lms/whoami (accepts session OR x-adapt-service-token)
server.get('/api/lms/whoami', function(req, res) {
  try {
    logger.log('info', 'LMS whoami: req.user exists?', !!req.user);
    var auth = _resolveAuth(req, res);
    if (!auth) {
      return res.status(401).json({ success: false, message: 'Unauthorized' });
    }
    // If session user is available, include email and tenantName; otherwise return token identity only
    var payload = {
      success: true,
      userId: auth.userId,
      tenantId: auth.tenantId
    };
    if (auth.user) {
      payload.email = auth.user.email;
      payload.tenantName = auth.user.tenant && auth.user.tenant.name;
    }
    return res.status(200).json(payload);
  } catch (e) {
    logger.log('error', 'LMS whoami error:', e);
    return _handleError(res, e);
  }
});

// GET /api/lms/course/:courseId/metadata (tenant-less helper; uses auth.tenantId or infers from course)
server.get('/api/lms/course/:courseId/metadata', function(req, res) {
  try {
    logger.log('info', 'LMS metadata: starting request for courseId:', req.params.courseId);
    var auth = _resolveAuth(req, res);
    if (!auth) {
      logger.log('info', 'LMS metadata: auth failed');
      return res.status(401).json({ success: false, message: 'Unauthorized' });
    }
    logger.log('info', 'LMS metadata: auth successful, userId:', auth.userId, 'tenantId:', auth.tenantId);
    var courseId = req.params.courseId;

    // Use tenantId from auth if available (service token), otherwise infer from course
    var effectiveTenantId = auth.tenantId;
    
    if (!effectiveTenantId) {
      // Infer tenant from course document
      app.contentmanager.getContentPlugin('course', function(error, plugin) {
        if (error) return _handleError(res, error);
        plugin.retrieve({ _id: courseId }, {}, function(error2, results) {
          if (error2) return _handleError(res, error2);
          if (!results || results.length !== 1) return _handleError(res, new Error('Course not found'), 404);
          var courseDoc = results[0];
          effectiveTenantId = (courseDoc && courseDoc._tenantId) ? String(courseDoc._tenantId) : null;
          if (!effectiveTenantId) return _handleError(res, new Error('Unable to resolve tenant for course'), 400);
          return _checkPermsAndReturn(courseDoc, effectiveTenantId);
        });
      });
      return;
    }

    // If we have tenantId from auth, fetch course and check permissions
    app.contentmanager.getContentPlugin('course', function(error, plugin) {
      if (error) return _handleError(res, error);
      plugin.retrieve({ _id: courseId }, {}, function(error2, results) {
        if (error2) return _handleError(res, error2);
        if (!results || results.length !== 1) return _handleError(res, new Error('Course not found'), 404);
        return _checkPermsAndReturn(results[0], effectiveTenantId);
      });
    });

    function _checkPermsAndReturn(courseDoc, tenantId) {
      logger.log('info', 'LMS metadata: checking permissions for userId:', auth.userId, 'tenantId:', tenantId, 'courseId:', courseId);
      helpers.hasCoursePermission('read', auth.userId, tenantId, { _id: courseId }, function(err, hasPermission) {
        if (err) {
          logger.log('error', 'Permission check error:', err);
          return _handleError(res, err, 500);
        }
        if (!hasPermission) {
          logger.log('info', 'LMS metadata: permission denied');
          return _handleError(res, new Error('Permission denied'), 403);
        }
        logger.log('info', 'LMS metadata: permission granted, returning course data');

        return res.status(200).json({
          success: true,
          id: courseDoc._id,
          title: courseDoc.title,
          description: courseDoc.body || courseDoc.description || null,
          heroImageUrl: null,
          updatedAt: courseDoc.updatedAt || courseDoc._modified || null
        });
      });
    }
  } catch (e) {
    return _handleError(res, e);
  }
});

// Allow service-token through permission guard (must be logged-in session to mint)
permissions.ignoreRoute(/^\/api\/lms\/service-token(?:\?.*)?$/);
// POST /api/lms/service-token
server.post('/api/lms/service-token', function(req, res) {
  try {
    // Prefer usermanager (richer object), then fall back to req.user
    var currentUser = null;
    try {
      if (usermanager.getCurrentUser && typeof usermanager.getCurrentUser === 'function') {
        currentUser = usermanager.getCurrentUser();
      }
    } catch (e) {}
    if (!currentUser && req && req.user) currentUser = req.user;

    if (!currentUser || !currentUser._id) {
      return res.status(401).json({ success: false, message: 'Unauthorized' });
    }
    var issued = _issueToken(currentUser._id, currentUser.tenant && currentUser.tenant._id, DEFAULT_TTL_MS);
    return res.status(200).json({ success: true, token: issued.token, userId: issued.userId, tenantId: issued.tenantId, expiresAt: issued.expiresAt });
  } catch (e) {
    return _handleError(res, e);
  }
});

// GET /api/lms/service-token (CSRF-friendly helper)
server.get('/api/lms/service-token', function(req, res) {
  try {
    var currentUser = null;
    try {
      if (usermanager.getCurrentUser && typeof usermanager.getCurrentUser === 'function') {
        currentUser = usermanager.getCurrentUser();
      }
    } catch (e) {}
    if (!currentUser && req && req.user) currentUser = req.user;
    if (!currentUser || !currentUser._id) {
      return res.status(401).json({ success: false, message: 'Unauthorized' });
    }
    var issued = _issueToken(currentUser._id, currentUser.tenant && currentUser.tenant._id, DEFAULT_TTL_MS);
    return res.status(200).json({ success: true, token: issued.token, userId: issued.userId, tenantId: issued.tenantId, expiresAt: issued.expiresAt });
  } catch (e) {
    return _handleError(res, e);
  }
});

// GET /api/lms/:tenantId/course/:courseId/metadata
server.get('/api/lms/:tenantId/course/:courseId/metadata', function(req, res) {
  try {
    var auth = _resolveAuth(req, res);
    if (!auth) return res.status(401).json({ success: false, message: 'Unauthorized' });

    // Note: whoami via token doesn't include tenantId; infer via course._tenantId
    var tenantId = req.params.tenantId;
    var courseId = req.params.courseId;

    // Permission check - try with different permission levels
    var effectiveTenantId = tenantId;
    if (!effectiveTenantId) {
      // Load the course to infer tenant
      app.contentmanager.getContentPlugin('course', function(error, plugin) {
        if (error) return _handleError(res, error);
        plugin.retrieve({ _id: courseId }, {}, function(error2, results) {
          if (error2) return _handleError(res, error2);
          if (!results || results.length !== 1) return _handleError(res, new Error('Course not found'), 404);
          var courseDoc = results[0];
          effectiveTenantId = (courseDoc && courseDoc._tenantId) ? String(courseDoc._tenantId) : null;
          if (!effectiveTenantId) return _handleError(res, new Error('Unable to resolve tenant for course'), 400);
          return _checkPermsAndReturn(courseDoc);
        });
      });
      return;
    }
    // If tenantId was provided, fetch course after permission to preserve behavior
    helpers.hasCoursePermission('read', auth.userId, effectiveTenantId, { _id: courseId }, function(err, hasPermission) {
      if (err) {
        logger.log('error', 'Permission check error:', err);
        return _handleError(res, err, 500);
      }
      if (!hasPermission) {
        return _handleError(res, new Error('Permission denied'), 403);
      }
      // Retrieve course metadata
      app.contentmanager.getContentPlugin('course', function(error, plugin) {
        if (error) return _handleError(res, error);
        plugin.retrieve({ _id: courseId }, {}, function(error2, results) {
          if (error2) return _handleError(res, error2);
          if (!results || results.length !== 1) return _handleError(res, new Error('Course not found'), 404);
          return _checkPermsAndReturn(results[0]);
        });
      });
    });

    function _checkPermsAndReturn(course) {
      // effectiveTenantId is now known
      helpers.hasCoursePermission('read', auth.userId, effectiveTenantId, { _id: courseId }, function(err, hasPermission) {
        if (err) {
          logger.log('error', 'Permission check error:', err);
          return _handleError(res, err, 500);
        }
        if (!hasPermission) {
          return _handleError(res, new Error('Permission denied'), 403);
        }
        return res.status(200).json({
          success: true,
          id: course._id,
          title: course.title,
          description: course.body || course.description || null,
          heroImageUrl: null,
          updatedAt: course.updatedAt || course._modified || null
        });
      });
    }
  } catch (e) {
    return _handleError(res, e);
  }
});

// POST /api/lms/export  { tenantId, courseId }
server.post('/api/lms/export', function(req, res) {
  try {
    var auth = _resolveAuth(req, res);
    if (!auth) return res.status(401).json({ success: false, message: 'Unauthorized' });
    var body = req.body || {};
    var tenantId = body.tenantId;
    var courseId = body.courseId;
    if (!tenantId || !courseId) return res.status(400).json({ success: false, message: 'tenantId and courseId are required' });

    helpers.hasCoursePermission('read', auth.userId, tenantId, { _id: courseId }, function(err, hasPermission) {
      if (err) {
        logger.log('error', 'Permission check error:', err);
        return _handleError(res, err, 500);
      }
      if (!hasPermission) {
        return _handleError(res, new Error('Permission denied'), 403);
      }

      // Use the output plugin to export (same behavior as routes/export)
      app.outputmanager.getOutputPlugin(configuration.getConfig('outputPlugin'), function(error, plugin) {
        if (error) return _handleError(res, error);
        try {
          plugin.export(courseId, req, res, function (exportErr, result) {
            if (exportErr) {
              logger.log('error', 'Unable to export:', exportErr);
              return res.status(500).json({ success: false, message: exportErr.message || 'Export failed' });
            }
            // Indicate export was triggered; download endpoint will stream file
            return res.status(200).json({ success: true, status: 'queued' });
          });
        } catch (ex) {
          return _handleError(res, ex);
        }
      });
    });
  } catch (e) {
    return _handleError(res, e);
  }
});

// GET /api/lms/export/download?tenantId=...&courseId=...
server.get('/api/lms/export/download', function(req, res) {
  try {
    var auth = _resolveAuth(req, res);
    if (!auth) return res.status(401).json({ success: false, message: 'Unauthorized' });
    var tenantId = req.query.tenantId;
    var courseId = req.query.courseId;
    if (!tenantId || !courseId) return res.status(400).json({ success: false, message: 'tenantId and courseId are required' });

    helpers.hasCoursePermission('read', auth.userId, tenantId, { _id: courseId }, function(err, hasPermission) {
      if (err) {
        logger.log('error', 'Permission check error:', err);
        return _handleError(res, err, 500);
      }
      if (!hasPermission) {
        return _handleError(res, new Error('Permission denied'), 403);
      }

      var userId = auth.userId;
      var zipDir = path.join(
        configuration.tempDir,
        configuration.getConfig('masterTenantID'),
        Constants.Folders.Exports,
        userId + '.zip'
      );

      fs.stat(zipDir, function(statErr, stat) {
        if (statErr || !stat || !stat.size) {
          return _handleError(res, new Error('Export ZIP not found'), 404);
        }
        var zipName = 'export.zip';
        res.writeHead(200, {
          'Content-Type': 'application/zip',
          'Content-Length': stat.size,
          'Content-disposition': 'attachment; filename=' + zipName,
          'Pragma': 'no-cache',
          'Expires': '0'
        });
        fs.createReadStream(zipDir).pipe(res);
      });
    });
  } catch (e) {
    return _handleError(res, e);
  }
});


