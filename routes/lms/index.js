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
var Constants = outputmanager.Constants;

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
  // Prefer session user when available
  var currentUser = usermanager.getCurrentUser && usermanager.getCurrentUser();
  if (currentUser && currentUser._id && currentUser.tenant && currentUser.tenant._id) {
    return { userId: currentUser._id, tenantId: currentUser.tenant._id, user: currentUser };
  }

  // Fallback to service token header
  var hdr = req.headers['x-adapt-service-token'];
  if (!hdr || typeof hdr !== 'string') {
    return null;
  }
  var rec = _tokens.get(hdr);
  if (!rec) return null;
  if (Date.now() > rec.expMs) {
    _tokens.delete(hdr);
    return null;
  }
  // Lazy purge on use: if close to expiry, keep as-is; caller can request a new token via service-token endpoint
  return { userId: rec.userId, tenantId: rec.tenantId, user: null };
}

function _handleError(res, error, status) {
  logger.log('error', error);
  return res.status(status || 500).json({ success: false, message: (error && error.message) || String(error) });
}

// GET /api/lms/whoami
server.get('/lms/whoami', function(req, res) {
  try {
    var currentUser = usermanager.getCurrentUser && usermanager.getCurrentUser();
    if (!currentUser) {
      return res.status(401).json({ success: false, message: 'Unauthorized' });
    }
    return res.status(200).json({
      success: true,
      userId: currentUser._id,
      email: currentUser.email,
      tenantId: currentUser.tenant && currentUser.tenant._id,
      tenantName: currentUser.tenant && currentUser.tenant.name
    });
  } catch (e) {
    return _handleError(res, e);
  }
});

// POST /api/lms/service-token
server.post('/lms/service-token', function(req, res) {
  try {
    var currentUser = usermanager.getCurrentUser && usermanager.getCurrentUser();
    if (!currentUser) {
      return res.status(401).json({ success: false, message: 'Unauthorized' });
    }
    var issued = _issueToken(currentUser._id, currentUser.tenant && currentUser.tenant._id, DEFAULT_TTL_MS);
    return res.status(200).json({ success: true, token: issued.token, userId: issued.userId, tenantId: issued.tenantId, expiresAt: issued.expiresAt });
  } catch (e) {
    return _handleError(res, e);
  }
});

// GET /api/lms/:tenantId/course/:courseId/metadata
server.get('/lms/:tenantId/course/:courseId/metadata', function(req, res) {
  try {
    var auth = _resolveAuth(req, res);
    if (!auth) return res.status(401).json({ success: false, message: 'Unauthorized' });

    var tenantId = req.params.tenantId;
    var courseId = req.params.courseId;

    // Permission check
    helpers.hasCoursePermission('', auth.userId, tenantId, { _id: courseId }, function(err, hasPermission) {
      if (err || !hasPermission) {
        return _handleError(res, err || new Error('Permission denied'), 401);
      }
      // Retrieve course metadata
      app.contentmanager.getContentPlugin('course', function(error, plugin) {
        if (error) return _handleError(res, error);
        plugin.retrieve({ _id: courseId }, {}, function(error2, results) {
          if (error2) return _handleError(res, error2);
          if (!results || results.length !== 1) return _handleError(res, new Error('Course not found'), 404);
          var course = results[0];
          return res.status(200).json({
            success: true,
            id: course._id,
            title: course.title,
            description: course.body || course.description || null,
            heroImageUrl: null,
            updatedAt: course.updatedAt || course._modified || null
          });
        });
      });
    });
  } catch (e) {
    return _handleError(res, e);
  }
});

// POST /api/lms/export  { tenantId, courseId }
server.post('/lms/export', function(req, res) {
  try {
    var auth = _resolveAuth(req, res);
    if (!auth) return res.status(401).json({ success: false, message: 'Unauthorized' });
    var body = req.body || {};
    var tenantId = body.tenantId;
    var courseId = body.courseId;
    if (!tenantId || !courseId) return res.status(400).json({ success: false, message: 'tenantId and courseId are required' });

    helpers.hasCoursePermission('', auth.userId, tenantId, { _id: courseId }, function(err, hasPermission) {
      if (err || !hasPermission) return _handleError(res, err || new Error('Permission denied'), 401);

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
server.get('/lms/export/download', function(req, res) {
  try {
    var auth = _resolveAuth(req, res);
    if (!auth) return res.status(401).json({ success: false, message: 'Unauthorized' });
    var tenantId = req.query.tenantId;
    var courseId = req.query.courseId;
    if (!tenantId || !courseId) return res.status(400).json({ success: false, message: 'tenantId and courseId are required' });

    helpers.hasCoursePermission('', auth.userId, tenantId, { _id: courseId }, function(err, hasPermission) {
      if (err || !hasPermission) return _handleError(res, err || new Error('Permission denied'), 401);

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


