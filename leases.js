/**
 * File upload configuration using Multer
 */
const multer = require('multer');
const path   = require('path');
const fs     = require('fs');

const UPLOAD_DIR = process.env.UPLOAD_DIR || './backend/uploads';
const MAX_MB     = parseInt(process.env.MAX_FILE_SIZE_MB || '10', 10);

// Ensure upload directories exist
['units', 'maintenance', 'documents', 'avatars'].forEach(sub => {
  const dir = path.join(UPLOAD_DIR, sub);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

function makeStorage(subfolder) {
  return multer.diskStorage({
    destination: (req, file, cb) => {
      cb(null, path.join(UPLOAD_DIR, subfolder));
    },
    filename: (req, file, cb) => {
      const ext  = path.extname(file.originalname).toLowerCase();
      const name = `${Date.now()}-${Math.round(Math.random() * 1e6)}${ext}`;
      cb(null, name);
    }
  });
}

function imageFilter(req, file, cb) {
  const allowed = ['.jpg', '.jpeg', '.png', '.webp', '.gif'];
  const ext = path.extname(file.originalname).toLowerCase();
  if (allowed.includes(ext)) {
    cb(null, true);
  } else {
    cb(new Error('Only image files are allowed (jpg, png, webp, gif)'));
  }
}

function docFilter(req, file, cb) {
  const allowed = ['.pdf', '.doc', '.docx', '.jpg', '.jpeg', '.png'];
  const ext = path.extname(file.originalname).toLowerCase();
  if (allowed.includes(ext)) {
    cb(null, true);
  } else {
    cb(new Error('Only PDF and image files allowed'));
  }
}

const unitPhotoUpload = multer({
  storage: makeStorage('units'),
  fileFilter: imageFilter,
  limits: { fileSize: MAX_MB * 1024 * 1024 }
});

const maintenancePhotoUpload = multer({
  storage: makeStorage('maintenance'),
  fileFilter: imageFilter,
  limits: { fileSize: MAX_MB * 1024 * 1024 }
});

const documentUpload = multer({
  storage: makeStorage('documents'),
  fileFilter: docFilter,
  limits: { fileSize: MAX_MB * 1024 * 1024 }
});

const avatarUpload = multer({
  storage: makeStorage('avatars'),
  fileFilter: imageFilter,
  limits: { fileSize: 5 * 1024 * 1024 }
});

module.exports = { unitPhotoUpload, maintenancePhotoUpload, documentUpload, avatarUpload };
