import express from 'express';
import type { Request, Response, NextFunction } from 'express';
import fs from 'node:fs/promises';
import path from 'node:path';
import { FernetCipher, FernetError } from './server/fernet.ts';
import {
  VaultManager,
  VaultPathError,
  formatSafeUserError,
} from './server/vault.ts';

const PORT = Number(process.env.PORT) || 3000;
const MAX_UPLOAD_BYTES = 5 * 1024 * 1024; // 5 MB text file limit

const vault = new VaultManager();

function stripEncExtension(filename: string): string {
  if (filename.toLowerCase().endsWith('.enc')) {
    const stripped = filename.slice(0, -4);
    if (stripped.toLowerCase().endsWith('.txt')) {
      return stripped;
    }
    return `${stripped || 'decrypted_output'}.txt`;
  }
  return `${filename}_decrypted.txt`;
}

async function createApp() {
  await vault.initialize();

  const app = express();
  app.use(express.json({ limit: '10mb' }));

  // Dashboard summary & recent activity
  app.get('/api/dashboard', async (_req: Request, res: Response, next: NextFunction) => {
    try {
      const [history, samples, encrypted, decrypted] = await Promise.all([
        vault.readHistory(),
        vault.listFiles('samples'),
        vault.listFiles('encrypted'),
        vault.listFiles('decrypted'),
      ]);

      const totalProcessed = history.length;
      const successfulEncryptions = history.filter(
        (h) => h.operation === 'encrypt' && h.status === 'success'
      ).length;
      const successfulDecryptions = history.filter(
        (h) => h.operation === 'decrypt' && h.status === 'success'
      ).length;
      const failedOperations = history.filter((h) => h.status === 'failed').length;

      res.json({
        stats: {
          totalProcessed,
          successfulEncryptions,
          successfulDecryptions,
          failedOperations,
        },
        recentActivity: history.slice(0, 6),
        vaultFiles: {
          samples,
          encrypted,
          decrypted,
        },
      });
    } catch (err) {
      next(err);
    }
  });

  // Full filtered activity history
  app.get('/api/history', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const operation = String(req.query.operation || 'all');
      const status = String(req.query.status || 'all');
      const q = String(req.query.q || '').trim().toLowerCase();

      const history = await vault.readHistory();
      const filtered = history.filter((item) => {
        if (operation !== 'all' && item.operation !== operation) return false;
        if (status !== 'all' && item.status !== status) return false;
        if (q) {
          const haystack = `${item.filename} ${item.outputFilename || ''} ${item.message}`.toLowerCase();
          if (!haystack.includes(q)) return false;
        }
        return true;
      });

      res.json({ records: filtered, totalCount: history.length });
    } catch (err) {
      next(err);
    }
  });

  // Generate a new 32-byte Fernet key (never logged or stored in history)
  app.post('/api/keys/generate', async (_req: Request, res: Response, next: NextFunction) => {
    try {
      const key = FernetCipher.generateKey();
      await vault.writeAuditLog('INFO', 'KEY_GENERATED', 'New 256-bit Fernet symmetric key generated in memory.');
      res.json({
        key,
        algorithm: 'Fernet (AES-128-CBC + HMAC-SHA256)',
        keyBytes: 32,
      });
    } catch (err) {
      next(err);
    }
  });

  // Validate an existing Fernet key without logging or storing it
  app.post('/api/keys/validate', async (req: Request, res: Response) => {
    try {
      const rawKey = typeof req.body?.key === 'string' ? req.body.key : '';
      FernetCipher.parseKey(rawKey);
      await vault.writeAuditLog('INFO', 'KEY_VALIDATED', 'User-supplied Fernet key validated successfully.');
      res.json({ valid: true, keyBytes: 32 });
    } catch (err) {
      const safe = formatSafeUserError(err);
      await vault.writeAuditLog('WARNING', 'KEY_VALIDATION_FAILED', safe.message).catch(() => {});
      res.status(safe.statusCode).json({ valid: false, error: safe.message });
    }
  });

  // Save a key file to vault_data/keys without silently overwriting existing key files
  app.post('/api/keys/save', async (req: Request, res: Response) => {
    try {
      const rawKey = typeof req.body?.key === 'string' ? req.body.key.trim() : '';
      const desiredName = typeof req.body?.filename === 'string' && req.body.filename.trim()
        ? req.body.filename.trim()
        : 'securevault.key';

      FernetCipher.parseKey(rawKey);

      const normalizedName = desiredName.toLowerCase().endsWith('.key')
        ? desiredName
        : `${desiredName}.key`;

      const { safeName } = vault.resolveSafePath(vault.keysDir, normalizedName);
      const unique = await vault.resolveUniqueOutputPath(vault.keysDir, safeName);

      await fs.writeFile(unique.fullPath, `${rawKey}\n`, { encoding: 'utf8', mode: 0o600 });
      await vault.writeAuditLog(
        'INFO',
        'KEY_SAVED',
        `Key file saved to ${unique.relativePath} (key value omitted).`
      );

      res.json({
        savedFilename: unique.filename,
        savedLocation: unique.relativePath,
        renamedDueToDuplicate: unique.renamedDueToDuplicate,
      });
    } catch (err) {
      const safe = formatSafeUserError(err);
      res.status(safe.statusCode).json({ error: safe.message });
    }
  });

  // List vault files by category
  app.get('/api/vault/files', async (_req: Request, res: Response, next: NextFunction) => {
    try {
      const [samples, encrypted, decrypted, keys] = await Promise.all([
        vault.listFiles('samples'),
        vault.listFiles('encrypted'),
        vault.listFiles('decrypted'),
        vault.listFiles('keys'),
      ]);
      res.json({ samples, encrypted, decrypted, keys });
    } catch (err) {
      next(err);
    }
  });

  // Load or download a confined vault file
  app.get('/api/vault/download', async (req: Request, res: Response) => {
    try {
      const category = String(req.query.category || '');
      const filename = String(req.query.filename || '');
      const inline = req.query.inline === 'true';

      if (category !== 'samples' && category !== 'encrypted' && category !== 'decrypted') {
        res.status(400).json({ error: 'Invalid vault storage category requested.' });
        return;
      }

      const dir = vault.getDirectoryForCategory(category);
      const { safeName, fullPath } = vault.resolveSafePath(dir, filename);
      const buffer = await fs.readFile(fullPath);

      if (inline) {
        res.json({
          filename: safeName,
          sizeBytes: buffer.length,
          contentBase64: buffer.toString('base64'),
          textPreview: buffer.toString('utf8').slice(0, 8000),
        });
        return;
      }

      res.setHeader('Content-Disposition', `attachment; filename="${safeName}"`);
      res.setHeader('Content-Type', 'application/octet-stream');
      res.send(buffer);
    } catch (err) {
      const safe = formatSafeUserError(err);
      res.status(safe.statusCode).json({ error: safe.message });
    }
  });

  // Encrypt a .txt file -> .enc
  app.post('/api/encrypt', async (req: Request, res: Response) => {
    const rawFilename = typeof req.body?.filename === 'string' ? req.body.filename.trim() : '';
    const vaultSampleName =
      typeof req.body?.vaultSampleName === 'string' ? req.body.vaultSampleName.trim() : '';
    const contentBase64 = typeof req.body?.contentBase64 === 'string' ? req.body.contentBase64 : '';
    const key = typeof req.body?.key === 'string' ? req.body.key : '';

    let effectiveFilename = rawFilename || vaultSampleName || 'untitled';
    let inputSizeBytes = 0;

    try {
      let plaintextBuffer: Buffer;

      if (vaultSampleName) {
        const { safeName, fullPath } = vault.resolveSafePath(vault.samplesDir, vaultSampleName);
        effectiveFilename = safeName;
        plaintextBuffer = await fs.readFile(fullPath);
      } else {
        if (!rawFilename) {
          throw new VaultPathError('No file selected. Please select or drop a .txt file to encrypt.');
        }
        const { safeName } = vault.resolveSafePath(vault.encryptedDir, rawFilename);
        effectiveFilename = safeName;
        if (!contentBase64) {
          throw new FernetError('EMPTY_INPUT', 'Cannot encrypt an empty file. Please select a non-empty .txt file.');
        }
        plaintextBuffer = Buffer.from(contentBase64, 'base64');
      }

      inputSizeBytes = plaintextBuffer.length;

      if (!effectiveFilename.toLowerCase().endsWith('.txt')) {
        throw new VaultPathError(
          `Unsupported file format for "${effectiveFilename}". Only .txt files are supported for encryption.`
        );
      }

      if (inputSizeBytes === 0) {
        throw new FernetError('EMPTY_INPUT', 'Cannot encrypt an empty file (0 bytes).');
      }

      if (inputSizeBytes > MAX_UPLOAD_BYTES) {
        throw new VaultPathError('File exceeds the 5 MB maximum size limit for encryption.');
      }

      const encryptedBuffer = FernetCipher.encrypt(plaintextBuffer, key);
      const desiredOutputName = `${effectiveFilename}.enc`;
      const outputTarget = await vault.resolveUniqueOutputPath(vault.encryptedDir, desiredOutputName);

      await fs.writeFile(outputTarget.fullPath, encryptedBuffer, { mode: 0o644 });

      const detailMessage = outputTarget.renamedDueToDuplicate
        ? `Encrypted successfully (renamed to ${outputTarget.filename} to prevent overwriting existing file).`
        : 'Encrypted successfully using Fernet (AES-128-CBC + HMAC-SHA256).';

      await Promise.all([
        vault.writeAuditLog(
          'INFO',
          'ENCRYPT_SUCCESS',
          `Input="${effectiveFilename}" (${inputSizeBytes} B) -> Output="${outputTarget.relativePath}" (${encryptedBuffer.length} B)`
        ),
        vault.appendHistory({
          filename: effectiveFilename,
          operation: 'encrypt',
          status: 'success',
          outputFilename: outputTarget.filename,
          outputLocation: outputTarget.relativePath,
          inputSizeBytes,
          outputSizeBytes: encryptedBuffer.length,
          message: detailMessage,
        }),
      ]);

      res.json({
        status: 'success',
        inputFilename: effectiveFilename,
        outputFilename: outputTarget.filename,
        outputLocation: outputTarget.relativePath,
        inputSizeBytes,
        outputSizeBytes: encryptedBuffer.length,
        renamedDueToDuplicate: outputTarget.renamedDueToDuplicate,
        message: detailMessage,
        tokenPreview: encryptedBuffer.toString('ascii').slice(0, 140),
      });
    } catch (err) {
      const safe = formatSafeUserError(err);
      await Promise.all([
        vault.writeAuditLog(
          'ERROR',
          'ENCRYPT_FAILED',
          `Input="${effectiveFilename}" - ${safe.message}`
        ).catch(() => {}),
        vault.appendHistory({
          filename: effectiveFilename || 'Unknown file',
          operation: 'encrypt',
          status: 'failed',
          outputFilename: null,
          outputLocation: null,
          inputSizeBytes,
          outputSizeBytes: null,
          message: safe.message,
        }).catch(() => {}),
      ]);

      res.status(safe.statusCode).json({ error: safe.message });
    }
  });

  // Decrypt an .enc file -> .txt
  app.post('/api/decrypt', async (req: Request, res: Response) => {
    const rawFilename = typeof req.body?.filename === 'string' ? req.body.filename.trim() : '';
    const vaultEncryptedName =
      typeof req.body?.vaultEncryptedName === 'string' ? req.body.vaultEncryptedName.trim() : '';
    const contentBase64 = typeof req.body?.contentBase64 === 'string' ? req.body.contentBase64 : '';
    const key = typeof req.body?.key === 'string' ? req.body.key : '';

    let effectiveFilename = rawFilename || vaultEncryptedName || 'untitled';
    let inputSizeBytes = 0;

    try {
      let tokenBuffer: Buffer;

      if (vaultEncryptedName) {
        const { safeName, fullPath } = vault.resolveSafePath(vault.encryptedDir, vaultEncryptedName);
        effectiveFilename = safeName;
        tokenBuffer = await fs.readFile(fullPath);
      } else {
        if (!rawFilename) {
          throw new VaultPathError('No file selected. Please select or drop an encrypted .enc file to decrypt.');
        }
        const { safeName } = vault.resolveSafePath(vault.decryptedDir, rawFilename);
        effectiveFilename = safeName;
        if (!contentBase64) {
          throw new FernetError('EMPTY_INPUT', 'The selected encrypted file is empty (0 bytes).');
        }
        tokenBuffer = Buffer.from(contentBase64, 'base64');
      }

      inputSizeBytes = tokenBuffer.length;

      if (!effectiveFilename.toLowerCase().endsWith('.enc')) {
        throw new VaultPathError(
          `Unsupported file format for "${effectiveFilename}". Please select a .enc file for decryption.`
        );
      }

      if (inputSizeBytes === 0) {
        throw new FernetError('EMPTY_INPUT', 'The selected encrypted file is empty (0 bytes).');
      }

      const { plaintext, encryptedAt } = FernetCipher.decrypt(tokenBuffer, key);
      const desiredOutputName = stripEncExtension(effectiveFilename);
      const outputTarget = await vault.resolveUniqueOutputPath(vault.decryptedDir, desiredOutputName);

      await fs.writeFile(outputTarget.fullPath, plaintext, { mode: 0o644 });

      const detailMessage = outputTarget.renamedDueToDuplicate
        ? `Decrypted successfully (saved as ${outputTarget.filename} to preserve existing output).`
        : 'Decrypted and HMAC-verified successfully.';

      await Promise.all([
        vault.writeAuditLog(
          'INFO',
          'DECRYPT_SUCCESS',
          `Input="${effectiveFilename}" (${inputSizeBytes} B) -> Output="${outputTarget.relativePath}" (${plaintext.length} B)`
        ),
        vault.appendHistory({
          filename: effectiveFilename,
          operation: 'decrypt',
          status: 'success',
          outputFilename: outputTarget.filename,
          outputLocation: outputTarget.relativePath,
          inputSizeBytes,
          outputSizeBytes: plaintext.length,
          message: detailMessage,
        }),
      ]);

      res.json({
        status: 'success',
        inputFilename: effectiveFilename,
        outputFilename: outputTarget.filename,
        outputLocation: outputTarget.relativePath,
        inputSizeBytes,
        outputSizeBytes: plaintext.length,
        renamedDueToDuplicate: outputTarget.renamedDueToDuplicate,
        encryptedAt,
        message: detailMessage,
        decryptedPreview: plaintext.toString('utf8').slice(0, 8000),
      });
    } catch (err) {
      const safe = formatSafeUserError(err);
      await Promise.all([
        vault.writeAuditLog(
          'ERROR',
          'DECRYPT_FAILED',
          `Input="${effectiveFilename}" - ${safe.message}`
        ).catch(() => {}),
        vault.appendHistory({
          filename: effectiveFilename || 'Unknown file',
          operation: 'decrypt',
          status: 'failed',
          outputFilename: null,
          outputLocation: null,
          inputSizeBytes,
          outputSizeBytes: null,
          message: safe.message,
        }).catch(() => {}),
      ]);

      res.status(safe.statusCode).json({ error: safe.message });
    }
  });

  // Global error handler — never expose stack traces
  app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    const safe = formatSafeUserError(err);
    vault.writeAuditLog('ERROR', 'UNEXPECTED_ERROR', safe.message).catch(() => {});
    res.status(safe.statusCode).json({ error: safe.message });
  });

  if (process.env.NODE_ENV === 'production') {
    const distDir = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distDir));
    app.get('*splat', (_req: Request, res: Response) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  } else {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`SecureVault server running on http://0.0.0.0:${PORT}`);
  });
}

createApp().catch((err) => {
  console.error('Failed to start SecureVault server:', err instanceof Error ? err.message : err);
  process.exit(1);
});
