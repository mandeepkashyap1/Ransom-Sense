/**
 * OK Sentinel — Background File Download Watcher & Real-Time Heuristic Security Scanner
 * Continuously monitors downloaded files, calculates Shannon entropy, checks executable signatures,
 * computes SHA-256 hashes, detects ransomware indicators, auto-quarantines threats, and logs findings.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const EventEmitter = require('events');

class FileSecurityWatcher extends EventEmitter {
  constructor(options = {}) {
    super();
    
    // Default monitored locations: local ./monitored_downloads and user Downloads folder
    const userHome = process.env.USERPROFILE || process.env.HOME || 'C:\\Users\\Mande';
    const userDownloads = path.join(userHome, 'Downloads');
    const localWatchDir = path.join(__dirname, 'monitored_downloads');
    const quarantineDir = path.join(__dirname, 'quarantine');

    this.watchDirs = [localWatchDir];
    if (fs.existsSync(userDownloads)) {
      this.watchDirs.push(userDownloads);
    }

    this.quarantineDir = quarantineDir;
    this.logsDir = path.join(__dirname, 'logs');
    this.serverLogFile = path.join(this.logsDir, 'server.log');
    this.serverJsonlFile = path.join(this.logsDir, 'server_logs.jsonl');

    this.scannedHistory = [];
    this.processedFiles = new Set();
    this.isWatching = false;
    this.watchers = [];

    // Ensure required directories exist
    this.initDirectories();
  }

  initDirectories() {
    this.watchDirs.forEach(dir => {
      if (!fs.existsSync(dir)) {
        try { fs.mkdirSync(dir, { recursive: true }); } catch (e) {}
      }
    });

    if (!fs.existsSync(this.quarantineDir)) {
      try { fs.mkdirSync(this.quarantineDir, { recursive: true }); } catch (e) {}
    }
    if (!fs.existsSync(this.logsDir)) {
      try { fs.mkdirSync(this.logsDir, { recursive: true }); } catch (e) {}
    }
  }

  start() {
    if (this.isWatching) return;
    this.isWatching = true;

    console.log(`[FILE WATCHER] Starting background monitoring on:`);
    this.watchDirs.forEach(dir => {
      console.log(`  - ${dir}`);
      try {
        const watcher = fs.watch(dir, (eventType, filename) => {
          if (!filename) return;
          const filePath = path.join(dir, filename);
          this.handleFileEvent(filePath, eventType);
        });
        this.watchers.push(watcher);
      } catch (err) {
        console.warn(`[FILE WATCHER] Warning: Could not attach fs.watch on ${dir}:`, err.message);
      }
    });

    // Also run periodic scan check every 10 seconds for any missed downloads
    this.pollingInterval = setInterval(() => this.scanAllDirectories(), 10000);
    this.logServerMessage('SYSTEM', `Background File Watcher active. Monitoring ${this.watchDirs.length} folders.`);
  }

  stop() {
    this.isWatching = false;
    this.watchers.forEach(w => w.close());
    this.watchers = [];
    if (this.pollingInterval) clearInterval(this.pollingInterval);
    console.log('[FILE WATCHER] Background watcher stopped.');
  }

  scanAllDirectories() {
    this.watchDirs.forEach(dir => {
      if (!fs.existsSync(dir)) return;
      try {
        const files = fs.readdirSync(dir);
        files.forEach(file => {
          const filePath = path.join(dir, file);
          this.handleFileEvent(filePath, 'poll');
        });
      } catch (e) {}
    });
  }

  handleFileEvent(filePath, eventType) {
    if (!fs.existsSync(filePath)) return;

    try {
      const stats = fs.statSync(filePath);
      if (stats.isDirectory()) return; // ignore subdirectories
      
      // Prevent rapid duplicate processing of same file within 5 seconds
      const fileKey = `${filePath}_${stats.mtimeMs}_${stats.size}`;
      if (this.processedFiles.has(fileKey)) return;
      this.processedFiles.add(fileKey);

      // Clean old key cache
      if (this.processedFiles.size > 1000) this.processedFiles.clear();

      // Run Heuristic Scan on new/modified file!
      this.scanFile(filePath, stats);
    } catch (err) {
      // File might be temporarily locked while browser is writing download stream
    }
  }

  scanFile(filePath, stats) {
    const filename = path.basename(filePath);
    const ext = path.extname(filename).toLowerCase();
    
    // Ignore temporary browser partial download extensions
    if (ext === '.tmp' || ext === '.crdownload' || ext === '.part' || filename.startsWith('.')) {
      return;
    }

    try {
      // Read file bytes (limit max analysis buffer to 10MB for speed)
      const bufferSize = Math.min(stats.size, 10 * 1024 * 1024);
      const fd = fs.openSync(filePath, 'r');
      const buffer = Buffer.alloc(bufferSize);
      fs.readSync(fd, buffer, 0, bufferSize, 0);
      fs.closeSync(fd);

      // 1. Calculate Shannon Entropy (0.0 to 8.0)
      const entropy = this.calculateShannonEntropy(buffer);

      // 2. Compute SHA-256 Hash
      const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');

      // 3. Perform Static Heuristic Analysis
      const heuristics = this.evaluateHeuristics(filename, ext, buffer, entropy, stats.size);

      const scanResult = {
        id: `scan_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`,
        timestamp: new Date().toISOString(),
        filePath,
        filename,
        extension: ext,
        fileSize: stats.size,
        fileSizeFormatted: this.formatBytes(stats.size),
        sha256,
        entropy: parseFloat(entropy.toFixed(3)),
        heuristics,
        threatLevel: heuristics.threatLevel, // 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS_RANSOMWARE_RISK'
        riskScore: heuristics.riskScore,     // 0 to 100
        quarantined: false
      };

      // Auto Quarantine if high-risk malicious ransomware signature detected
      if (heuristics.threatLevel === 'MALICIOUS_RANSOMWARE_RISK') {
        scanResult.quarantined = this.quarantineFile(filePath, filename);
      }

      // Add to History
      this.scannedHistory.unshift(scanResult);
      if (this.scannedHistory.length > 200) this.scannedHistory.pop();

      // Log Findings to server.log & server_logs.jsonl
      const logType = heuristics.threatLevel === 'CLEAN' ? 'INFO' : (heuristics.threatLevel === 'SUSPICIOUS' ? 'WARN' : 'ERROR');
      const logMsg = `🛡️ [FILE WATCHER] Scanned "${filename}" (${scanResult.fileSizeFormatted}) | Entropy: ${scanResult.entropy} | Threat: ${scanResult.threatLevel} (Risk Score: ${scanResult.riskScore}/100) | SHA-256: ${sha256.substring(0, 12)}...`;
      this.logServerMessage(logType, logMsg);

      // Emit event for real-time SSE streaming to browser
      this.emit('fileScanned', scanResult);

      return scanResult;
    } catch (err) {
      console.warn(`[FILE WATCHER] Error scanning file ${filename}:`, err.message);
      return null;
    }
  }

  // Calculate Shannon Entropy (Entropy > 7.5 indicates compressed binary, packed code, or encrypted ransomware payload)
  calculateShannonEntropy(buffer) {
    if (!buffer || buffer.length === 0) return 0;

    const frequencies = new Array(256).fill(0);
    for (let i = 0; i < buffer.length; i++) {
      frequencies[buffer[i]]++;
    }

    let entropy = 0;
    const len = buffer.length;
    for (let i = 0; i < 256; i++) {
      if (frequencies[i] > 0) {
        const p = frequencies[i] / len;
        entropy -= p * Math.log2(p);
      }
    }
    return entropy;
  }

  // Heuristic Rule Engine
  evaluateHeuristics(filename, ext, buffer, entropy, fileSize) {
    let riskScore = 0;
    const flags = [];

    // Rule 1: Double Extension Trick (e.g. invoice.pdf.exe, report.docx.vbs)
    const parts = filename.split('.');
    if (parts.length > 2) {
      const secondLastExt = parts[parts.length - 2].toLowerCase();
      const dangerousExts = ['.exe', '.vbs', '.bat', '.cmd', '.ps1', '.scr', '.js', '.wsf', '.hta'];
      const docExts = ['pdf', 'docx', 'xlsx', 'pptx', 'jpg', 'png', 'txt'];

      if (docExts.includes(secondLastExt) && dangerousExts.includes(ext)) {
        riskScore += 45;
        flags.push('CRITICAL: Double extension trick detected (masquerading document file)');
      }
    }

    // Rule 2: High Entropy Encryption Check (Ransomware Indicator)
    if (entropy > 7.6) {
      riskScore += 35;
      flags.push('WARNING: Very high entropy (> 7.6) — indicates file packing or AES encryption payload');
    } else if (entropy > 7.2) {
      riskScore += 15;
      flags.push('INFO: Elevated entropy (> 7.2) — file is compressed or compiled binary');
    }

    // Rule 3: Executable Header Verification (PE MZ Header)
    const isPEExecutable = buffer.length > 2 && buffer[0] === 0x4D && buffer[1] === 0x5A; // "MZ"
    if (isPEExecutable) {
      flags.push('INFO: Windows Portable Executable (PE) binary header verified');
      if (ext !== '.exe' && ext !== '.dll' && ext !== '.sys') {
        riskScore += 40;
        flags.push('CRITICAL: Binary executable masquerading under non-exe extension (' + ext + ')');
      } else {
        riskScore += 15;
      }
    }

    // Rule 4: Suspicious Script Commands Check (PowerShell / VBS / BAT)
    const fileContentStr = buffer.toString('utf8', 0, Math.min(buffer.length, 64 * 1024)).toLowerCase();
    const suspiciousKeywords = [
      'cmd.exe /c', 'powershell -enc', 'powershell -encodedcommand',
      'vssadmin delete shadows', 'wbadmin delete catalog',
      'bcedit /set', 'wscript.shell', 'net stop', 'cryptoapi',
      'encrypt', 'ransom', 'bitcoin', 'torbrowser'
    ];

    let foundKeywordCount = 0;
    suspiciousKeywords.forEach(kw => {
      if (fileContentStr.includes(kw)) {
        foundKeywordCount++;
        flags.push(`SUSPICIOUS KEYWORD: Contains command pattern "${kw}"`);
      }
    });

    if (foundKeywordCount > 0) {
      riskScore += Math.min(foundKeywordCount * 20, 50);
    }

    // Rule 5: Zero-Byte / Corrupted Download
    if (fileSize === 0) {
      flags.push('INFO: Zero-byte file detected');
    }

    // Determine Threat Level Category
    let threatLevel = 'CLEAN';
    if (riskScore >= 65) {
      threatLevel = 'MALICIOUS_RANSOMWARE_RISK';
    } else if (riskScore >= 30) {
      threatLevel = 'SUSPICIOUS';
    }

    return {
      riskScore: Math.min(riskScore, 100),
      threatLevel,
      flags,
      isPEExecutable
    };
  }

  // Quarantine High Risk File
  quarantineFile(filePath, filename) {
    try {
      const destPath = path.join(this.quarantineDir, `${Date.now()}_QUARANTINED_${filename}`);
      fs.renameSync(filePath, destPath);
      this.logServerMessage('WARN', `🔒 [QUARANTINE] Automatically isolated malicious file "${filename}" to ${destPath}`);
      return true;
    } catch (err) {
      console.warn(`[QUARANTINE] Could not move file ${filename}:`, err.message);
      return false;
    }
  }

  logServerMessage(type, msg) {
    const timestamp = new Date().toISOString();
    const formattedLine = `[${timestamp}] [${type}] [FILE_WATCHER] [Security Engine] ${msg}\n`;
    try {
      fs.appendFileSync(this.serverLogFile, formattedLine, 'utf8');
      const jsonlRecord = JSON.stringify({ timestamp, source: 'FILE_WATCHER', type, workflowName: 'Security Engine', msg }) + '\n';
      fs.appendFileSync(this.serverJsonlFile, jsonlRecord, 'utf8');
    } catch (e) {}
  }

  formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }
}

module.exports = FileSecurityWatcher;
