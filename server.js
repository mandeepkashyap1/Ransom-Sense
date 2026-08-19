/**
 * OK Sentinel — Backend Security Operations Server
 * Handles static file serving, real-time log persistence, file scan API, SSE streaming, and workflow storage.
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');
const crypto = require('crypto');
const FileSecurityWatcher = require('./fileWatcher');

const PORT = 8080;
const PUBLIC_DIR = __dirname;
const LOGS_DIR = path.join(__dirname, 'logs');
const WORKFLOWS_DIR = path.join(__dirname, 'workflows');

const SERVER_LOG_FILE = path.join(LOGS_DIR, 'server.log');
const SERVER_JSONL_FILE = path.join(LOGS_DIR, 'server_logs.jsonl');

// Initialize & Start Background File Watcher Security Daemon
const fileSecurityWatcher = new FileSecurityWatcher();
fileSecurityWatcher.start();

// Active SSE client connections for real-time security stream
const sseClients = new Set();

fileSecurityWatcher.on('fileScanned', (scanResult) => {
  const sseData = `data: ${JSON.stringify(scanResult)}\n\n`;
  sseClients.forEach(client => {
    try { client.write(sseData); } catch (e) { sseClients.delete(client); }
  });
});

// Ensure storage directories exist
if (!fs.existsSync(LOGS_DIR)) {
  fs.mkdirSync(LOGS_DIR, { recursive: true });
}
if (!fs.existsSync(WORKFLOWS_DIR)) {
  fs.mkdirSync(WORKFLOWS_DIR, { recursive: true });
}

// MIME types for static files
const MIME_TYPES = {
  '.html': 'text/html; charset=UTF-8',
  '.css': 'text/css; charset=UTF-8',
  '.js': 'application/javascript; charset=UTF-8',
  '.json': 'application/json; charset=UTF-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.ico': 'image/x-icon',
  '.svg': 'image/svg+xml'
};

const server = http.createServer((req, res) => {
  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;
  const method = req.method.toUpperCase();

  // CORS Headers for browser requests
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  // =========================================================================
  // API ENDPOINTS FOR FILE SCANNER & SECURITY DAEMON
  // =========================================================================

  // GET /api/scanner/status — Return background watcher health
  if (pathname === '/api/scanner/status' && method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      success: true,
      isWatching: fileSecurityWatcher.isWatching,
      monitoredDirectories: fileSecurityWatcher.watchDirs,
      totalScanned: fileSecurityWatcher.scannedHistory.length,
      quarantineDir: fileSecurityWatcher.quarantineDir
    }));
    return;
  }

  // GET /api/scanner/history — Return scanned file history
  if (pathname === '/api/scanner/history' && method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      success: true,
      history: fileSecurityWatcher.scannedHistory
    }));
    return;
  }

  // GET /api/scanner/stream — Real-time Server-Sent Events (SSE) stream for download scans
  if (pathname === '/api/scanner/stream' && method === 'GET') {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive'
    });
    res.write('retry: 5000\n\n');
    sseClients.add(res);

    req.on('close', () => {
      sseClients.delete(res);
    });
    return;
  }

  // POST /api/scanner/simulate — Create a real test download file in monitored_downloads
  if (pathname === '/api/scanner/simulate' && method === 'POST') {
    let body = '';
    req.on('data', chunk => { body += chunk.toString(); });
    req.on('end', () => {
      try {
        const { type } = JSON.parse(body || '{}');
        const monitoredDir = path.join(__dirname, 'monitored_downloads');
        if (!fs.existsSync(monitoredDir)) {
          fs.mkdirSync(monitoredDir, { recursive: true });
        }

        let filename = '';
        let fileContent = Buffer.from('Standard clean document file content for security test.');
        
        if (type === 'ransomware') {
          filename = `urgent_invoice_document_${Date.now()}.pdf.exe`;
          // Create high entropy buffer (>7.8) to simulate ransomware payload
          fileContent = crypto.randomBytes(50 * 1024);
        } else if (type === 'suspicious') {
          filename = `financial_statement_${Date.now()}.docx`;
          // Medium entropy buffer with macro script keywords
          fileContent = Buffer.from('AutoOpen macro execution: Powershell.exe -ExecutionPolicy Bypass -Command ' + crypto.randomBytes(512).toString('hex'));
        } else {
          filename = `annual_report_${Date.now()}.pdf`;
          fileContent = Buffer.from('%PDF-1.5\nClean corporate annual report document text\n%%EOF');
        }

        const filePath = path.join(monitoredDir, filename);
        fs.writeFileSync(filePath, fileContent);
        console.log(`[SIMULATION TEST] Created file: ${filePath}`);

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, filename, filePath }));
      } catch (err) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: err.message }));
      }
    });
    return;
  }

  // POST /api/scanner/scan-now — Manually scan a specified file path
  if (pathname === '/api/scanner/scan-now' && method === 'POST') {
    let body = '';
    req.on('data', chunk => { body += chunk.toString(); });
    req.on('end', () => {
      try {
        const { filePath } = JSON.parse(body);
        if (!filePath || !fs.existsSync(filePath)) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: false, error: 'File path does not exist' }));
          return;
        }
        const stats = fs.statSync(filePath);
        const result = fileSecurityWatcher.scanFile(filePath, stats);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, scanResult: result }));
      } catch (err) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: err.message }));
      }
    });
    return;
  }

  // =========================================================================
  // API ENDPOINTS
  // =========================================================================

  // POST /api/logs — Save a new server log entry to disk
  if (pathname === '/api/logs' && method === 'POST') {
    let body = '';
    req.on('data', chunk => { body += chunk.toString(); });
    req.on('end', () => {
      try {
        const logData = JSON.parse(body);
        const timestamp = logData.timestamp || new Date().toISOString();
        const source = logData.source || 'CLIENT';
        const type = (logData.type || 'info').toUpperCase();
        const msg = logData.msg || '';
        const workflowName = logData.workflowName || 'Default Workflow';

        // 1. Format human-readable line for server.log
        const formattedLine = `[${timestamp}] [${type}] [${source}] [${workflowName}] ${msg}\n`;
        fs.appendFileSync(SERVER_LOG_FILE, formattedLine, 'utf8');

        // 2. Format structured JSON Line for server_logs.jsonl
        const jsonlRecord = JSON.stringify({ timestamp, source, type, workflowName, msg }) + '\n';
        fs.appendFileSync(SERVER_JSONL_FILE, jsonlRecord, 'utf8');

        // Log to backend console as well
        console.log(`[LOG SAVED] [${type}] ${source}: ${msg.substring(0, 80)}`);

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, timestamp, file: 'logs/server.log' }));
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: 'Invalid JSON payload: ' + err.message }));
      }
    });
    return;
  }

  // GET /api/logs — Fetch saved server logs
  if (pathname === '/api/logs' && method === 'GET') {
    try {
      if (fs.existsSync(SERVER_LOG_FILE)) {
        const logsContent = fs.readFileSync(SERVER_LOG_FILE, 'utf8');
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=UTF-8' });
        res.end(logsContent);
      } else {
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=UTF-8' });
        res.end('[INFO] Server log file is empty.\n');
      }
    } catch (err) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: false, error: err.message }));
    }
    return;
  }

  // DELETE /api/logs — Clear server log file
  if (pathname === '/api/logs' && method === 'DELETE') {
    try {
      if (fs.existsSync(SERVER_LOG_FILE)) fs.writeFileSync(SERVER_LOG_FILE, '');
      if (fs.existsSync(SERVER_JSONL_FILE)) fs.writeFileSync(SERVER_JSONL_FILE, '');
      console.log('[LOGS CLEARED] Server log files cleared by user.');
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, message: 'Server logs cleared successfully' }));
    } catch (err) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: false, error: err.message }));
    }
    return;
  }

  // POST /api/workflows — Save a workflow blueprint file
  if (pathname === '/api/workflows' && method === 'POST') {
    let body = '';
    req.on('data', chunk => { body += chunk.toString(); });
    req.on('end', () => {
      try {
        const data = JSON.parse(body);
        const safeName = (data.name || 'workflow').toLowerCase().replace(/[^a-z0-9_-]/g, '_');
        const filename = `${safeName}_${Date.now()}.json`;
        const filePath = path.join(WORKFLOWS_DIR, filename);

        fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
        console.log(`[WORKFLOW SAVED] Saved to workflows/${filename}`);

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, filename, path: `workflows/${filename}` }));
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: err.message }));
      }
    });
    return;
  }

  // GET /api/workflows — List saved workflows
  if (pathname === '/api/workflows' && method === 'GET') {
    try {
      const files = fs.readdirSync(WORKFLOWS_DIR).filter(f => f.endsWith('.json'));
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, workflows: files }));
    } catch (err) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: false, error: err.message }));
    }
    return;
  }

  // =========================================================================
  // STATIC FILE SERVER
  // =========================================================================
  let reqFilePath = pathname === '/' ? '/main.html' : pathname;
  let safePath = path.normalize(reqFilePath).replace(/^(\.\.[\/\\])+/, '');
  let filePath = path.join(PUBLIC_DIR, safePath);

  fs.stat(filePath, (err, stats) => {
    if (err || !stats.isFile()) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('404 Not Found');
      return;
    }

    const ext = path.extname(filePath).toLowerCase();
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';

    res.writeHead(200, { 'Content-Type': contentType });
    const stream = fs.createReadStream(filePath);
    stream.pipe(res);
  });
});

server.listen(PORT, () => {
  console.log(``);
  console.log(`  \x1b[36m███████████████████████████████████████████████████\x1b[0m`);
  console.log(`  \x1b[36m█\x1b[0m  OK Sentinel — Security Operations Server   \x1b[36m█\x1b[0m`);
  console.log(`  \x1b[36m█\x1b[0m  URL:  http://localhost:${PORT}/main.html        \x1b[36m█\x1b[0m`);
  console.log(`  \x1b[36m█\x1b[0m  API:  http://localhost:${PORT}/api/logs           \x1b[36m█\x1b[0m`);
  console.log(`  \x1b[36m█\x1b[0m  Log:  ${SERVER_LOG_FILE}`);
  console.log(`  \x1b[36m███████████████████████████████████████████████████\x1b[0m`);
  console.log(``);
});
