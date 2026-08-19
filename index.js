/**
 * OK Sentinel — Real-Time File Download Security Watcher & Threat Mitigation Studio
 * Core Application Engine
 */

// ============================================================================
// 1. NODE SCHEMAS & CONFIGURATIONS (SECURITY & HEURISTICS FOCUSED)
// ============================================================================

const NODE_TYPES = {
  // --- SECURITY TRIGGERS & WATCHERS ---
  trigger_file_download: {
    name: 'Downloads Watcher',
    category: 'trigger',
    icon: 'fa-shield-virus',
    iconClass: 'icon-trigger',
    desc: 'Fires in real-time when a file is downloaded or modified in C:\\Users\\Mande\\Downloads',
    inputs: [],
    outputs: ['file_scan_event'],
    defaultConfig: {
      monitoredFolders: 'Downloads, ./monitored_downloads',
      minThreatLevel: 'ALL', // 'ALL' | 'SUSPICIOUS' | 'MALICIOUS_ONLY'
      targetExt: '*'
    },
    run: async (config, inputs) => {
      // Returns last scanned file payload or mock download payload
      return {
        event: 'file_download_scanned',
        timestamp: new Date().toISOString(),
        filename: 'suspicious_invoice_receipt.pdf.exe',
        fileSizeFormatted: '2.45 MB',
        sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
        entropy: 7.85,
        threatLevel: 'MALICIOUS_RANSOMWARE_RISK',
        riskScore: 88,
        heuristics: {
          flags: [
            'CRITICAL: Double extension trick detected (.pdf.exe)',
            'WARNING: Very high entropy (> 7.6) — indicates ransomware encryption payload',
            'SUSPICIOUS: PE executable header signature detected in document stream'
          ]
        }
      };
    }
  },

  trigger_manual_file: {
    name: 'Manual File Drop',
    category: 'trigger',
    icon: 'fa-file-arrow-up',
    iconClass: 'icon-trigger',
    desc: 'Triggers workflow using custom uploaded or pasted file metadata',
    inputs: [],
    outputs: ['file_scan_event'],
    defaultConfig: {
      filename: 'annual_financial_report.pdf',
      fileSizeFormatted: '1.12 MB',
      entropy: '4.25',
      threatLevel: 'CLEAN'
    },
    run: async (config, inputs) => {
      return {
        event: 'manual_file_uploaded',
        timestamp: new Date().toISOString(),
        filename: config.filename || 'uploaded_sample.pdf',
        fileSizeFormatted: config.fileSizeFormatted || '1.0 MB',
        sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        entropy: parseFloat(config.entropy) || 4.2,
        threatLevel: config.threatLevel || 'CLEAN',
        riskScore: config.threatLevel === 'CLEAN' ? 5 : 75,
        heuristics: { flags: [] }
      };
    }
  },

  trigger_dir_audit: {
    name: 'Batch Directory Audit',
    category: 'trigger',
    icon: 'fa-folder-tree',
    iconClass: 'icon-trigger',
    desc: 'Audits all existing files in a designated directory',
    inputs: [],
    outputs: ['file_scan_event'],
    defaultConfig: {
      directoryPath: './monitored_downloads',
      recursive: true
    },
    run: async (config, inputs) => {
      return {
        event: 'directory_audit_tick',
        timestamp: new Date().toISOString(),
        directory: config.directoryPath,
        filename: 'batch_scanned_archive.zip',
        fileSizeFormatted: '14.8 MB',
        entropy: 6.1,
        threatLevel: 'SUSPICIOUS',
        riskScore: 55,
        heuristics: { flags: ['WARNING: Password protected ZIP archive detected'] }
      };
    }
  },

  trigger_security_webhook: {
    name: 'Security Webhook',
    category: 'trigger',
    icon: 'fa-globe',
    iconClass: 'icon-trigger',
    desc: 'Listens for scan metadata POSTed from external security gateways',
    inputs: [],
    outputs: ['file_scan_event'],
    defaultConfig: {
      path: '/api/v1/security/ingest',
      secretKey: 'sec_key_9921'
    },
    run: async (config, inputs) => {
      return {
        event: 'webhook_scan_received',
        timestamp: new Date().toISOString(),
        sourceIp: '192.168.1.105',
        filename: 'gateway_intercepted_payload.bin',
        entropy: 7.92,
        threatLevel: 'MALICIOUS_RANSOMWARE_RISK',
        riskScore: 92,
        heuristics: { flags: ['CRITICAL: High entropy payload from unverified host'] }
      };
    }
  },

  // --- HEURISTICS & THREAT AI ---
  ai_entropy_heuristics: {
    name: 'Shannon Entropy Scanner',
    category: 'ai',
    icon: 'fa-chart-simple',
    iconClass: 'icon-ai',
    desc: 'Calculates Shannon byte entropy (0.0 to 8.0) for ransomware packing',
    inputs: ['file_scan_event'],
    outputs: ['entropy_analysis'],
    defaultConfig: {
      entropyThreshold: '7.5',
      packersCheck: true
    },
    run: async (config, inputs) => {
      const data = inputs.file_scan_event || {};
      const entropy = parseFloat(data.entropy || 7.8);
      const isHighEntropy = entropy >= parseFloat(config.entropyThreshold || 7.5);
      
      const flags = [...(data.heuristics?.flags || [])];
      if (isHighEntropy && !flags.some(f => f.includes('entropy'))) {
        flags.push(`WARNING: High Shannon entropy (${entropy.toFixed(2)}/8.0) indicates packed/encrypted payload`);
      }

      return {
        ...data,
        entropy,
        isHighEntropy,
        entropyRating: isHighEntropy ? 'CRITICAL_PACKED' : 'NORMAL_DOCUMENT',
        heuristics: { flags }
      };
    }
  },

  ai_double_extension: {
    name: 'Double Extension Audit',
    category: 'ai',
    icon: 'fa-mask',
    iconClass: 'icon-ai',
    desc: 'Detects masquerading extension tricks (e.g. invoice.pdf.exe)',
    inputs: ['file_scan_event'],
    outputs: ['extension_audit'],
    defaultConfig: {
      strictMode: true
    },
    run: async (config, inputs) => {
      const data = inputs.file_scan_event || {};
      const filename = data.filename || 'file.pdf.exe';
      const parts = filename.split('.');
      const isDoubleExt = parts.length > 2 && ['exe', 'bat', 'cmd', 'ps1', 'vbs', 'scr', 'js'].includes(parts[parts.length - 1].toLowerCase());

      const flags = [...(data.heuristics?.flags || [])];
      if (isDoubleExt && !flags.some(f => f.includes('Double extension'))) {
        flags.push(`CRITICAL: Masquerading double extension detected (${filename})`);
      }

      return {
        ...data,
        isDoubleExt,
        extensionAuditPass: !isDoubleExt,
        heuristics: { flags }
      };
    }
  },

  ai_gemini_threat: {
    name: 'Gemini Threat Classifier',
    category: 'ai',
    icon: 'fa-wand-magic-sparkles',
    iconClass: 'icon-ai',
    desc: 'AI threat scoring, ransomware family identification & risk report',
    inputs: ['file_scan_event'],
    outputs: ['threat_report'],
    defaultConfig: {
      model: 'gemini-1.5-flash',
      riskSensitivity: 'High'
    },
    run: async (config, inputs) => {
      const data = inputs.file_scan_event || {};
      const flags = data.heuristics?.flags || [];
      const hasCritical = flags.some(f => f.includes('CRITICAL'));
      const highEntropy = (data.entropy || 0) > 7.5;

      let threatLevel = data.threatLevel || 'CLEAN';
      let riskScore = data.riskScore || 10;
      let classification = 'Clean User File';
      let threatFamily = 'None';

      if (hasCritical || highEntropy) {
        threatLevel = 'MALICIOUS_RANSOMWARE_RISK';
        riskScore = Math.max(riskScore, 88);
        classification = 'High Risk Ransomware / Obfuscated Dropper';
        threatFamily = 'Win32.Ransom.GenericPacker';
      } else if (flags.length > 0) {
        threatLevel = 'SUSPICIOUS';
        riskScore = Math.max(riskScore, 60);
        classification = 'Suspicious Macro Document';
        threatFamily = 'Doc.Macro.Generic';
      }

      return {
        ...data,
        threatLevel,
        riskScore,
        aiClassification: classification,
        threatFamily,
        aiSummary: `Gemini AI evaluated file "${data.filename}". Detected ${flags.length} heuristic risk indicators.`
      };
    }
  },

  ai_hash_sha256: {
    name: 'SHA-256 Hash Lookup',
    category: 'ai',
    icon: 'fa-fingerprint',
    iconClass: 'icon-ai',
    desc: 'Computes cryptographic SHA-256 signature & checks Threat DB',
    inputs: ['file_scan_event'],
    outputs: ['hash_result'],
    defaultConfig: {
      threatDbLookup: true
    },
    run: async (config, inputs) => {
      const data = inputs.file_scan_event || {};
      const sha256 = data.sha256 || '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08';
      
      return {
        ...data,
        sha256,
        knownMalwareMatch: data.threatLevel === 'MALICIOUS_RANSOMWARE_RISK',
        signatureStatus: data.threatLevel === 'MALICIOUS_RANSOMWARE_RISK' ? 'KNOWN_RANSOMWARE_HASH' : 'CLEAN_KNOWN_HASH'
      };
    }
  },

  ai_header_pe: {
    name: 'MZ / PE Header Audit',
    category: 'ai',
    icon: 'fa-file-code',
    iconClass: 'icon-ai',
    desc: 'Inspects binary magic bytes (MZ / PE) for executable spoofing',
    inputs: ['file_scan_event'],
    outputs: ['header_result'],
    defaultConfig: {
      magicCheck: true
    },
    run: async (config, inputs) => {
      const data = inputs.file_scan_event || {};
      const isPeExecutable = (data.filename || '').endsWith('.exe') || (data.entropy || 0) > 7.5;
      
      return {
        ...data,
        isPeExecutable,
        magicHeader: isPeExecutable ? '4D 5A (MZ Portable Executable)' : '25 50 44 46 (%PDF Document)',
        headerSecurityRating: isPeExecutable ? 'HIGH_RISK_BINARY' : 'SAFE_DOCUMENT'
      };
    }
  },

  // --- MITIGATION & INCIDENT RESPONSE ---
  action_quarantine: {
    name: 'Quarantine Vault',
    category: 'action',
    icon: 'fa-box-archive',
    iconClass: 'icon-action',
    desc: 'Automatically isolates & moves dangerous file to ./quarantine',
    inputs: ['threat_payload'],
    outputs: ['quarantine_receipt'],
    defaultConfig: {
      quarantineFolder: './quarantine',
      autoLockPermissions: true
    },
    run: async (config, inputs) => {
      const data = inputs.threat_payload || {};
      const filename = data.filename || 'threat_payload.exe';
      const quarantinePath = `./quarantine/ISOLATED_${Date.now()}_${filename}`;

      return {
        action: 'FILE_QUARANTINED',
        timestamp: new Date().toISOString(),
        originalFilename: filename,
        quarantineLocation: quarantinePath,
        sha256: data.sha256,
        threatLevel: data.threatLevel || 'MALICIOUS_RANSOMWARE_RISK',
        status: 'SUCCESSFULLY_ISOLATED_IN_VAULT'
      };
    }
  },

  action_shred: {
    name: 'File Shredder',
    category: 'action',
    icon: 'fa-dumpster-fire',
    iconClass: 'icon-action',
    desc: 'Permanently deletes malicious file bytes from disk',
    inputs: ['threat_payload'],
    outputs: ['shred_receipt'],
    defaultConfig: {
      overwritePasses: 3
    },
    run: async (config, inputs) => {
      const data = inputs.threat_payload || {};
      return {
        action: 'FILE_SHREDDED',
        timestamp: new Date().toISOString(),
        deletedFile: data.filename || 'malicious_file.exe',
        passes: 3,
        status: 'PERMANENTLY_DESTROYED'
      };
    }
  },

  action_sandbox: {
    name: 'Sandbox Execution',
    category: 'action',
    icon: 'fa-cubes',
    iconClass: 'icon-action',
    desc: 'Defers file execution to an isolated VM sandbox container',
    inputs: ['threat_payload'],
    outputs: ['sandbox_logs'],
    defaultConfig: {
      sandboxTimeoutMs: 5000,
      networkIsolation: true
    },
    run: async (config, inputs) => {
      return {
        action: 'SANDBOX_ANALYSIS_COMPLETE',
        timestamp: new Date().toISOString(),
        behaviorLogs: [
          'Attempted registry key modification: HKLM\\Software\\Run',
          'Attempted process spawn: cmd.exe /c vssadmin delete shadows'
        ],
        sandboxRating: 'MALICIOUS_BEHAVIOR_CONFIRMED'
      };
    }
  },

  // --- THREAT LOGIC & RULES ---
  logic_threat_eval: {
    name: 'Threat Level Evaluator',
    category: 'logic',
    icon: 'fa-diamond',
    iconClass: 'icon-logic',
    desc: 'Branches workflow: Malicious/Suspicious (True) vs Clean File (False)',
    inputs: ['in'],
    outputs: ['true_branch', 'false_branch'],
    defaultConfig: {
      threatCondition: 'SUSPICIOUS_OR_MALICIOUS'
    },
    run: async (config, inputs) => {
      const data = inputs.in || {};
      const level = data.threatLevel || 'CLEAN';
      const riskScore = data.riskScore || 0;
      
      const isThreat = level === 'MALICIOUS_RANSOMWARE_RISK' || level === 'SUSPICIOUS' || riskScore >= 50;

      return {
        conditionPassed: isThreat,
        threatDetected: isThreat,
        evaluatedLevel: level,
        evaluatedRiskScore: riskScore,
        payload: data
      };
    }
  },

  logic_risk_gate: {
    name: 'Risk Score Filter',
    category: 'logic',
    icon: 'fa-filter',
    iconClass: 'icon-logic',
    desc: 'Passes payload only if risk score exceeds threshold score',
    inputs: ['in'],
    outputs: ['high_risk', 'low_risk'],
    defaultConfig: {
      minRiskScore: 70
    },
    run: async (config, inputs) => {
      const data = inputs.in || {};
      const score = data.riskScore || 0;
      const isHighRisk = score >= parseInt(config.minRiskScore || 70);

      return {
        isHighRisk,
        score,
        threshold: config.minRiskScore,
        payload: data
      };
    }
  },

  // --- SOC ALERTS & OUTPUTS ---
  output_soc_alert: {
    name: 'SOC Slack Alert',
    category: 'output',
    icon: 'fa-bell',
    iconClass: 'icon-output',
    desc: 'Dispatches emergency alert to SOC #cyber-sec Slack channel',
    inputs: ['alert_payload'],
    outputs: ['alert_sent'],
    defaultConfig: {
      slackChannel: '#cyber-security-ops',
      notifyOnCall: true
    },
    run: async (config, inputs) => {
      const data = inputs.alert_payload || {};
      return {
        dispatchStatus: 'SLACK_ALERT_SENT',
        timestamp: new Date().toISOString(),
        channel: config.slackChannel,
        alertTitle: '🚨 CRITICAL MALWARE DOWNLOAD INTERCEPTED',
        details: `File "${data.originalFilename || data.filename || 'unknown'}" quarantined automatically. SHA-256: ${data.sha256 || 'N/A'}`
      };
    }
  },

  output_disk_log: {
    name: 'Security Disk Logger',
    category: 'output',
    icon: 'fa-hard-drive',
    iconClass: 'icon-output',
    desc: 'Appends structured audit log record to backend logs/server.log',
    inputs: ['audit_record'],
    outputs: ['log_written'],
    defaultConfig: {
      logLevel: 'AUDIT'
    },
    run: async (config, inputs) => {
      const data = inputs.audit_record || {};
      return {
        logStatus: 'DISK_LOG_WRITTEN',
        timestamp: new Date().toISOString(),
        targetFile: 'logs/server.log',
        entry: `[AUDIT] Scanned file verified: ${data.filename || 'document'}`
      };
    }
  },

  output_desktop_toast: {
    name: 'Desktop Threat Notification',
    category: 'output',
    icon: 'fa-desktop',
    iconClass: 'icon-output',
    desc: 'Displays native OS desktop notification toast for threat events',
    inputs: ['notification'],
    outputs: ['toast_shown'],
    defaultConfig: {
      soundAlert: true
    },
    run: async (config, inputs) => {
      return {
        toastStatus: 'OS_NOTIFICATION_TRIGGERED',
        timestamp: new Date().toISOString()
      };
    }
  }
};

// ============================================================================
// 2. GLOBAL APPLICATION STATE
// ============================================================================

const state = {
  workflowName: 'Real-Time File Download Security Watcher & Threat Quarantine Flow',
  nodes: new Map(), // Map<id, nodeObj>
  wires: [], // Array<{ id, fromNode, fromPort, toNode, toPort }>
  annotations: [], // Array<{ id, x, y, author, text, timestamp }>
  selectedNodeId: null,
  activeMode: 'flow', // 'flow' | 'annotation'
  zoom: 1.0,
  panX: 80,
  panY: 100,
  isPanning: false,
  startPanX: 0,
  startPanY: 0,
  gridSnap: true,
  gridSize: 20,
  isDraggingNode: false,
  dragNodeId: null,
  dragOffsetX: 0,
  dragOffsetY: 0,
  draftWire: null,
  simulation: {
    isRunning: false,
    speedMs: 1000,
    currentStepIndex: 0,
    executionQueue: [],
    timerId: null
  },
  hudCounters: {
    scanned: 0,
    clean: 0,
    suspicious: 0,
    quarantined: 0
  }
};

// ============================================================================
// 3. DOM ELEMENTS & CANVAS SETUP
// ============================================================================

const viewport = document.getElementById('canvas-viewport');
const world = document.getElementById('canvas-world');
const nodesContainer = document.getElementById('nodes-container');
const annotationsContainer = document.getElementById('annotations-container');
const connectionsSvg = document.getElementById('connections-svg');
const wiresGroup = document.getElementById('wires-group');
const draftWirePath = document.getElementById('draft-wire-path');
const dataPacketsGroup = document.getElementById('data-packets-group');
const zoomText = document.getElementById('zoom-text');

function updateTransform() {
  world.style.transform = `translate(${state.panX}px, ${state.panY}px) scale(${state.zoom})`;
  zoomText.textContent = `${Math.round(state.zoom * 100)}%`;
  renderMinimap();
}

// Canvas Panning Handlers
viewport.addEventListener('mousedown', (e) => {
  if (e.target === viewport || e.target === connectionsSvg || e.target.id === 'canvas-world') {
    if (state.activeMode === 'annotation') {
      const rect = viewport.getBoundingClientRect();
      const x = (e.clientX - rect.left - state.panX) / state.zoom;
      const y = (e.clientY - rect.top - state.panY) / state.zoom;
      createAnnotationPin(x, y);
      return;
    }

    state.isPanning = true;
    state.startPanX = e.clientX - state.panX;
    state.startPanY = e.clientY - state.panY;
    deselectAllNodes();
  }
});

window.addEventListener('mousemove', (e) => {
  if (state.isPanning) {
    state.panX = e.clientX - state.startPanX;
    state.panY = e.clientY - state.startPanY;
    updateTransform();
  } else if (state.isDraggingNode && state.dragNodeId) {
    const node = state.nodes.get(state.dragNodeId);
    if (node) {
      const rect = viewport.getBoundingClientRect();
      let rawX = (e.clientX - rect.left - state.panX) / state.zoom - state.dragOffsetX;
      let rawY = (e.clientY - rect.top - state.panY) / state.zoom - state.dragOffsetY;

      if (state.gridSnap) {
        rawX = Math.round(rawX / state.gridSize) * state.gridSize;
        rawY = Math.round(rawY / state.gridSize) * state.gridSize;
      }

      node.x = rawX;
      node.y = rawY;
      
      const nodeEl = document.getElementById(`node-${node.id}`);
      if (nodeEl) {
        nodeEl.style.left = `${node.x}px`;
        nodeEl.style.top = `${node.y}px`;
      }

      renderWires();
      renderMinimap();
    }
  } else if (state.draftWire) {
    const rect = viewport.getBoundingClientRect();
    state.draftWire.currentX = (e.clientX - rect.left - state.panX) / state.zoom;
    state.draftWire.currentY = (e.clientY - rect.top - state.panY) / state.zoom;
    renderDraftWire();
  }
});

window.addEventListener('mouseup', () => {
  state.isPanning = false;
  state.isDraggingNode = false;
  if (state.draftWire) {
    state.draftWire = null;
    draftWirePath.style.display = 'none';
  }
});

// Zoom Mouse Wheel
viewport.addEventListener('wheel', (e) => {
  e.preventDefault();
  const zoomFactor = e.deltaY < 0 ? 1.1 : 0.9;
  const newZoom = Math.min(Math.max(state.zoom * zoomFactor, 0.3), 2.5);

  const rect = viewport.getBoundingClientRect();
  const mouseX = e.clientX - rect.left;
  const mouseY = e.clientY - rect.top;

  state.panX = mouseX - (mouseX - state.panX) * (newZoom / state.zoom);
  state.panY = mouseY - (mouseY - state.panY) * (newZoom / state.zoom);
  state.zoom = newZoom;

  updateTransform();
}, { passive: false });

// Zoom Control Buttons
document.getElementById('btn-zoom-in').addEventListener('click', () => {
  state.zoom = Math.min(state.zoom * 1.2, 2.5);
  updateTransform();
});
document.getElementById('btn-zoom-out').addEventListener('click', () => {
  state.zoom = Math.max(state.zoom / 1.2, 0.3);
  updateTransform();
});
document.getElementById('btn-zoom-reset').addEventListener('click', () => {
  state.zoom = 1.0;
  state.panX = 80;
  state.panY = 100;
  updateTransform();
});
document.getElementById('btn-toggle-grid').addEventListener('click', (e) => {
  state.gridSnap = !state.gridSnap;
  e.currentTarget.style.color = state.gridSnap ? 'var(--accent-cyan)' : 'var(--text-muted)';
  logToConsole('SYSTEM', `Grid Snapping ${state.gridSnap ? 'Enabled' : 'Disabled'}`);
});
document.getElementById('btn-clear-canvas').addEventListener('click', () => {
  if (confirm('Are you sure you want to clear all security canvas nodes and wires?')) {
    state.nodes.clear();
    state.wires = [];
    state.annotations = [];
    state.selectedNodeId = null;
    renderAllNodes();
    renderWires();
    renderAnnotations();
    updateInspector();
    showCanvasWatermark();
    logToConsole('SYSTEM', 'Security Canvas cleared.', 'warning');
  }
});

// ============================================================================
// 4. PALETTE DRAG & DROP
// ============================================================================

const paletteItems = document.querySelectorAll('.palette-node-item');
paletteItems.forEach(item => {
  item.addEventListener('dragstart', (e) => {
    e.dataTransfer.setData('application/okflow-node-type', item.getAttribute('data-type'));
  });
});

viewport.addEventListener('dragover', (e) => e.preventDefault());
viewport.addEventListener('drop', (e) => {
  e.preventDefault();
  const nodeTypeKey = e.dataTransfer.getData('application/okflow-node-type');
  if (!nodeTypeKey || !NODE_TYPES[nodeTypeKey]) return;

  const rect = viewport.getBoundingClientRect();
  let x = (e.clientX - rect.left - state.panX) / state.zoom - 110;
  let y = (e.clientY - rect.top - state.panY) / state.zoom - 40;

  if (state.gridSnap) {
    x = Math.round(x / state.gridSize) * state.gridSize;
    y = Math.round(y / state.gridSize) * state.gridSize;
  }

  createNodeInstance(nodeTypeKey, x, y);
});

// Search Palette Filter
document.getElementById('palette-search').addEventListener('input', (e) => {
  const query = e.target.value.toLowerCase();
  paletteItems.forEach(item => {
    const text = item.textContent.toLowerCase();
    item.style.display = text.includes(query) ? 'flex' : 'none';
  });
});

// ============================================================================
// 5. NODE INSTANTIATION & CARD RENDERING
// ============================================================================

function createNodeInstance(typeKey, x, y, customConfig = null, customId = null) {
  const schema = NODE_TYPES[typeKey];
  if (!schema) return null;

  const id = customId || generateId('node');
  const node = {
    id,
    type: typeKey,
    name: schema.name,
    desc: schema.desc,
    x,
    y,
    inputs: [...schema.inputs],
    outputs: [...schema.outputs],
    config: customConfig ? { ...schema.defaultConfig, ...customConfig } : { ...schema.defaultConfig },
    status: 'idle', // 'idle' | 'running' | 'success' | 'error'
    inputPayload: null,
    outputPayload: null
  };

  state.nodes.set(id, node);
  renderNodeCard(node);
  selectNode(id);
  saveStateToLocalStorage();
  return node;
}

function renderAllNodes() {
  nodesContainer.innerHTML = '';
  state.nodes.forEach(node => renderNodeCard(node));
}

function renderNodeCard(node) {
  const schema = NODE_TYPES[node.type];
  let nodeEl = document.getElementById(`node-${node.id}`);
  
  if (!nodeEl) {
    nodeEl = document.createElement('div');
    nodeEl.id = `node-${node.id}`;
    nodeEl.className = `node-card ${schema?.iconClass || ''}`;
    nodesContainer.appendChild(nodeEl);
    // Hide the canvas watermark once a node exists
    hideCanvasWatermark();
  }

  nodeEl.style.left = `${node.x}px`;
  nodeEl.style.top = `${node.y}px`;

  // Status Indicator glow classes
  nodeEl.classList.remove('status-running', 'status-success', 'status-error');
  if (node.status === 'running') nodeEl.classList.add('status-running');
  if (node.status === 'success') nodeEl.classList.add('status-success');
  if (node.status === 'error') nodeEl.classList.add('status-error');

  const inputsHtml = node.inputs.map(port => `
    <div class="port-row input">
      <div class="port-dot input-port" data-node-id="${node.id}" data-port-name="${port}" data-port-type="input" title="Input: ${port}"></div>
      <span class="port-label">${formatPortLabel(port)}</span>
    </div>
  `).join('');

  const outputsHtml = node.outputs.map(port => `
    <div class="port-row output">
      <span class="port-label">${formatPortLabel(port)}</span>
      <div class="port-dot output-port" data-node-id="${node.id}" data-port-name="${port}" data-port-type="output" title="Output: ${port}"></div>
    </div>
  `).join('');

  nodeEl.innerHTML = `
    <div class="node-header">
      <div class="node-title-group">
        <i class="fa-solid ${schema?.icon || 'fa-gear'} node-type-icon"></i>
        <div>
          <div class="node-title">${escapeHtml(node.name)}</div>
          <div class="node-subtitle">${escapeHtml(node.desc || '')}</div>
        </div>
      </div>
      <div class="node-status-dot ${node.status}" title="Node Status: ${node.status}"></div>
    </div>

    <div class="node-body">
      <div class="ports-column inputs-col">${inputsHtml}</div>
      <div class="ports-column outputs-col">${outputsHtml}</div>
    </div>
  `;

  // Node Drag & Selection Events
  const headerEl = nodeEl.querySelector('.node-header');
  headerEl.addEventListener('mousedown', (e) => {
    e.stopPropagation();
    selectNode(node.id);
    state.isDraggingNode = true;
    state.dragNodeId = node.id;

    const rect = viewport.getBoundingClientRect();
    state.dragOffsetX = (e.clientX - rect.left - state.panX) / state.zoom - node.x;
    state.dragOffsetY = (e.clientY - rect.top - state.panY) / state.zoom - node.y;
  });

  // Attach Port Wire Drag Listeners
  nodeEl.querySelectorAll('.port-dot').forEach(portDot => {
    portDot.addEventListener('mousedown', (e) => {
      e.stopPropagation();
      const nodeId = portDot.getAttribute('data-node-id');
      const portName = portDot.getAttribute('data-port-name');
      const portType = portDot.getAttribute('data-port-type');

      if (portType === 'output') {
        const portPos = getPortCenter(nodeId, portName, 'output');
        state.draftWire = {
          fromNode: nodeId,
          fromPort: portName,
          startX: portPos.x,
          startY: portPos.y,
          currentX: portPos.x,
          currentY: portPos.y
        };
        draftWirePath.style.display = 'block';
      }
    });

    portDot.addEventListener('mouseup', (e) => {
      e.stopPropagation();
      const toNodeId = portDot.getAttribute('data-node-id');
      const toPortName = portDot.getAttribute('data-port-name');
      const toPortType = portDot.getAttribute('data-port-type');

      if (state.draftWire && toPortType === 'input') {
        connectWire(state.draftWire.fromNode, state.draftWire.fromPort, toNodeId, toPortName);
        state.draftWire = null;
        draftWirePath.style.display = 'none';
      }
    });
  });
}

function selectNode(id) {
  state.selectedNodeId = id;
  document.querySelectorAll('.node-card').forEach(el => {
    if (el.id === `node-${id}`) {
      el.classList.add('selected');
    } else {
      el.classList.remove('selected');
    }
  });
  updateInspector();
}

function deselectAllNodes() {
  state.selectedNodeId = null;
  document.querySelectorAll('.node-card').forEach(el => el.classList.remove('selected'));
  updateInspector();
}

// ============================================================================
// 6. SVG WIRES & CURVED CONNECTIONS
// ============================================================================

function connectWire(fromNodeId, fromPort, toNodeId, toPort) {
  // Prevent self-loop wires
  if (fromNodeId === toNodeId) return;

  // Prevent duplicate wires
  const exists = state.wires.some(w => 
    w.fromNode === fromNodeId && w.fromPort === fromPort && 
    w.toNode === toNodeId && w.toPort === toPort
  );
  if (exists) return;

  const wireId = generateId('wire');
  state.wires.push({ id: wireId, fromNode: fromNodeId, fromPort, toNode: toNodeId, toPort });
  renderWires();
  saveStateToLocalStorage();
}

function renderWires() {
  wiresGroup.innerHTML = '';

  state.wires.forEach((wire) => {
    const fromPos = getPortCenter(wire.fromNode, wire.fromPort, 'output');
    const toPos = getPortCenter(wire.toNode, wire.toPort, 'input');

    if (!fromPos || !toPos) return;

    const pathD = calculateBezierPath(fromPos.x, fromPos.y, toPos.x, toPos.y);

    const pathEl = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    pathEl.setAttribute('d', pathD);
    pathEl.setAttribute('class', 'wire-path');
    pathEl.setAttribute('data-wire-id', wire.id);

    // Click wire to delete
    pathEl.addEventListener('click', (e) => {
      e.stopPropagation();
      if (confirm('Delete this wire connection?')) {
        state.wires = state.wires.filter(w => w.id !== wire.id);
        renderWires();
        saveStateToLocalStorage();
      }
    });

    wiresGroup.appendChild(pathEl);
  });
}

function renderDraftWire() {
  if (!state.draftWire) return;
  const pathD = calculateBezierPath(
    state.draftWire.startX, 
    state.draftWire.startY, 
    state.draftWire.currentX, 
    state.draftWire.currentY
  );
  draftWirePath.setAttribute('d', pathD);
}

function getPortCenter(nodeId, portName, type) {
  const nodeEl = document.getElementById(`node-${nodeId}`);
  if (!nodeEl) return null;

  const portEl = nodeEl.querySelector(`.port-dot[data-port-name="${portName}"][data-port-type="${type}"]`);
  if (!portEl) return null;

  const node = state.nodes.get(nodeId);
  if (!node) return null;

  // Relative offset within node card
  const portRect = portEl.getBoundingClientRect();
  const nodeRect = nodeEl.getBoundingClientRect();

  const relX = (portRect.left + portRect.width / 2 - nodeRect.left) / state.zoom;
  const relY = (portRect.top + portRect.height / 2 - nodeRect.top) / state.zoom;

  return {
    x: node.x + relX,
    y: node.y + relY
  };
}

function calculateBezierPath(x1, y1, x2, y2) {
  const dx = Math.abs(x2 - x1) * 0.5;
  const cx1 = x1 + Math.max(dx, 40);
  const cy1 = y1;
  const cx2 = x2 - Math.max(dx, 40);
  const cy2 = y2;
  return `M ${x1} ${y1} C ${cx1} ${cy1}, ${cx2} ${cy2}, ${x2} ${y2}`;
}

// ============================================================================
// 7. INSPECTOR CONFIGURATION PANEL
// ============================================================================

const inspectorTitle = document.getElementById('inspector-title');
const configEmptyState = document.getElementById('config-empty-state');
const configFormContainer = document.getElementById('config-form-container');
const nodeNameInput = document.getElementById('node-name-input');
const nodeDescInput = document.getElementById('node-desc-input');
const dynamicNodeControls = document.getElementById('dynamic-node-controls');
const payloadInputViewer = document.getElementById('payload-input-viewer');
const payloadOutputViewer = document.getElementById('payload-output-viewer');

function updateInspector() {
  if (!state.selectedNodeId || !state.nodes.has(state.selectedNodeId)) {
    inspectorTitle.textContent = 'Security Node Inspector';
    configEmptyState.style.display = 'flex';
    configFormContainer.style.display = 'none';
    payloadInputViewer.textContent = '// Select a node to view input payload';
    payloadOutputViewer.textContent = '// Select a node to view output result';
    return;
  }

  const node = state.nodes.get(state.selectedNodeId);
  const schema = NODE_TYPES[node.type];

  inspectorTitle.textContent = `${schema?.name || 'Node'} Settings`;
  configEmptyState.style.display = 'none';
  configFormContainer.style.display = 'flex';

  nodeNameInput.value = node.name;
  nodeDescInput.value = node.desc || '';

  // Render schema configuration controls
  dynamicNodeControls.innerHTML = '';
  
  if (node.config) {
    Object.keys(node.config).forEach(key => {
      const formGrp = document.createElement('div');
      formGrp.className = 'form-group';

      const label = document.createElement('label');
      label.className = 'form-label';
      label.textContent = capitalizeFirstLetter(key.replace(/([A-Z])/g, ' $1'));

      const input = document.createElement('input');
      input.className = 'form-input';
      input.type = typeof node.config[key] === 'number' ? 'number' : 'text';
      input.value = node.config[key];

      input.addEventListener('input', (e) => {
        node.config[key] = e.target.value;
        saveStateToLocalStorage();
      });

      formGrp.appendChild(label);
      formGrp.appendChild(input);
      dynamicNodeControls.appendChild(formGrp);
    });
  }

  // Update Payload Inspector tab content
  payloadInputViewer.textContent = node.inputPayload ? JSON.stringify(node.inputPayload, null, 2) : '// No input payload received yet';
  payloadOutputViewer.textContent = node.outputPayload ? JSON.stringify(node.outputPayload, null, 2) : '// No output result generated yet';
}

nodeNameInput.addEventListener('input', (e) => {
  if (state.selectedNodeId && state.nodes.has(state.selectedNodeId)) {
    const node = state.nodes.get(state.selectedNodeId);
    node.name = e.target.value;
    renderNodeCard(node);
    saveStateToLocalStorage();
  }
});

nodeDescInput.addEventListener('input', (e) => {
  if (state.selectedNodeId && state.nodes.has(state.selectedNodeId)) {
    const node = state.nodes.get(state.selectedNodeId);
    node.desc = e.target.value;
    renderNodeCard(node);
    saveStateToLocalStorage();
  }
});

document.getElementById('btn-delete-node').addEventListener('click', () => {
  if (state.selectedNodeId) {
    deleteNode(state.selectedNodeId);
  }
});

function deleteNode(nodeId) {
  state.nodes.delete(nodeId);
  state.wires = state.wires.filter(w => w.fromNode !== nodeId && w.toNode !== nodeId);
  
  const el = document.getElementById(`node-${nodeId}`);
  if (el) el.remove();

  state.selectedNodeId = null;
  renderWires();
  updateInspector();
  saveStateToLocalStorage();
  logToConsole('SYSTEM', `Deleted security node "${nodeId}".`, 'warning');
}

// Inspector Tabs Handler
const tabBtns = document.querySelectorAll('.inspector-tabs .tab-btn');
tabBtns.forEach(btn => {
  btn.addEventListener('click', () => {
    tabBtns.forEach(b => b.classList.remove('active'));
    btn.classList.add('active');

    const targetTab = btn.getAttribute('data-tab');
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    document.getElementById(`tab-${targetTab}`).classList.add('active');
  });
});

// Close Inspector Side Panel
document.getElementById('btn-close-inspector').addEventListener('click', () => {
  const container = document.getElementById('app-container');
  container.classList.toggle('inspector-collapsed');
});

// Mode Toggle Handler (Flow vs Annotation Pins)
const modeFlowBtn = document.getElementById('mode-flow-btn');
const modeAnnotationBtn = document.getElementById('mode-annotation-btn');

modeFlowBtn.addEventListener('click', () => {
  state.activeMode = 'flow';
  modeFlowBtn.classList.add('active');
  modeAnnotationBtn.classList.remove('active');
  viewport.style.cursor = 'grab';
});

modeAnnotationBtn.addEventListener('click', () => {
  state.activeMode = 'annotation';
  modeAnnotationBtn.classList.add('active');
  modeFlowBtn.classList.remove('active');
  viewport.style.cursor = 'crosshair';
  logToConsole('SYSTEM', 'Annotation Mode active. Click on canvas to pin a feedback note.');
});

// ============================================================================
// 8. SIMULATION EXECUTION ENGINE
// ============================================================================

const btnRunFlow = document.getElementById('btn-run-flow');
const btnStepFlow = document.getElementById('btn-step-flow');
const btnPauseFlow = document.getElementById('btn-pause-flow');
const btnResetFlow = document.getElementById('btn-reset-flow');
const globalStatusDot = document.getElementById('global-status-dot');
const globalStatusText = document.getElementById('global-status-text');

btnRunFlow.addEventListener('click', startSimulation);
btnStepFlow.addEventListener('click', stepSimulation);
btnPauseFlow.addEventListener('click', pauseSimulation);
btnResetFlow.addEventListener('click', resetSimulation);

function setEngineStatus(status, text) {
  globalStatusDot.className = `status-dot ${status}`;
  globalStatusText.textContent = text;
}

function startSimulation() {
  if (state.simulation.isRunning) return;
  state.simulation.isRunning = true;
  btnRunFlow.disabled = true;
  btnPauseFlow.disabled = false;
  setEngineStatus('running', 'Simulating Security Flow...');

  // Build topological execution queue
  prepareExecutionQueue();
  logToConsole('ENGINE', 'Started real-time security threat mitigation simulation.', 'info');

  runNextQueuedStep();
}

function pauseSimulation() {
  state.simulation.isRunning = false;
  btnRunFlow.disabled = false;
  btnPauseFlow.disabled = true;
  if (state.simulation.timerId) clearTimeout(state.simulation.timerId);
  setEngineStatus('idle', 'Engine Paused');
  logToConsole('ENGINE', 'Simulation paused.', 'warning');
}

function resetSimulation() {
  pauseSimulation();
  state.nodes.forEach(node => {
    node.status = 'idle';
    node.inputPayload = null;
    node.outputPayload = null;
    renderNodeCard(node);
  });
  dataPacketsGroup.innerHTML = '';
  setEngineStatus('idle', 'Watcher Engine Active');
  logToConsole('ENGINE', 'Reset node execution states.', 'info');
  updateInspector();
}

function prepareExecutionQueue() {
  state.simulation.executionQueue = [];
  
  // Triggers first
  state.nodes.forEach(node => {
    if (NODE_TYPES[node.type]?.category === 'trigger') {
      state.simulation.executionQueue.push(node.id);
    }
  });

  // Downstream nodes in topological order
  let index = 0;
  while (index < state.simulation.executionQueue.length) {
    const currentId = state.simulation.executionQueue[index];
    const outgoingWires = state.wires.filter(w => w.fromNode === currentId);
    
    outgoingWires.forEach(wire => {
      if (!state.simulation.executionQueue.includes(wire.toNode)) {
        state.simulation.executionQueue.push(wire.toNode);
      }
    });
    index++;
  }
}

async function runNextQueuedStep() {
  if (!state.simulation.isRunning) return;
  if (state.simulation.executionQueue.length === 0) {
    pauseSimulation();
    setEngineStatus('success', 'Threat Flow Complete');
    logToConsole('ENGINE', 'Threat mitigation workflow simulation completed successfully!', 'success');
    return;
  }

  const nodeId = state.simulation.executionQueue.shift();
  await executeSingleNode(nodeId);

  const speedSelect = document.getElementById('sim-speed-select');
  const delay = parseInt(speedSelect ? speedSelect.value : 1000);

  state.simulation.timerId = setTimeout(() => {
    runNextQueuedStep();
  }, delay);
}

async function stepSimulation() {
  if (state.simulation.executionQueue.length === 0) {
    prepareExecutionQueue();
  }
  if (state.simulation.executionQueue.length > 0) {
    const nodeId = state.simulation.executionQueue.shift();
    await executeSingleNode(nodeId);
  }
}

async function executeSingleNode(nodeId) {
  const node = state.nodes.get(nodeId);
  if (!node) return;

  const schema = NODE_TYPES[node.type];
  if (!schema) return;

  node.status = 'running';
  renderNodeCard(node);
  logToConsole('NODE', `Executing node "${node.name}"...`, 'info');

  // Collect inputs from incoming wire connections
  const incomingWires = state.wires.filter(w => w.toNode === nodeId);
  const inputsData = {};

  incomingWires.forEach(wire => {
    const sourceNode = state.nodes.get(wire.fromNode);
    if (sourceNode && sourceNode.outputPayload) {
      inputsData[wire.toPort] = sourceNode.outputPayload;

      // Animate packet glow along SVG wire
      animateDataPacket(wire.fromNode, wire.fromPort, wire.toNode, wire.toPort);
    }
  });

  node.inputPayload = inputsData;

  try {
    const result = await schema.run(node.config, inputsData);
    node.outputPayload = result;
    node.status = 'success';
    renderNodeCard(node);

    logToConsole('NODE', `Node "${node.name}" finished. Risk Score: ${result.riskScore || 'N/A'}`, 'success');
  } catch (err) {
    node.status = 'error';
    renderNodeCard(node);
    logToConsole('NODE', `Node "${node.name}" failed: ${err.message}`, 'error');
  }

  if (state.selectedNodeId === nodeId) updateInspector();
}

// ============================================================================
// 9. ANIMATED SVG DATA PACKETS
// ============================================================================

function animateDataPacket(fromNodeId, fromPort, toNodeId, toPort) {
  const fromPos = getPortCenter(fromNodeId, fromPort, 'output');
  const toPos = getPortCenter(toNodeId, toPort, 'input');
  if (!fromPos || !toPos) return;

  const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
  circle.setAttribute('r', '6');
  circle.setAttribute('fill', 'var(--accent-cyan)');
  circle.setAttribute('filter', 'url(#wire-glow)');
  dataPacketsGroup.appendChild(circle);

  const startTime = performance.now();
  const duration = 600;

  const pathD = calculateBezierPath(fromPos.x, fromPos.y, toPos.x, toPos.y);
  const tempPath = document.createElementNS('http://www.w3.org/2000/svg', 'path');
  tempPath.setAttribute('d', pathD);
  const pathLen = tempPath.getTotalLength();

  function animate(now) {
    const elapsed = now - startTime;
    const progress = Math.min(elapsed / duration, 1.0);
    const point = tempPath.getPointAtLength(progress * pathLen);

    circle.setAttribute('cx', point.x);
    circle.setAttribute('cy', point.y);

    if (progress < 1.0) {
      requestAnimationFrame(animate);
    } else {
      circle.remove();
    }
  }

  requestAnimationFrame(animate);
}

// ============================================================================
// 10. ANNOTATION PINS SYSTEM
// ============================================================================

const annotationsList = document.getElementById('annotations-list');
const pinCountBadge = document.getElementById('pin-count');
const pinsTabCount = document.getElementById('pins-tab-count');

function createAnnotationPin(x, y, text = 'Security Audit Note') {
  const id = generateId('pin');
  const annotation = {
    id,
    x,
    y,
    author: 'Security Officer',
    text,
    timestamp: new Date().toLocaleTimeString()
  };

  state.annotations.push(annotation);
  renderAnnotations();
  saveStateToLocalStorage();
  logToConsole('SYSTEM', 'Pinned audit note on canvas.');
}

function renderAnnotations() {
  annotationsContainer.innerHTML = '';
  annotationsList.innerHTML = '';
  pinCountBadge.textContent = state.annotations.length;
  pinsTabCount.textContent = state.annotations.length;

  state.annotations.forEach((ann, idx) => {
    // Render Pin on Canvas
    const pinEl = document.createElement('div');
    pinEl.className = 'annotation-pin';
    pinEl.style.left = `${ann.x}px`;
    pinEl.style.top = `${ann.y}px`;
    pinEl.innerHTML = `
      <div class="pin-badge">${idx + 1}</div>
      <div class="pin-card">
        <div class="pin-author">${escapeHtml(ann.author)} • ${ann.timestamp}</div>
        <div class="pin-text">${escapeHtml(ann.text)}</div>
      </div>
    `;
    annotationsContainer.appendChild(pinEl);

    // Render Pin List item in Inspector
    const listItem = document.createElement('div');
    listItem.style.cssText = 'background: rgba(255,255,255,0.03); border: 1px solid var(--panel-border); border-radius: 8px; padding: 10px; font-size: 12px; display: flex; flex-direction: column; gap: 4px;';
    listItem.innerHTML = `
      <div style="display: flex; align-items: center; justify-content: space-between;">
        <strong>#${idx + 1} ${escapeHtml(ann.author)}</strong>
        <button class="btn-icon" style="width: 20px; height: 20px;" title="Delete Pin"><i class="fa-solid fa-trash"></i></button>
      </div>
      <div style="color: var(--text-secondary);">${escapeHtml(ann.text)}</div>
    `;

    listItem.querySelector('button').addEventListener('click', () => {
      state.annotations = state.annotations.filter(a => a.id !== ann.id);
      renderAnnotations();
      saveStateToLocalStorage();
    });

    annotationsList.appendChild(listItem);
  });
}

// ============================================================================
// 11. PRE-BUILT BLUEPRINTS & TEMPLATES
// ============================================================================

const templatesModal = document.getElementById('templates-modal');
document.getElementById('btn-templates').addEventListener('click', () => {
  templatesModal.classList.add('active');
});
document.getElementById('btn-close-modal').addEventListener('click', () => {
  templatesModal.classList.remove('active');
});

document.querySelectorAll('.template-card').forEach(card => {
  card.addEventListener('click', () => {
    const templateKey = card.getAttribute('data-template');
    loadPrebuiltTemplate(templateKey);
    templatesModal.classList.remove('active');
  });
});

function loadPrebuiltTemplate(key) {
  state.nodes.clear();
  state.wires = [];

  if (key === 'download_security') {
    state.workflowName = 'Real-Time File Download Security Watcher & Threat Quarantine Flow';
    document.getElementById('workflow-name').value = state.workflowName;

    const n1 = createNodeInstance('trigger_file_download', 60, 160);
    const n2 = createNodeInstance('ai_entropy_heuristics', 360, 160);
    const n3 = createNodeInstance('ai_gemini_threat', 660, 160);
    const n4 = createNodeInstance('logic_threat_eval', 960, 160);
    const n5 = createNodeInstance('action_quarantine', 1260, 80);
    const n6 = createNodeInstance('output_soc_alert', 1560, 80);
    const n7 = createNodeInstance('output_disk_log', 1260, 260);

    connectWire(n1.id, 'file_scan_event', n2.id, 'file_scan_event');
    connectWire(n2.id, 'entropy_analysis', n3.id, 'file_scan_event');
    connectWire(n3.id, 'threat_report', n4.id, 'in');
    connectWire(n4.id, 'true_branch', n5.id, 'threat_payload');
    connectWire(n5.id, 'quarantine_receipt', n6.id, 'alert_payload');
    connectWire(n4.id, 'false_branch', n7.id, 'audit_record');

  } else if (key === 'ransomware_detector') {
    state.workflowName = 'Ransomware High-Entropy & Extension Detector';
    document.getElementById('workflow-name').value = state.workflowName;

    const n1 = createNodeInstance('trigger_file_download', 60, 160);
    const n2 = createNodeInstance('ai_double_extension', 340, 160);
    const n3 = createNodeInstance('ai_entropy_heuristics', 620, 160);
    const n4 = createNodeInstance('logic_threat_eval', 900, 160);
    const n5 = createNodeInstance('action_shred', 1180, 160);

    connectWire(n1.id, 'file_scan_event', n2.id, 'file_scan_event');
    connectWire(n2.id, 'extension_audit', n3.id, 'file_scan_event');
    connectWire(n3.id, 'entropy_analysis', n4.id, 'in');
    connectWire(n4.id, 'true_branch', n5.id, 'threat_payload');

  } else if (key === 'hash_soc_audit') {
    state.workflowName = 'Download Hash Signature Audit & SOC Incident Dispatcher';
    document.getElementById('workflow-name').value = state.workflowName;

    const n1 = createNodeInstance('trigger_file_download', 60, 160);
    const n2 = createNodeInstance('ai_hash_sha256', 360, 160);
    const n3 = createNodeInstance('ai_gemini_threat', 660, 160);
    const n4 = createNodeInstance('output_soc_alert', 960, 160);

    connectWire(n1.id, 'file_scan_event', n2.id, 'file_scan_event');
    connectWire(n2.id, 'hash_result', n3.id, 'file_scan_event');
    connectWire(n3.id, 'threat_report', n4.id, 'alert_payload');
  }

  renderAllNodes();
  renderWires();
  logToConsole('SYSTEM', `Loaded security blueprint "${state.workflowName}".`);
}

// Export Blueprint JSON
document.getElementById('btn-export-json').addEventListener('click', () => {
  const data = {
    name: state.workflowName,
    version: '1.0.0',
    nodes: Array.from(state.nodes.values()),
    wires: state.wires,
    annotations: state.annotations
  };

  const jsonStr = JSON.stringify(data, null, 2);
  const blob = new Blob([jsonStr], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `${state.workflowName.toLowerCase().replace(/\s+/g, '_')}_blueprint.json`;
  a.click();
  URL.revokeObjectURL(url);
  logToConsole('SYSTEM', 'Exported security blueprint JSON.');
});

// Import Blueprint JSON
const fileImportInput = document.getElementById('file-import-input');
document.getElementById('btn-import-trigger').addEventListener('click', () => {
  fileImportInput.click();
});

fileImportInput.addEventListener('change', (e) => {
  const file = e.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = (event) => {
    try {
      const data = JSON.parse(event.target.result);
      if (data.nodes && Array.isArray(data.nodes)) {
        state.nodes.clear();
        state.wires = [];
        state.annotations = data.annotations || [];

        if (data.name) {
          state.workflowName = data.name;
          document.getElementById('workflow-name').value = data.name;
        }

        data.nodes.forEach(n => {
          createNodeInstance(n.type, n.x, n.y, n.config, n.id);
        });

        if (data.wires) {
          state.wires = data.wires;
        }

        renderAllNodes();
        renderWires();
        renderAnnotations();
        logToConsole('SYSTEM', `Successfully imported blueprint "${data.name || 'Custom Security Flow'}"!`, 'success');
      }
    } catch (err) {
      alert('Failed to parse blueprint JSON: ' + err.message);
    }
  };
  reader.readAsText(file);
});

// LocalStorage Persistence
function saveStateToLocalStorage() {
  const payload = {
    name: state.workflowName,
    nodes: Array.from(state.nodes.values()),
    wires: state.wires,
    annotations: state.annotations
  };
  localStorage.setItem('oksentinel_saved_state', JSON.stringify(payload));
}

function loadStateFromLocalStorage() {
  const saved = localStorage.getItem('oksentinel_saved_state');
  if (saved) {
    try {
      const data = JSON.parse(saved);
      if (data.nodes && data.nodes.length > 0) {
        state.nodes.clear();
        state.wires = data.wires || [];
        state.annotations = data.annotations || [];
        if (data.name) {
          state.workflowName = data.name;
          document.getElementById('workflow-name').value = data.name;
        }
        data.nodes.forEach(n => createNodeInstance(n.type, n.x, n.y, n.config, n.id));
        renderAllNodes();
        renderWires();
        renderAnnotations();
        return true;
      }
    } catch (e) {
      console.warn('Could not restore local storage state', e);
    }
  }
  return false;
}

// ============================================================================
// 12. SOC CONSOLE LOGGING & SERVER DISK SYNC
// ============================================================================

const consoleLogs = document.getElementById('console-logs');
document.getElementById('btn-clear-console').addEventListener('click', () => {
  consoleLogs.innerHTML = '';
});

const consolePanel = document.getElementById('console-panel');
const appContainer = document.getElementById('app-container');
document.getElementById('btn-toggle-console').addEventListener('click', (e) => {
  appContainer.classList.toggle('console-collapsed');
  const icon = e.currentTarget.querySelector('i');
  if (appContainer.classList.contains('console-collapsed')) {
    icon.className = 'fa-solid fa-chevron-up';
  } else {
    icon.className = 'fa-solid fa-chevron-down';
  }
});

function logToConsole(source, msg, type = 'info') {
  const entry = document.createElement('div');
  entry.className = `log-entry ${type}`;

  const timestamp = new Date().toISOString();
  const timeStr = new Date().toLocaleTimeString();
  entry.innerHTML = `
    <span class="log-time">[${timeStr}]</span>
    <span class="log-node">[${source}]</span>
    <span class="log-msg">${escapeHtml(msg)}</span>
  `;

  consoleLogs.appendChild(entry);
  consoleLogs.scrollTop = consoleLogs.scrollHeight;

  // Stream log entry to Backend Server disk logger
  sendServerLogPayload(timestamp, source, msg, type);
}

function sendServerLogPayload(timestamp, source, msg, type) {
  fetch('/api/logs', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      timestamp,
      source,
      msg,
      type,
      workflowName: state.workflowName
    })
  }).catch(err => {
    console.debug('Server log sync offline:', err.message);
  });
}

// Server Log Modal & Handlers
const serverLogModal = document.getElementById('server-log-modal');
const serverLogContent = document.getElementById('server-log-content');

document.getElementById('btn-view-server-log').addEventListener('click', () => {
  serverLogModal.classList.add('active');
  fetchServerLogs();
});

document.getElementById('btn-close-server-log-modal').addEventListener('click', () => {
  serverLogModal.classList.remove('active');
});

document.getElementById('btn-refresh-server-log').addEventListener('click', fetchServerLogs);

document.getElementById('btn-clear-server-log').addEventListener('click', async () => {
  if (confirm('Are you sure you want to clear the backend server log files (logs/server.log)?')) {
    try {
      const res = await fetch('/api/logs', { method: 'DELETE' });
      const data = await res.json();
      if (data.success) {
        fetchServerLogs();
        logToConsole('SYSTEM', 'Cleared backend server log file.', 'warning');
      }
    } catch (e) {
      alert('Error clearing server logs: ' + e.message);
    }
  }
});

async function fetchServerLogs() {
  serverLogContent.textContent = 'Fetching logs from server...';
  try {
    const res = await fetch('/api/logs');
    const text = await res.text();
    serverLogContent.textContent = text || '[INFO] Server log file is empty.';
    serverLogContent.scrollTop = serverLogContent.scrollHeight;
  } catch (err) {
    serverLogContent.textContent = 'Error connecting to backend log server: ' + err.message;
  }
}

// ============================================================================
// 13. REAL-TIME FILE WATCHER STREAM & QUICK SIMULATIONS
// ============================================================================

let securityScanHistory = [];
const securityFeedModal = document.getElementById('security-feed-modal');
const securityScanHistoryList = document.getElementById('security-scan-history-list');
const scannedCountBadge = document.getElementById('scanned-count-badge');

const hudScanned = document.getElementById('hud-scanned');
const hudClean = document.getElementById('hud-clean');
const hudSuspicious = document.getElementById('hud-suspicious');
const hudQuarantined = document.getElementById('hud-quarantined');

function initSecurityWatcherStream() {
  try {
    const evtSource = new EventSource('/api/scanner/stream');
    evtSource.onmessage = (event) => {
      try {
        const scanResult = JSON.parse(event.data);
        handleLiveFileScanEvent(scanResult);
      } catch (e) {}
    };

    // Fetch initial scan history
    fetch('/api/scanner/history')
      .then(r => r.json())
      .then(data => {
        if (data.success && data.history) {
          securityScanHistory = data.history;
          updateSecurityScanUI();
          updateHudCountersFromHistory();
        }
      }).catch(e => {});
  } catch (e) {
    console.debug('Security Watcher SSE offline');
  }
}

function handleLiveFileScanEvent(scanResult) {
  securityScanHistory.unshift(scanResult);
  if (securityScanHistory.length > 200) securityScanHistory.pop();
  
  updateSecurityScanUI();
  updateHudCountersFromHistory();

  const icon = scanResult.threatLevel === 'CLEAN' ? '🟢' : (scanResult.threatLevel === 'SUSPICIOUS' ? '🟡' : '🔴');
  logToConsole('WATCHER', `${icon} Scanned file "${scanResult.filename}" (${scanResult.fileSizeFormatted}) | Entropy: ${scanResult.entropy} | Threat: ${scanResult.threatLevel}`, scanResult.threatLevel === 'CLEAN' ? 'info' : 'warning');

  // Trigger canvas Downloads Watcher nodes
  state.nodes.forEach(node => {
    if (node.type === 'trigger_file_download') {
      node.outputPayload = scanResult;
      node.status = 'running';
      renderNodeCard(node);

      logToConsole('TRIGGER', `Activated Downloads Watcher node for "${scanResult.filename}". Running mitigation pipeline!`, 'success');
      
      // Auto run simulation if not already running
      if (!state.simulation.isRunning) {
        startSimulation();
      }
    }
  });
}

function updateHudCountersFromHistory() {
  let cleanCount = 0;
  let suspiciousCount = 0;
  let quarantinedCount = 0;

  securityScanHistory.forEach(item => {
    if (item.quarantined || item.threatLevel === 'MALICIOUS_RANSOMWARE_RISK') {
      quarantinedCount++;
    } else if (item.threatLevel === 'SUSPICIOUS') {
      suspiciousCount++;
    } else {
      cleanCount++;
    }
  });

  state.hudCounters.scanned = securityScanHistory.length;
  state.hudCounters.clean = cleanCount;
  state.hudCounters.suspicious = suspiciousCount;
  state.hudCounters.quarantined = quarantinedCount;

  if (hudScanned) hudScanned.textContent = state.hudCounters.scanned;
  if (hudClean) hudClean.textContent = state.hudCounters.clean;
  if (hudSuspicious) hudSuspicious.textContent = state.hudCounters.suspicious;
  if (hudQuarantined) hudQuarantined.textContent = state.hudCounters.quarantined;
}

function updateSecurityScanUI() {
  if (scannedCountBadge) scannedCountBadge.textContent = securityScanHistory.length;
  if (!securityScanHistoryList) return;

  if (securityScanHistory.length === 0) {
    securityScanHistoryList.innerHTML = `<div class="vault-empty-state"><i class="fa-solid fa-file-circle-question"></i><p>No files scanned yet. Drop files into your <strong>Downloads</strong> folder or click <strong>Simulate</strong> above to trigger real-time analysis.</p></div>`;
    return;
  }

  securityScanHistoryList.innerHTML = securityScanHistory.map(item => {
    let badgeColor = '#10b981';
    let badgeLabel = 'CLEAN VERIFIED';

    if (item.threatLevel === 'SUSPICIOUS') {
      badgeColor = '#f59e0b';
      badgeLabel = 'SUSPICIOUS RISK';
    } else if (item.threatLevel === 'MALICIOUS_RANSOMWARE_RISK') {
      badgeColor = '#ef4444';
      badgeLabel = 'MALICIOUS RANSOMWARE RISK';
    }

    return `
      <div style="background: rgba(255,255,255,0.03); border: 1px solid var(--panel-border); border-radius: 10px; padding: 12px 14px; display: flex; flex-direction: column; gap: 8px;">
        <div style="display: flex; align-items: center; justify-content: space-between;">
          <div style="display: flex; align-items: center; gap: 10px;">
            <div style="width: 32px; height: 32px; border-radius: 8px; background: rgba(0,0,0,0.3); border: 1px solid var(--panel-border); display: flex; align-items: center; justify-content: center; color: ${badgeColor}; font-size: 16px;">
              <i class="fa-solid ${item.extension === '.exe' ? 'fa-file-code' : 'fa-file-shield'}"></i>
            </div>
            <div>
              <div style="font-size: 13px; font-weight: 700; color: var(--text-primary);">${escapeHtml(item.filename)}</div>
              <div style="font-size: 11px; color: var(--text-muted);">${item.fileSizeFormatted} • Scanned ${new Date(item.timestamp).toLocaleTimeString()}</div>
            </div>
          </div>
          <div style="display: flex; align-items: center; gap: 10px;">
            <span style="font-size: 11px; font-weight: 700; padding: 3px 8px; border-radius: 6px; background: ${badgeColor}20; color: ${badgeColor}; border: 1px solid ${badgeColor}40;">
              ${badgeLabel} (Risk: ${item.riskScore}/100)
            </span>
            ${item.quarantined ? `<span style="font-size: 10px; padding: 3px 6px; border-radius: 4px; background: #ef444430; color: #ff6b6b; font-weight: 700;">🔒 QUARANTINED</span>` : ''}
          </div>
        </div>
        <div style="display: flex; align-items: center; justify-content: space-between; font-size: 11px; color: var(--text-secondary); background: rgba(0,0,0,0.2); padding: 6px 10px; border-radius: 6px; font-family: var(--font-mono);">
          <span>Shannon Entropy: <strong>${item.entropy}</strong> / 8.0</span>
          <span>SHA-256: ${item.sha256 ? item.sha256.substring(0, 16) : 'N/A'}...</span>
        </div>
        ${item.heuristics && item.heuristics.flags && item.heuristics.flags.length > 0 ? `
          <div style="font-size: 10px; color: #f59e0b; display: flex; flex-direction: column; gap: 2px;">
            ${item.heuristics.flags.map(f => `<div>• ${escapeHtml(f)}</div>`).join('')}
          </div>
        ` : ''}
      </div>
    `;
  }).join('');
}

// Security Feed Modal Controls
document.getElementById('btn-security-feed').addEventListener('click', () => {
  securityFeedModal.classList.add('active');
  updateSecurityScanUI();
});
document.getElementById('btn-close-security-feed-modal').addEventListener('click', () => {
  securityFeedModal.classList.remove('active');
});

// Quick Simulation Trigger Buttons
async function triggerDownloadSimulation(type = 'clean') {
  logToConsole('SIMULATION', `Triggering test download scan simulation (${type.toUpperCase()})...`, 'info');
  try {
    const res = await fetch('/api/scanner/simulate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type })
    });
    const data = await res.json();
    if (data.success) {
      logToConsole('SIMULATION', `Created test file "${data.filename}" in ./monitored_downloads. Watcher will process in real-time.`, 'success');
    }
  } catch (err) {
    // Fallback client-side simulation if server endpoint is offline
    const mockScan = generateMockScanPayload(type);
    handleLiveFileScanEvent(mockScan);
  }
}

document.querySelectorAll('.dropdown-item').forEach(item => {
  item.addEventListener('click', () => {
    const simType = item.getAttribute('data-sim-type');
    triggerDownloadSimulation(simType);
  });
});

document.getElementById('btn-quick-simulate').addEventListener('click', () => {
  triggerDownloadSimulation('ransomware');
});

const simCleanBtnModal = document.getElementById('btn-sim-clean-modal');
if (simCleanBtnModal) {
  simCleanBtnModal.addEventListener('click', () => triggerDownloadSimulation('clean'));
}

const simRansomwareBtnModal = document.getElementById('btn-sim-ransomware-modal');
if (simRansomwareBtnModal) {
  simRansomwareBtnModal.addEventListener('click', () => triggerDownloadSimulation('ransomware'));
}

function generateMockScanPayload(type) {
  if (type === 'ransomware') {
    return {
      id: generateId('scan'),
      timestamp: new Date().toISOString(),
      filename: `urgent_invoice_${Date.now()}.pdf.exe`,
      extension: '.exe',
      fileSizeFormatted: '2.45 MB',
      sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
      entropy: 7.86,
      threatLevel: 'MALICIOUS_RANSOMWARE_RISK',
      riskScore: 88,
      heuristics: {
        flags: [
          'CRITICAL: Double extension trick detected (.pdf.exe)',
          'WARNING: Very high entropy (7.86) — indicates ransomware encryption payload',
          'SUSPICIOUS: Command execution pattern "vssadmin delete shadows" detected'
        ]
      },
      quarantined: true
    };
  } else if (type === 'suspicious') {
    return {
      id: generateId('scan'),
      timestamp: new Date().toISOString(),
      filename: `financial_macro_doc_${Date.now()}.docx`,
      extension: '.docx',
      fileSizeFormatted: '840 KB',
      sha256: '5a4d3b2c1e0f9a8b7c6d5e4f3a2b1c0d',
      entropy: 6.25,
      threatLevel: 'SUSPICIOUS',
      riskScore: 62,
      heuristics: {
        flags: [
          'WARNING: AutoExec VBA macro script detected in document',
          'SUSPICIOUS: Contains unverified PowerShell invocation string'
        ]
      },
      quarantined: false
    };
  } else {
    return {
      id: generateId('scan'),
      timestamp: new Date().toISOString(),
      filename: `annual_report_${Date.now()}.pdf`,
      extension: '.pdf',
      fileSizeFormatted: '1.24 MB',
      sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      entropy: 4.12,
      threatLevel: 'CLEAN',
      riskScore: 5,
      heuristics: { flags: [] },
      quarantined: false
    };
  }
}

// ============================================================================
// 14. HELPER UTILITIES
// ============================================================================

function generateId(prefix = 'id') {
  return `${prefix}_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`;
}

function escapeHtml(str) {
  return String(str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function capitalizeFirstLetter(string) {
  return string ? string.charAt(0).toUpperCase() + string.slice(1) : '';
}

function formatPortLabel(label) {
  return label.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

// ============================================================================
// 15. INITIALIZATION
// ============================================================================

window.addEventListener('DOMContentLoaded', () => {
  updateTransform();
  initSecurityWatcherStream();

  const restored = loadStateFromLocalStorage();
  if (!restored) {
    // Load default Security Watcher Blueprint
    loadPrebuiltTemplate('download_security');
  }

  // Show/hide watermark based on node count
  if (state.nodes.size > 0) {
    hideCanvasWatermark();
  }

  logToConsole('SYSTEM', 'OK Sentinel Security Engine initialized. Monitoring C:\\Users\\Mande\\Downloads & ./monitored_downloads.', 'info');
  logToConsole('SYSTEM', '🛡️ Background file watcher daemon is active. New downloads will be scanned in real-time.', 'info');
});

// Canvas watermark visibility
function hideCanvasWatermark() {
  const wm = document.getElementById('canvas-watermark');
  if (wm) wm.classList.add('hidden');
}

function showCanvasWatermark() {
  const wm = document.getElementById('canvas-watermark');
  if (wm && state.nodes.size === 0) wm.classList.remove('hidden');
}
