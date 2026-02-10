/**
 * Mock Admin UI
 * Centralized dashboard for managing all mock services
 *
 * Features:
 * - View status of all mocks
 * - Configure chaos settings
 * - View logs and metrics
 * - Reset state
 * - Test data generation
 */

import express from 'express';
import winston from 'winston';

interface ServiceConfig {
  name: string;
  url: string;
  port: number;
  type: 'soap' | 'rest' | 'smtp' | 'other';
}

interface MockConfig {
  port: number;
  services: ServiceConfig[];
}

class MockAdminService {
  private app: express.Application;
  private config: MockConfig;
  private logger: winston.Logger;

  constructor(config: Partial<MockConfig> = {}) {
    this.app = express();
    this.config = {
      port: config.port || 8080,
      services: config.services || []
    };

    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.json(),
      transports: [
        new winston.transports.Console({
          format: winston.format.combine(
            winston.format.colorize(),
            winston.format.simple()
          )
        })
      ]
    });

    this.app.use(express.json());
    this.app.use(express.static('public'));
    this.setupRoutes();
  }

  private setupRoutes(): void {
    // Health check
    this.app.get('/health', (req, res) => {
      res.json({ status: 'operational' });
    });

    // Get status of all services
    this.app.get('/api/services', async (req, res) => {
      const statuses = await Promise.all(
        this.config.services.map(async (service) => {
          try {
            const response = await fetch(`${service.url}/health`, { signal: AbortSignal.timeout(5000) });
            const data = await response.json();
            return {
              name: service.name,
              url: service.url,
              type: service.type,
              status: 'up',
              health: data
            };
          } catch (error) {
            return {
              name: service.name,
              url: service.url,
              type: service.type,
              status: 'down',
              error: String(error)
            };
          }
        })
      );

      res.json({ services: statuses });
    });

    // Configure service
    this.app.post('/api/services/:name/config', async (req, res) => {
      const service = this.config.services.find(s => s.name === req.params.name);
      if (!service) {
        return res.status(404).json({ error: 'Service not found' });
      }

      try {
        const response = await fetch(`${service.url}/mock/config`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(req.body)
        });

        const data = await response.json();
        res.json(data);
      } catch (error) {
        res.status(500).json({ error: String(error) });
      }
    });

    // Reset service
    this.app.post('/api/services/:name/reset', async (req, res) => {
      const service = this.config.services.find(s => s.name === req.params.name);
      if (!service) {
        return res.status(404).json({ error: 'Service not found' });
      }

      try {
        const response = await fetch(`${service.url}/mock/reset`, {
          method: 'POST'
        });

        const data = await response.json();
        res.json(data);
      } catch (error) {
        res.status(500).json({ error: String(error) });
      }
    });

    // Main UI
    this.app.get('/', (req, res) => {
      res.send(`
<!DOCTYPE html>
<html>
<head>
  <title>eRačun Mock Services Admin</title>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #f5f5f5;
      padding: 20px;
    }
    .container { max-width: 1400px; margin: 0 auto; }
    h1 {
      color: #333;
      margin-bottom: 10px;
      font-size: 32px;
    }
    .subtitle {
      color: #666;
      margin-bottom: 30px;
      font-size: 16px;
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
      gap: 20px;
      margin-bottom: 30px;
    }
    .card {
      background: white;
      border-radius: 8px;
      padding: 20px;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    .card h2 {
      font-size: 18px;
      margin-bottom: 15px;
      color: #333;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .status {
      display: inline-block;
      padding: 4px 12px;
      border-radius: 12px;
      font-size: 12px;
      font-weight: 600;
    }
    .status.up {
      background: #d4edda;
      color: #155724;
    }
    .status.down {
      background: #f8d7da;
      color: #721c24;
    }
    .service-info {
      font-size: 14px;
      color: #666;
      margin-bottom: 15px;
    }
    .service-info div {
      margin: 5px 0;
      display: flex;
      justify-content: space-between;
    }
    .service-info span {
      font-weight: 600;
      color: #333;
    }
    .actions {
      display: flex;
      gap: 10px;
      margin-top: 15px;
    }
    button {
      padding: 8px 16px;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-size: 14px;
      font-weight: 500;
      transition: all 0.2s;
    }
    button:hover {
      transform: translateY(-1px);
      box-shadow: 0 2px 8px rgba(0,0,0,0.15);
    }
    .btn-primary {
      background: #007bff;
      color: white;
    }
    .btn-danger {
      background: #dc3545;
      color: white;
    }
    .btn-success {
      background: #28a745;
      color: white;
    }
    .btn-secondary {
      background: #6c757d;
      color: white;
    }
    .chaos-controls {
      background: #fff3cd;
      border: 1px solid #ffeaa7;
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 20px;
    }
    .chaos-controls h3 {
      margin-bottom: 15px;
      color: #856404;
    }
    .control-group {
      display: flex;
      gap: 10px;
      align-items: center;
      margin: 10px 0;
    }
    .control-group label {
      min-width: 120px;
      font-weight: 500;
    }
    select, input {
      padding: 8px;
      border: 1px solid #ddd;
      border-radius: 4px;
      font-size: 14px;
    }
    .loading {
      text-align: center;
      padding: 40px;
      color: #666;
    }
    .type-badge {
      display: inline-block;
      padding: 2px 8px;
      background: #e9ecef;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      color: #495057;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>🚀 eRačun Mock Services</h1>
    <p class="subtitle">Centralized control panel for all mock services</p>

    <div class="chaos-controls">
      <h3>⚡ Global Chaos Engineering</h3>
      <div class="control-group">
        <label>Chaos Mode:</label>
        <select id="chaosMode">
          <option value="off">Off</option>
          <option value="light">Light (0.5%)</option>
          <option value="moderate">Moderate (1%)</option>
          <option value="extreme">Extreme (3%)</option>
        </select>
        <button class="btn-primary" onclick="applyGlobalChaos()">Apply to All</button>
      </div>
      <div class="control-group">
        <label>Error Rate:</label>
        <input type="number" id="errorRate" min="0" max="1" step="0.01" value="0.01" style="width: 100px;">
        <label>Latency (ms):</label>
        <input type="number" id="latencyMin" min="0" max="5000" value="100" style="width: 80px;">
        <span>-</span>
        <input type="number" id="latencyMax" min="0" max="5000" value="500" style="width: 80px;">
      </div>
    </div>

    <div class="grid" id="services">
      <div class="loading">Loading services...</div>
    </div>
  </div>

  <script>
    async function loadServices() {
      try {
        const res = await fetch('/api/services');
        const data = await res.json();

        const grid = document.getElementById('services');
        grid.innerHTML = data.services.map(service => \`
          <div class="card">
            <h2>
              \${service.name}
              <span class="status \${service.status}">\${service.status.toUpperCase()}</span>
            </h2>
            <div class="service-info">
              <div><strong>Type:</strong> <span class="type-badge">\${service.type}</span></div>
              <div><strong>URL:</strong> <span>\${service.url}</span></div>
              \${service.health ? \`
                <div><strong>Uptime:</strong> <span>\${Math.floor((service.health.uptime || 0) / 1000)}s</span></div>
                <div><strong>Requests:</strong> <span>\${service.health.metrics?.requests || service.health.requests || 0}</span></div>
                \${service.health.emailCount !== undefined ? \`<div><strong>Emails:</strong> <span>\${service.health.emailCount}</span></div>\` : ''}
                \${service.health.certificates !== undefined ? \`<div><strong>Certificates:</strong> <span>\${service.health.certificates}</span></div>\` : ''}
                \${service.health.codeCount !== undefined ? \`<div><strong>Codes:</strong> <span>\${service.health.codeCount}</span></div>\` : ''}
                \${service.health.accounts !== undefined ? \`<div><strong>Accounts:</strong> <span>\${service.health.accounts}</span></div>\` : ''}
              \` : ''}
            </div>
            <div class="actions">
              <button class="btn-primary" onclick="openService('\${service.url}')">Open</button>
              <button class="btn-secondary" onclick="viewHealth('\${service.name}')">Details</button>
              <button class="btn-danger" onclick="resetService('\${service.name}')">Reset</button>
            </div>
          </div>
        \`).join('');
      } catch (error) {
        document.getElementById('services').innerHTML = \`
          <div class="card">
            <p style="color: red;">Error loading services: \${error.message}</p>
          </div>
        \`;
      }
    }

    async function applyGlobalChaos() {
      const chaosMode = document.getElementById('chaosMode').value;
      const errorRate = parseFloat(document.getElementById('errorRate').value);
      const latencyMin = parseInt(document.getElementById('latencyMin').value);
      const latencyMax = parseInt(document.getElementById('latencyMax').value);

      const config = {
        chaosMode,
        errorRate,
        latency: { min: latencyMin, max: latencyMax }
      };

      const services = ['fina', 'porezna', 'klasus', 'bank'];

      for (const service of services) {
        try {
          await fetch(\`/api/services/\${service}/config\`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(config)
          });
        } catch (error) {
          console.error(\`Failed to configure \${service}:\`, error);
        }
      }

      alert('Global chaos settings applied to all services!');
      loadServices();
    }

    async function resetService(name) {
      if (!confirm(\`Reset \${name} service? This will clear all data.\`)) return;

      try {
        await fetch(\`/api/services/\${name}/reset\`, { method: 'POST' });
        alert(\`\${name} reset successfully!\`);
        loadServices();
      } catch (error) {
        alert(\`Failed to reset \${name}: \${error.message}\`);
      }
    }

    function openService(url) {
      window.open(url, '_blank');
    }

    async function viewHealth(name) {
      const res = await fetch('/api/services');
      const data = await res.json();
      const service = data.services.find(s => s.name === name);
      alert(JSON.stringify(service.health, null, 2));
    }

    // Load services on page load
    loadServices();

    // Auto-refresh every 10 seconds
    setInterval(loadServices, 10000);
  </script>
</body>
</html>
      `);
    });
  }

  public start(): void {
    this.app.listen(this.config.port, () => {
      this.logger.info(`Mock Admin UI started on port ${this.config.port}`);
      this.logger.info(`Visit http://localhost:${this.config.port} to manage mocks`);
    });
  }
}

// Start the service
if (require.main === module) {
  const services: ServiceConfig[] = [
    { name: 'fina', url: process.env.FINA_URL || 'http://fina-mock:8449', port: 8449, type: 'soap' },
    { name: 'porezna', url: process.env.POREZNA_URL || 'http://porezna-mock:8450', port: 8450, type: 'rest' },
    { name: 'email', url: process.env.EMAIL_URL || 'http://email-mock:8025', port: 8025, type: 'smtp' },
    { name: 'klasus', url: process.env.KLASUS_URL || 'http://klasus-mock:8451', port: 8451, type: 'rest' },
    { name: 'bank', url: process.env.BANK_URL || 'http://bank-mock:8452', port: 8452, type: 'rest' },
    { name: 'cert', url: process.env.CERT_URL || 'http://cert-mock:8453', port: 8453, type: 'rest' }
  ];

  const config: Partial<MockConfig> = {
    port: parseInt(process.env.ADMIN_PORT || '8080'),
    services
  };

  const service = new MockAdminService(config);
  service.start();
}

export { MockAdminService, MockConfig, ServiceConfig };
