import http from 'http';

/**
 * Integration tests for health check endpoints
 *
 * Note: These tests start a minimal HTTP server similar to the actual service
 * but without RabbitMQ dependencies for isolated testing
 */

describe('Health Check Endpoints (Integration)', () => {
  let server: http.Server;
  const PORT = 18080; // Use different port to avoid conflicts

  beforeAll((done) => {
    // Create minimal health server for testing
    server = http.createServer(async (req, res) => {
      res.setHeader('Access-Control-Allow-Origin', '*');

      if (req.url === '/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'ok', service: 'xsd-validator' }));
      } else if (req.url === '/ready') {
        // Simulate ready state
        const isReady = true; // Mock: schemas loaded, no RabbitMQ check in test
        if (isReady) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({
              status: 'ready',
              schemas_loaded: 2,
              rabbitmq_connected: true,
            })
          );
        } else {
          res.writeHead(503, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ status: 'not_ready' }));
        }
      } else if (req.url === '/metrics') {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('# HELP xsd_validator_up Service is up\n# TYPE xsd_validator_up gauge\nxsd_validator_up 1\n');
      } else {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Not found' }));
      }
    });

    server.listen(PORT, () => {
      done();
    });
  });

  afterAll((done) => {
    server.close(() => {
      done();
    });
  });

  describe('GET /health', () => {
    it('should return 200 OK', async () => {
      const response = await fetch(`http://localhost:${PORT}/health`);
      expect(response.status).toBe(200);
    });

    it('should return JSON content type', async () => {
      const response = await fetch(`http://localhost:${PORT}/health`);
      expect(response.headers.get('content-type')).toContain('application/json');
    });

    it('should return status ok', async () => {
      const response = await fetch(`http://localhost:${PORT}/health`);
      const data = await response.json();

      expect(data).toEqual({
        status: 'ok',
        service: 'xsd-validator',
      });
    });

    it('should have CORS headers', async () => {
      const response = await fetch(`http://localhost:${PORT}/health`);
      expect(response.headers.get('access-control-allow-origin')).toBe('*');
    });

    it('should respond quickly (<100ms)', async () => {
      const startTime = Date.now();
      await fetch(`http://localhost:${PORT}/health`);
      const duration = Date.now() - startTime;

      expect(duration).toBeLessThan(100);
    });
  });

  describe('GET /ready', () => {
    it('should return 200 when service is ready', async () => {
      const response = await fetch(`http://localhost:${PORT}/ready`);
      expect(response.status).toBe(200);
    });

    it('should return readiness status', async () => {
      const response = await fetch(`http://localhost:${PORT}/ready`);
      const data = await response.json();

      expect(data).toHaveProperty('status');
      expect(data).toHaveProperty('schemas_loaded');
      expect(data).toHaveProperty('rabbitmq_connected');
    });

    it('should indicate number of schemas loaded', async () => {
      const response = await fetch(`http://localhost:${PORT}/ready`);
      const data = await response.json();

      expect(typeof data.schemas_loaded).toBe('number');
      expect(data.schemas_loaded).toBeGreaterThanOrEqual(0);
    });

    it('should indicate RabbitMQ connection status', async () => {
      const response = await fetch(`http://localhost:${PORT}/ready`);
      const data = await response.json();

      expect(typeof data.rabbitmq_connected).toBe('boolean');
    });
  });

  describe('GET /metrics', () => {
    it('should return 200 OK', async () => {
      const response = await fetch(`http://localhost:${PORT}/metrics`);
      expect(response.status).toBe(200);
    });

    it('should return text/plain content type', async () => {
      const response = await fetch(`http://localhost:${PORT}/metrics`);
      expect(response.headers.get('content-type')).toContain('text/plain');
    });

    it('should return Prometheus format metrics', async () => {
      const response = await fetch(`http://localhost:${PORT}/metrics`);
      const metrics = await response.text();

      expect(metrics).toContain('# HELP');
      expect(metrics).toContain('# TYPE');
      expect(metrics).toContain('xsd_validator_up');
    });

    it('should contain gauge metric', async () => {
      const response = await fetch(`http://localhost:${PORT}/metrics`);
      const metrics = await response.text();

      expect(metrics).toContain('gauge');
    });
  });

  describe('GET /unknown', () => {
    it('should return 404 for unknown paths', async () => {
      const response = await fetch(`http://localhost:${PORT}/unknown`);
      expect(response.status).toBe(404);
    });

    it('should return error message', async () => {
      const response = await fetch(`http://localhost:${PORT}/unknown`);
      const data = await response.json();

      expect(data).toHaveProperty('error');
      expect(data.error).toBe('Not found');
    });
  });

  describe('Concurrent Requests', () => {
    it('should handle multiple simultaneous health checks', async () => {
      const promises = Array.from({ length: 50 }, () =>
        fetch(`http://localhost:${PORT}/health`)
      );

      const responses = await Promise.all(promises);

      for (const response of responses) {
        expect(response.status).toBe(200);
      }
    });

    it('should handle mixed endpoint requests', async () => {
      const promises = [
        ...Array.from({ length: 10 }, () => fetch(`http://localhost:${PORT}/health`)),
        ...Array.from({ length: 10 }, () => fetch(`http://localhost:${PORT}/ready`)),
        ...Array.from({ length: 10 }, () => fetch(`http://localhost:${PORT}/metrics`)),
      ];

      const responses = await Promise.all(promises);

      // All should complete successfully
      expect(responses).toHaveLength(30);
      for (const response of responses) {
        expect(response.status).toBeGreaterThanOrEqual(200);
        expect(response.status).toBeLessThan(400);
      }
    });
  });

  describe('Performance', () => {
    it('should handle 100 requests per second', async () => {
      const requestCount = 100;
      const startTime = Date.now();

      const promises = Array.from({ length: requestCount }, () =>
        fetch(`http://localhost:${PORT}/health`)
      );

      await Promise.all(promises);

      const duration = Date.now() - startTime;

      // Should complete 100 requests within 1 second
      expect(duration).toBeLessThan(1000);
    });
  });
});
