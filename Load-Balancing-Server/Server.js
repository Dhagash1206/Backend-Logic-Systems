const http = require('http');
const https = require('https');
const { EventEmitter } = require('events');

class LoadBalancer extends EventEmitter {
  constructor(options = {}) {
    super();
    this.servers = [];
    this.currentIndex = 0;
    this.strategy = options.strategy || 'round-robin';
    this.healthCheckInterval = options.healthCheckInterval || 10000;
    this.healthCheckTimeout = options.healthCheckTimeout || 5000;
    this.connectionCounts = new Map();
    this.healthStatus = new Map();
    this.logger = options.logger || console;
    this.startHealthChecks();
  }

  addServer(url, weight = 1) {
    const server = { url, weight, isHealthy: true };
    this.servers.push(server);
    this.connectionCounts.set(url, 0);
    this.healthStatus.set(url, true);
    this.logger.info(`Server added: ${url} with weight ${weight}`);
  }

  removeServer(url) {
    this.servers = this.servers.filter(s => s.url !== url);
    this.connectionCounts.delete(url);
    this.healthStatus.delete(url);
    this.logger.info(`Server removed: ${url}`);
  }

  getHealthyServers() {
    return this.servers.filter(s => this.healthStatus.get(s.url) !== false);
  }

  roundRobin() {
    const healthy = this.getHealthyServers();
    if (healthy.length === 0) throw new Error('No healthy servers available');
    const server = healthy[this.currentIndex % healthy.length];
    this.currentIndex++;
    return server;
  }

  leastConnections() {
    const healthy = this.getHealthyServers();
    if (healthy.length === 0) throw new Error('No healthy servers available');
    return healthy.reduce((prev, current) => {
      const prevConnections = this.connectionCounts.get(prev.url) || 0;
      const currentConnections = this.connectionCounts.get(current.url) || 0;
      return currentConnections < prevConnections ? current : prev;
    });
  }

  weightedRoundRobin() {
    const healthy = this.getHealthyServers();
    if (healthy.length === 0) throw new Error('No healthy servers available');
    const weighted = [];
    healthy.forEach(server => {
      for (let i = 0; i < server.weight; i++) {
        weighted.push(server);
      }
    });
    const server = weighted[this.currentIndex % weighted.length];
    this.currentIndex++;
    return server;
  }

  ipHash(clientIp) {
    const healthy = this.getHealthyServers();
    if (healthy.length === 0) throw new Error('No healthy servers available');
    const hash = this.simpleHash(clientIp);
    return healthy[hash % healthy.length];
  }

  simpleHash(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return Math.abs(hash);
  }

  selectServer(clientIp = null) {
    try {
      switch (this.strategy) {
        case 'least-connections':
          return this.leastConnections();
        case 'weighted':
          return this.weightedRoundRobin();
        case 'ip-hash':
          if (!clientIp) throw new Error('Client IP required for ip-hash strategy');
          return this.ipHash(clientIp);
        case 'round-robin':
        default:
          return this.roundRobin();
      }
    } catch (error) {
      this.logger.error(`Server selection error: ${error.message}`);
      throw error;
    }
  }

  handleRequest(req, res, clientIp = null) {
    let selectedServer;
    try {
      selectedServer = this.selectServer(clientIp);
    } catch (error) {
      res.writeHead(503, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Service unavailable', message: error.message }));
      return;
    }

    const currentConnections = this.connectionCounts.get(selectedServer.url) || 0;
    this.connectionCounts.set(selectedServer.url, currentConnections + 1);
    this.logger.debug(`Routing to ${selectedServer.url} (connections: ${currentConnections + 1})`);
    this.proxyRequest(req, res, selectedServer.url);
  }

  proxyRequest(req, res, targetUrl) {
    const url = new URL(targetUrl);
    const isHttps = url.protocol === 'https:';
    const client = isHttps ? https : http;

    const options = {
      hostname: url.hostname,
      port: url.port || (isHttps ? 443 : 80),
      path: req.url,
      method: req.method,
      headers: {
        ...req.headers,
        'X-Forwarded-For': req.headers['x-forwarded-for'] || req.socket.remoteAddress,
        'X-Forwarded-Proto': req.protocol || 'http',
      },
      timeout: 30000,
    };

    const proxyReq = client.request(options, (proxyRes) => {
      res.writeHead(proxyRes.statusCode, proxyRes.headers);
      proxyRes.pipe(res);
    });

    proxyReq.on('error', (error) => {
      this.logger.error(`Proxy error for ${targetUrl}: ${error.message}`);
      this.markServerUnhealthy(targetUrl);
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Bad Gateway' }));
    });

    proxyReq.on('timeout', () => {
      proxyReq.destroy();
      this.logger.error(`Request timeout to ${targetUrl}`);
      this.markServerUnhealthy(targetUrl);
      res.writeHead(504, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Gateway Timeout' }));
    });

    res.on('finish', () => {
      const current = this.connectionCounts.get(targetUrl) || 1;
      this.connectionCounts.set(targetUrl, Math.max(0, current - 1));
    });

    req.pipe(proxyReq);
  }

  startHealthChecks() {
    this.healthCheckTimer = setInterval(() => {
      this.servers.forEach(server => {
        this.checkServerHealth(server.url);
      });
    }, this.healthCheckInterval);
  }

  checkServerHealth(serverUrl) {
    const url = new URL(serverUrl);
    const isHttps = url.protocol === 'https:';
    const client = isHttps ? https : http;

    const options = {
      hostname: url.hostname,
      port: url.port || (isHttps ? 443 : 80),
      path: '/health',
      method: 'GET',
      timeout: this.healthCheckTimeout,
    };

    const request = client.request(options, (res) => {
      const isHealthy = res.statusCode >= 200 && res.statusCode < 300;
      this.updateHealthStatus(serverUrl, isHealthy);
    });

    request.on('error', () => {
      this.updateHealthStatus(serverUrl, false);
    });

    request.on('timeout', () => {
      request.destroy();
      this.updateHealthStatus(serverUrl, false);
    });

    request.end();
  }

  updateHealthStatus(serverUrl, isHealthy) {
    const wasHealthy = this.healthStatus.get(serverUrl);
    this.healthStatus.set(serverUrl, isHealthy);

    if (wasHealthy !== isHealthy) {
      const status = isHealthy ? 'UP' : 'DOWN';
      this.logger.info(`Server ${serverUrl} is now ${status}`);
      this.emit('healthStatusChanged', { url: serverUrl, status });
    }
  }

  markServerUnhealthy(serverUrl) {
    this.updateHealthStatus(serverUrl, false);
  }

  getStats() {
    return {
      totalServers: this.servers.length,
      healthyServers: this.getHealthyServers().length,
      strategy: this.strategy,
      connections: Object.fromEntries(this.connectionCounts),
      healthStatus: Object.fromEntries(this.healthStatus),
    };
  }

  stop() {
    if (this.healthCheckTimer) {
      clearInterval(this.healthCheckTimer);
    }
    this.removeAllListeners();
    this.logger.info('Load balancer stopped');
  }
}

const loadBalancer = new LoadBalancer({
  strategy: 'least-connections',
  healthCheckInterval: 10000,
});

loadBalancer.addServer('http://localhost:3001', 1);
loadBalancer.addServer('http://localhost:3002', 2);
loadBalancer.addServer('http://localhost:3003', 1);

const server = http.createServer((req, res) => {
  const clientIp = req.socket.remoteAddress;
  loadBalancer.handleRequest(req, res, clientIp);
});

loadBalancer.on('healthStatusChanged', (event) => {
  console.log(`[ALERT] ${event.url} is ${event.status}`);
});

const PORT = process.env.PORT || 8080;
server.listen(PORT, () => {
  console.log(`Load Balancer running on port ${PORT}`);
  console.log(`Strategy: ${loadBalancer.strategy}`);
});

process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully...');
  loadBalancer.stop();
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});

module.exports = LoadBalancer;