const http = require('http');
const https = require('https');
const crypto = require('crypto');
const { EventEmitter } = require('events');

const HOP_BY_HOP = ['connection', 'keep-alive', 'proxy-connection', 'transfer-encoding', 'upgrade', 'te', 'trailer'];

class LoadBalancer extends EventEmitter {
  constructor(options = {}) {
    super();
    this.servers = [];
    this.serverMap = new Map();
    this.ring = [];
    this.currentIndex = 0;
    this.strategy = options.strategy || 'round-robin';
    this.healthCheckInterval = options.healthCheckInterval || 10000;
    this.healthCheckTimeout = options.healthCheckTimeout || 5000;
    this.drainTimeout = options.drainTimeout || 30000;
    this.virtualNodes = options.virtualNodes || 100;
    this.connectionCounts = new Map();
    this.healthStatus = new Map();
    this.drainTimers = new Map();
    this.logger = options.logger || console;
    // reuse sockets to the backends instead of opening a new one per request
    const agentOptions = {
      keepAlive: true,
      keepAliveMsecs: 1000,
      maxSockets: options.maxSockets || 100,
      maxFreeSockets: options.maxFreeSockets || 20,
    };
    this.httpAgent = new http.Agent(agentOptions);
    this.httpsAgent = new https.Agent(agentOptions);

    this.startHealthChecks();
  }

  // server management
  addServer(url, weight = 1) {
    if (this.serverMap.has(url)) {
      this.logger.warn(`Server already exists: ${url}`);
      return;
    }
    const server = { url, weight, isHealthy: true, draining: false };
    this.servers.push(server);
    this.serverMap.set(url, server);
    this.connectionCounts.set(url, 0);
    this.healthStatus.set(url, true);
    this.buildRing();
    this.logger.info(`Server added: ${url} with weight ${weight}`);
  }
  // stops new traffic, removes the server once in-flight requests finish or the timeout hits
  removeServer(url, { drain = true, timeout = this.drainTimeout } = {}) {
    const server = this.serverMap.get(url);
    if (!server) return;

    const active = this.connectionCounts.get(url) || 0;
    if (!drain || active === 0) {
      this.finalizeRemoval(url);
      return;
    }

    server.draining = true;
    this.logger.info(`Draining ${url} (${active} active connections)`);
    this.emit('draining', { url, active });

    const timer = setTimeout(() => {
      this.logger.warn(`Drain timeout for ${url}, removing with active connections`);
      this.finalizeRemoval(url);
    }, timeout);
    timer.unref();
    this.drainTimers.set(url, timer);
  }

  finalizeRemoval(url) {
    const timer = this.drainTimers.get(url);
    if (timer) {
      clearTimeout(timer);
      this.drainTimers.delete(url);
    }
    this.servers = this.servers.filter(s => s.url !== url);
    this.serverMap.delete(url);
    this.connectionCounts.delete(url);
    this.healthStatus.delete(url);
    this.buildRing();
    this.logger.info(`Server removed: ${url}`);
  }

  getHealthyServers() {
    return this.servers.filter(s => !s.draining && this.healthStatus.get(s.url) !== false);
  }

  // consistent hash ring, so ip-hash doesn't reshuffle everyone when a server goes down
  hash32(str) {
    return crypto.createHash('md5').update(str).digest().readUInt32BE(0);
  }

  buildRing() {
    const ring = [];
    for (const server of this.servers) {
      const nodes = this.virtualNodes * Math.max(1, server.weight);
      for (let i = 0; i < nodes; i++) {
        ring.push({ point: this.hash32(`${server.url}#${i}`), url: server.url });
      }
    }
    ring.sort((a, b) => a.point - b.point);
    this.ring = ring;
  }

  ipHash(clientIp) {
    if (this.ring.length === 0) throw new Error('No healthy servers available');

    const h = this.hash32(clientIp);
    // first ring point >= h
    let lo = 0;
    let hi = this.ring.length;
    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      if (this.ring[mid].point < h) lo = mid + 1;
      else hi = mid;
    }
    // walk clockwise to the next healthy server.
    // unhealthy ones stay in the ring so only their own clients move
    for (let i = 0; i < this.ring.length; i++) {
      const entry = this.ring[(lo + i) % this.ring.length];
      const server = this.serverMap.get(entry.url);
      if (server && !server.draining && this.healthStatus.get(server.url) !== false) {
        return server;
      }
    }
    throw new Error('No healthy servers available');
  }

  // selection strategies
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

  // request handling
  acquireConnection(url) {
    this.connectionCounts.set(url, (this.connectionCounts.get(url) || 0) + 1);
  }

  releaseConnection(url) {
    if (!this.connectionCounts.has(url)) return;
    const next = Math.max(0, (this.connectionCounts.get(url) || 1) - 1);
    this.connectionCounts.set(url, next);

    const server = this.serverMap.get(url);
    if (server && server.draining && next === 0) {
      this.finalizeRemoval(url);
    }
  }

  getTotalConnections() {
    let total = 0;
    for (const count of this.connectionCounts.values()) total += count;
    return total;
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

    const targetUrl = selectedServer.url;
    this.acquireConnection(targetUrl);
    this.logger.debug(`Routing to ${targetUrl} (connections: ${this.connectionCounts.get(targetUrl)})`);
    // 'close' fires on finish and on client abort, so the counter can't leak
    let released = false;
    res.on('close', () => {
      if (released) return;
      released = true;
      this.releaseConnection(targetUrl);
    });

    this.proxyRequest(req, res, targetUrl);
  }

  proxyRequest(req, res, targetUrl) {
    const url = new URL(targetUrl);
    const isHttps = url.protocol === 'https:';
    const client = isHttps ? https : http;

    const headers = { ...req.headers };
    HOP_BY_HOP.forEach(h => delete headers[h]);
    headers['x-forwarded-for'] = req.headers['x-forwarded-for']
      ? `${req.headers['x-forwarded-for']}, ${req.socket.remoteAddress}`
      : req.socket.remoteAddress;
    headers['x-forwarded-proto'] = req.socket.encrypted ? 'https' : 'http';

    const options = {
      hostname: url.hostname,
      port: url.port || (isHttps ? 443 : 80),
      path: req.url,
      method: req.method,
      headers,
      timeout: 30000,
      agent: isHttps ? this.httpsAgent : this.httpAgent,
    };

    const fail = (status, message) => {
      if (res.headersSent) {
        res.destroy();
        return;
      }
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: message }));
    };

    const proxyReq = client.request(options, (proxyRes) => {
      res.writeHead(proxyRes.statusCode, proxyRes.headers);
      proxyRes.pipe(res);
    });

    proxyReq.on('error', (error) => {
      if (res.destroyed) return;
      this.logger.error(`Proxy error for ${targetUrl}: ${error.message}`);
      this.markServerUnhealthy(targetUrl);
      fail(502, 'Bad Gateway');
    });

    proxyReq.on('timeout', () => {
      this.logger.error(`Request timeout to ${targetUrl}`);
      this.markServerUnhealthy(targetUrl);
      proxyReq.destroy();
      fail(504, 'Gateway Timeout');
    });
    // client left early, drop the backend request
    res.on('close', () => {
      if (!res.writableFinished) proxyReq.destroy();
    });

    req.pipe(proxyReq);
  }

  // health checks
  startHealthChecks() {
    this.healthCheckTimer = setInterval(() => {
      this.servers.forEach(server => {
        this.checkServerHealth(server.url);
      });
    }, this.healthCheckInterval);
    this.healthCheckTimer.unref();
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
      agent: isHttps ? this.httpsAgent : this.httpAgent,
    };

    const request = client.request(options, (res) => {
      const isHealthy = res.statusCode >= 200 && res.statusCode < 300;
      res.resume(); // let the socket go back to the pool
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
    // server may have been removed while the check was running
    if (!this.healthStatus.has(serverUrl)) return;

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
      drainingServers: this.servers.filter(s => s.draining).map(s => s.url),
      strategy: this.strategy,
      connections: Object.fromEntries(this.connectionCounts),
      healthStatus: Object.fromEntries(this.healthStatus),
    };
  }
  // wait for in-flight requests (up to timeout) before tearing down
  async stop(timeout = this.drainTimeout) {
    if (this.healthCheckTimer) {
      clearInterval(this.healthCheckTimer);
    }

    const deadline = Date.now() + timeout;
    while (this.getTotalConnections() > 0 && Date.now() < deadline) {
      await new Promise(resolve => setTimeout(resolve, 100));
    }

    this.drainTimers.forEach(timer => clearTimeout(timer));
    this.drainTimers.clear();
    this.httpAgent.destroy();
    this.httpsAgent.destroy();
    this.removeAllListeners();
    this.logger.info('Load balancer stopped');
  }
}

const loadBalancer = new LoadBalancer({
  strategy: 'least-connections',
  healthCheckInterval: 10000,
  drainTimeout: 30000,
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

let shuttingDown = false;
process.on('SIGTERM', () => {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log('SIGTERM received, shutting down gracefully...');
  // stop accepting new connections, close idle keep-alive sockets
  server.close(async () => {
    await loadBalancer.stop();
    console.log('Server closed');
    process.exit(0);
  });
  server.closeIdleConnections();
  // force exit if draining takes too long
  setTimeout(() => process.exit(1), 35000).unref();
});

module.exports = LoadBalancer;
