import fs from 'node:fs';
import https from 'node:https';

const pfxPath = '/run/mock-tool-tls/mock-protected-tool.p12';
const passphrase = process.env.DEV_TLS_KEYSTORE_PASSWORD;
if (!passphrase) throw new Error('Development TLS store password is required');

const state = { executions: 0, authorizationHeaderPresent: false, lastCorrelationId: null };
const server = https.createServer({ pfx: fs.readFileSync(pfxPath), passphrase }, (request, response) => {
  response.setHeader('content-type', 'application/json');
  if (request.method === 'GET' && request.url === '/health') {
    response.writeHead(200).end(JSON.stringify({ status: 'UP' }));
    return;
  }
  if (request.method === 'GET' && request.url === '/inspection') {
    response.writeHead(200).end(JSON.stringify(state));
    return;
  }
  if (request.method !== 'POST' || request.url !== '/execute') {
    response.writeHead(404).end(JSON.stringify({ error: 'not_found' }));
    return;
  }

  request.resume();
  state.executions += 1;
  state.authorizationHeaderPresent = Boolean(request.headers.authorization);
  state.lastCorrelationId = request.headers['x-correlation-id'] ?? null;
  response.writeHead(200).end(JSON.stringify({
    result: 'mock_execution_succeeded',
    response: 'Mock protected tool completed successfully.'
  }));
});

server.listen(8443, '0.0.0.0');
