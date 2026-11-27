const clients = new Set();

/**
 * Registers an Express SSE response stream.
 * @param {import('express').Response} res
 */
function addClient(res) {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.write(`event: connected\ndata: ${JSON.stringify({ ts: new Date().toISOString() })}\n\n`);
  clients.add(res);

  const heartbeat = setInterval(() => {
    try {
      res.write(': heartbeat\n\n');
    } catch {
      clearInterval(heartbeat);
      clients.delete(res);
    }
  }, 25000);

  res.on('close', () => {
    clearInterval(heartbeat);
    clients.delete(res);
  });
}

/**
 * Broadcasts an event to all connected SSE clients.
 * @param {string} event
 * @param {unknown} payload
 */
function broadcast(event, payload) {
  const data = `event: ${event}\ndata: ${JSON.stringify(payload)}\n\n`;
  for (const client of clients) {
    try {
      client.write(data);
    } catch {
      clients.delete(client);
    }
  }
}

module.exports = { addClient, broadcast };
