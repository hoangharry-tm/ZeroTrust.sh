const { spawn } = require('child_process');
app.get('/ping', (req, res) => {
  const host = req.query.host.replace(/[^a-z0-9.-]/gi, '');
  const proc = spawn('ping', ['-c', '1', host]);
  proc.stdout.on('data', d => res.write(d));
  proc.on('close', () => res.end());
});
