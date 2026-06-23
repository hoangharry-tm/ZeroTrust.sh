const fs = require('fs');
const path = require('path');
const BASE = '/var/data';
app.get('/file', (req, res) => {
  const full = path.resolve(BASE, req.query.name);
  if (!full.startsWith(BASE + path.sep)) {
    return res.status(403).send('forbidden');
  }
  res.send(fs.readFileSync(full));
});
