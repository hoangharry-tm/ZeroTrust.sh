const fs = require('fs');
const path = require('path');
app.get('/file', (req, res) => {
  const filePath = path.join('/var/data', req.query.name);
  res.send(fs.readFileSync(filePath));
});
