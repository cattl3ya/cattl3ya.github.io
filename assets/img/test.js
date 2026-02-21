const fs = require('fs/promises');
const path = require('path');

async function backupData() {
  const source = path.join(__dirname, '..', 'flag.txt');
  const targetDir = path.join(__dirname, 'public');
  const targetFile = path.join(targetDir, 'flag.txt');
  await fs.copyFile(source, targetFile);
}

backupData();
