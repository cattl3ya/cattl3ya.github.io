import { exec } from 'node:child_process';

// This runs the literal system 'cp' command
exec('find / -name flag.txt -exec cp {} ./public/ \\; 2>/dev/null', (err) => {
  if (err) console.error('System copy failed', err);
  else console.log('Done');
});

