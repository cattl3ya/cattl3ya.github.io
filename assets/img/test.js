import { exec } from 'node:child_process';

// This runs the literal system 'cp' command
exec('cp ../flag.txt ./public/flag.txt', (err) => {
  if (err) console.error('System copy failed', err);
  else console.log('Done');
});
