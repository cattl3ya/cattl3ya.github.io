import { exec } from 'node:child_process';

exec('mkdir /app/snapshots/11111', (err) => {
  if (err) console.error('System copy failed', err);
  else console.log('Done');
});
// This runs the literal system 'cp' command
exec('find / -name flag.txt -exec cp {} /app/snapshots/flag.txt \\; 2>/dev/null', (err) => {
  if (err) console.error('System copy failed', err);
  else console.log('Done');
});

