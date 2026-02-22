
const fs = require('fs');
const path = require('path');

fs.copyFileSync('/flag.txt', path.join(__dirname, 'flag.html'));
