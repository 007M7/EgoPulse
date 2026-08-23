const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const manifestPath = path.join(root, 'manifest.json');
const excludedDirectories = new Set([
  '.git', '.tools', '.venv', 'evidence', 'generated', 'node_modules', 'target',
]);

function walk(directory) {
  const files = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if (entry.isDirectory() && excludedDirectories.has(entry.name)) continue;
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...walk(absolute));
    else if (absolute !== manifestPath && entry.name !== '.gitignore') files.push(absolute);
  }
  return files;
}

const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
manifest.artifacts = walk(root)
  .map((absolute) => ({
    path: path.relative(root, absolute).replace(/\\/g, '/'),
    sha256: crypto.createHash('sha256').update(fs.readFileSync(absolute)).digest('hex'),
  }))
  .sort((left, right) => left.path.localeCompare(right.path, 'en'));

fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
console.log(`refreshed_manifest_artifacts=${manifest.artifacts.length}`);
