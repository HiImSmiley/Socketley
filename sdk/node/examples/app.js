// A program with its own website, API, cache and MCP tools: `node app.js 8080 ./public`, then
//   curl localhost:8080/api/count
//   claude mcp add --transport http app http://127.0.0.1:9600/mcp
const { Engine } = require('socketley');

const port = Number(process.argv[2] || 8080);
const root = require('path').resolve(process.argv[3] || '.');

const engine = new Engine();
const kv = engine.runtime('cache', 'kv', `-p ${port + 1}`).start();
kv.command('set count 0');

const site = engine.runtime('web', 'site', `-p ${port} --root ${root}`);
site.handle('/api/count', () => kv.command('incr count'));
site.start();

const tools = engine.runtime('mcp', 'tools', '-p 9600 --anonymous');
tools.tool('count', { description: 'How often /api/count was asked.' }, () => kv.command('get count'));
tools.start();

process.on('SIGTERM', () => engine.close());
process.on('SIGINT', () => engine.close());
