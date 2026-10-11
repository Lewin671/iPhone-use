import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { mkdtemp, mkdir, writeFile, chmod, symlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { once } from 'node:events';
import { loadToken, authorized } from '../tooling/auth.mjs';
const token = 'a'.repeat(64);
const root = new URL('../', import.meta.url);
async function directory() { return await mkdtemp(join(tmpdir(), 'iphone-auth-test-')); }
async function credential(dir) { const path = join(dir, 'control-token'); await writeFile(path, token+'\n', { mode: 0o600 }); return path; }
test('credentials reject missing files, symlinks, broad permissions and malformed values', async () => {
  const dir = await directory();
  try {
    assert.throws(() => loadToken(join(dir, 'missing')));
    const path = await credential(dir); assert.equal(loadToken(path), token);
    await symlink(path, join(dir, 'link')); assert.throws(() => loadToken(join(dir,'link')));
    await chmod(path,0o644); assert.throws(() => loadToken(path));
    await chmod(path,0o600); await writeFile(path,'short'); assert.throws(() => loadToken(path));
    assert.equal(authorized(`Bearer ${token}`,token), true);
    for (const value of [undefined, token, `Bearer ${'b'.repeat(64)}`, `Bearer ${token}, Bearer ${token}`])
      assert.equal(authorized(value,token), false);
  } finally { await rm(dir, { recursive:true, force:true }); }
});
async function fixture() {
  const dir = await directory(); const authFile = await credential(dir);
  let calls = 0, secured = true, drop = false;
  const backend = http.createServer((req,res) => {
    if (req.method === 'POST') calls++; assert.equal(req.headers.authorization,`Bearer ${token}`);
    if (drop && req.method === 'POST') { req.socket.destroy(); return; }
    if (secured) res.setHeader('X-IPhone-Use-Auth','bearer-v1');
    res.end('{"value":{"ready":true}}');
  });
  await new Promise(resolve=>backend.listen(0,'127.0.0.1',resolve));
  const module = join(dir,'node_modules/appium-ios-device'); await mkdir(module,{recursive:true});
  await writeFile(join(module,'package.json'),'{"type":"module","main":"index.js"}');
  await writeFile(join(module,'index.js'),`import net from 'node:net';
const original=net.createConnection;
net.createConnection=function(options,...args){return options?.path==='/var/run/usbmuxd' ? original.call(net,{host:'127.0.0.1',port:${backend.address().port}},...args) : original.call(net,options,...args)};
export default {Usbmux:class{constructor(socket){this.socket=socket}async listDevices(){return [{Properties:{SerialNumber:'TEST-DEVICE-1234',ConnectionType:'USB',DeviceID:1}}]}async connect(){return this.socket}close(){this.socket.destroy()}}};`);
  for (const name of ['forward.mjs','auth.mjs','device-transport.mjs'])
    await writeFile(join(dir,name),await readFile(new URL('tooling/'+name,root)));
  const reservation=net.createServer(); await new Promise(resolve=>reservation.listen(0,'127.0.0.1',resolve));
  const port=reservation.address().port; await new Promise(resolve=>reservation.close(resolve));
  const child=spawn(process.execPath,[join(dir,'forward.mjs'),'TEST-DEVICE-1234',String(port),'8100'],
    {env:{...process.env,IPHONE_USE_AUTH_FILE:authFile},stdio:['ignore','pipe','pipe']});
  await Promise.race([once(child.stdout,'data'),once(child,'exit').then(()=>{throw Error('gateway exited')}),
    new Promise((_,reject)=>{const timer=setTimeout(()=>reject(Error('startup timeout')),5000);timer.unref()})]);
  return {port,get calls(){return calls},set secured(v){secured=v},set drop(v){drop=v},
    async close(){child.kill();await once(child,'exit');backend.closeAllConnections();await new Promise(resolve=>backend.close(resolve));await rm(dir,{recursive:true,force:true})}};
}
function request(port, headers={}, body='{}') {
  return new Promise((resolve,reject)=>{
    const req=http.request({host:'127.0.0.1',port,path:'/wda/homescreen',method:'POST',headers},res=>{
      let data='';res.on('data',chunk=>data+=chunk);res.on('end',()=>resolve({status:res.statusCode,data}));
    });req.on('error',reject);req.end(body);
  });
}
test('real gateway rejects unauthorized, foreign Origin and rebound Host before reaching the device', async()=>{
  const f=await fixture();
  try {
    assert.equal((await request(f.port)).status,401);
    assert.equal((await request(f.port,{Authorization:`Bearer ${'b'.repeat(64)}`})).status,401);
    assert.equal((await request(f.port,{Authorization:`Bearer ${token}`,Origin:'https://untrusted.example'})).status,401);
    assert.equal((await request(f.port,{Authorization:`Bearer ${token}`,Host:'untrusted.example'})).status,401);
    assert.equal((await request(f.port,{Authorization:[`Bearer ${token}`,`Bearer ${token}`]})).status,401);
    assert.equal(f.calls,0);
    assert.equal((await request(f.port,{Authorization:`Bearer ${token}`})).status,200);
    assert.equal(f.calls,1);
  } finally {await f.close()}
});
test('real gateway refuses an old backend and never replays a disconnected mutation', async()=>{
  const f=await fixture();
  try {
    f.secured=false;
    const response=await request(f.port,{Authorization:`Bearer ${token}`});
    assert.equal(response.status,502);assert.equal(response.data.includes('ready'),false);assert.equal(f.calls,0);
    f.secured=true;f.drop=true;
    const uncertain=await request(f.port,{Authorization:`Bearer ${token}`});
    assert.equal(uncertain.status,502);assert.equal(JSON.parse(uncertain.data).value.error,'action_uncertain');
    assert.equal(f.calls,1);
  } finally {await f.close()}
});
