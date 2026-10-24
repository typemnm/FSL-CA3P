import test from 'node:test';
import assert from 'node:assert/strict';
import { parseDependencyManifest } from '../dependency-parser.mjs';

const parse=(s,ecosystem)=>parseDependencyManifest(s,{ecosystem,sourceFile:'fixture'});
test('npm resolved direct dependency matches curated CVE',()=>{
  const lock=JSON.stringify({lockfileVersion:3,packages:{
    '':{dependencies:{lodash:'4.17.15',json5:'2.2.2'}},
    'node_modules/lodash':{version:'4.17.15'},
    'node_modules/json5':{version:'2.2.2'}
  }});
  const r=parse(lock,'npm');
  assert.deepEqual(r.findings.map(f=>f.id),['CVE-2020-8203']);
  assert.equal(r.summary.isCompleteSCA,false);
  assert.equal(r.findings[0].validation,'not_executed');
});
test('Maven dependencies, parent-managed versions remain unresolved',()=>{
  const pom='<project><dependencies>'+
    '<dependency><groupId>org.yaml</groupId><artifactId>snakeyaml</artifactId><version>1.33</version></dependency>'+
    '<dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-webmvc</artifactId></dependency>'+
    '</dependencies></project>';
  const r=parse(pom,'maven');
  assert.deepEqual(r.findings.map(f=>f.id),['CVE-2022-1471']);
  assert.deepEqual(r.unresolved,['org.springframework.boot:spring-boot-starter-webmvc']);
});
test('rejects invalid inputs and fixed versions',()=>{
  assert.throws(()=>parse('<!DOCTYPE foo><project/>','maven'),/entity/);
  assert.throws(()=>parse('x'.repeat(2_097_153),'npm'),/2 MiB/);
  const lock=JSON.stringify({packages:{'':{dependencies:{lodash:'4.17.21'}},
    'node_modules/lodash':{version:'4.17.21'}}});
  assert.equal(parse(lock,'npm').findings.length,0);
});
