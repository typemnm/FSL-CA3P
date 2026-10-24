/** Bounded direct-dependency parser. No network access, no CVE execution. */
const MAX_BYTES = 2_097_152;
export const ADVISORIES = Object.freeze([
  { id:'CVE-2020-8203', ecosystem:'npm', name:'lodash', introduced:'3.7.0', fixed:'4.17.19' },
  { id:'CVE-2022-46175', ecosystem:'npm', name:'json5', introduced:'2.0.0', fixed:'2.2.2' },
  { id:'CVE-2022-21670', ecosystem:'npm', name:'markdown-it', maxInclusive:'12.3.1' },
  { id:'CVE-2022-42889', ecosystem:'maven', name:'org.apache.commons:commons-text', fixed:'1.10.0' },
  { id:'CVE-2022-1471', ecosystem:'maven', name:'org.yaml:snakeyaml', maxInclusive:'1.33' },
  { id:'CVE-2023-42503', ecosystem:'maven', name:'org.apache.commons:commons-compress', introduced:'1.22', fixed:'1.24.0' },
]);
function parts(s) {
  if (typeof s !== 'string' || !/^\d+(?:\.\d+){1,3}$/.test(s)) return null;
  const p=s.split('.').map(Number);
  return p.every(Number.isSafeInteger)?p:null;
}
function cmp(a,b) {
  const x=parts(a),y=parts(b);
  if(!x||!y)return null;
  for(let i=0;i<Math.max(x.length,y.length);i++){
    if((x[i]??0)!==(y[i]??0))return (x[i]??0)<(y[i]??0)?-1:1;
  }
  return 0;
}
function affected(version, rule) {
  if(!parts(version))return false;
  return (!rule.introduced||cmp(version,rule.introduced)>=0)
    &&(!rule.fixed||cmp(version,rule.fixed)<0)
    &&(!rule.maxInclusive||cmp(version,rule.maxInclusive)<=0);
}
function npm(content) {
  const data=JSON.parse(content);
  if(!data || typeof data!=='object'||!data.packages||!data.packages['']?.dependencies)
    throw new Error('Expected npm package-lock v2/v3 with direct dependencies.');
  return Object.keys(data.packages[''].dependencies).sort().map(name=>({
    ecosystem:'npm',name,version:parts(data.packages['node_modules/'+name]?.version)
      ?data.packages['node_modules/'+name].version:null,direct:true,
  }));
}
function maven(content) {
  if(/<!(?:DOCTYPE|ENTITY)\b/i.test(content))throw new Error('XML entity definitions are not supported.');
  const xml=content.replace(/<!--[\s\S]*?-->/g,'')
    .replace(/<dependencyManagement\b[^>]*>[\s\S]*?<\/dependencyManagement\s*>/g,'');
  const section=/<dependencies\b[^>]*>([\s\S]*?)<\/dependencies\s*>/.exec(xml)?.[1];
  if(!section)throw new Error('Maven dependencies not found.');
  const get=(s,k)=>new RegExp('<'+k+'\\s*>([^<]*)</'+k+'\\s*>').exec(s)?.[1]?.trim()||null;
  const props=/<properties\s*>([\s\S]*?)<\/properties\s*>/.exec(xml)?.[1]||'';
  const properties=new Map([...props.matchAll(/<([\w.-]+)\s*>([^<]*)<\/\1\s*>/g)]
    .map(m=>[m[1],m[2].trim()]));
  const deps=[];
  for(const m of section.matchAll(/<dependency\b[^>]*>([\s\S]*?)<\/dependency\s*>/g)){
    const group=get(m[1],'groupId'),artifact=get(m[1],'artifactId');
    if(!group||!artifact||!/^[\w.-]+$/.test(group)||!/^[\w.-]+$/.test(artifact))
      throw new Error('Invalid Maven coordinates.');
    if(['test','provided'].includes(get(m[1],'scope')))continue;
    let version=get(m[1],'version');
    const property=/^\$\{([\w.-]+)\}$/.exec(version||'');
    if(property)version=properties.get(property[1])||null;
    deps.push({ecosystem:'maven',name:group+':'+artifact,
      version:parts(version)?version:null,direct:true});
  }
  return deps.sort((a,b)=>a.name.localeCompare(b.name));
}
export function parseDependencyManifest(content,{ecosystem,sourceFile}={}){
  if(typeof content!=='string'||Buffer.byteLength(content)>MAX_BYTES)
    throw new TypeError('Manifest must be text no larger than 2 MiB.');
  if(!['npm','maven'].includes(ecosystem))throw new TypeError('Unsupported ecosystem.');
  if(typeof sourceFile!=='string'||!sourceFile||sourceFile.length>250)
    throw new TypeError('sourceFile required.');
  const dependencies=ecosystem==='npm'?npm(content):maven(content);
  const findings=dependencies.flatMap(d=>ADVISORIES
    .filter(a=>a.ecosystem===d.ecosystem&&a.name===d.name&&affected(d.version,a))
    .map(a=>({id:a.id,dependency:d,status:'affected_version',
      validation:'not_executed',evidence:{sourceFile,kind:'declared-direct-dependency-version'}})));
  return {schemaVersion:'1.0',scope:'direct-dependency-version-matches',ecosystem,
    sourceFile,catalog:'six-curated-fixture-CVEs',dependencies,findings,
    unresolved:dependencies.filter(d=>!d.version).map(d=>d.name),
    summary:{directDependencies:dependencies.length,matchedAdvisories:findings.length,
      isCompleteSCA:false,runtimeExploitabilityVerified:false}};
}
