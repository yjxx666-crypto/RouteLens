import { collectMeasurements, abortMeasurements } from './measurements.mjs';
process.once('SIGINT',()=>{abortMeasurements();process.exitCode=130;});
const ids=process.argv.slice(2);
const result=await collectMeasurements({...(ids.length?{ids}:{}),onProgress:message=>console.log(message)});
console.log(JSON.stringify({mode:result.mode,collectedAt:result.collectedAt,timing:result.timing,connections:result.connections.map(c=>({domain:c.domain,http:c.http.httpCode,destinationIP:c.destinationIP,city:c.destinationGeo?.cityLabel,verification:c.destinationGeo?.verification.label}))},null,2));
