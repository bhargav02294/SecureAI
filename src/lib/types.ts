export type Check = { id:string; title:string; status:"pass"|"warning"|"fail"|"info"; detail:string; weight:number };
export type ScanResult = { id:string; url:string; hostname:string; scannedAt:string; statusCode:number; finalUrl:string; score:number; grade:string; checks:Check[]; durationMs:number; note:string };
