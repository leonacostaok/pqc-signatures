const N=256,Q=8380417,QINV=1/Q;
const ZETAS=new Int32Array(256);{for(let k=0;k<256;k++){let b=0;for(let i=0;i<8;i++)b|=((k>>i)&1)<<(7-i);let r=1;for(let i=0;i<b;i++)r=(r*1753)%Q;ZETAS[k]=r;}}
function mulmodA(a,b){const t=a*b;let r=t-Math.floor(t*QINV)*Q;if(r>=Q)r-=Q;else if(r<0)r+=Q;return r;}
function mulmodB(a,b){return (a*b)%Q;}
function mk(mm){return function ntt(p){let k=0;for(let len=128;len>=1;len>>=1){for(let start=0;start<N;start+=len<<1){const z=ZETAS[++k];const end=start+len;for(let j=start;j<end;j++){const t=mm(z,p[j+len]);const a=p[j];const u=a+t;const v=a-t;p[j]=u>=Q?u-Q:u;p[j+len]=v<0?v+Q:v;}}}return p;}}
const nA=mk(mulmodA), nB=mk(mulmodB);
const p=new Int32Array(256); for(let i=0;i<256;i++)p[i]=(i*7919)%Q;
const a=nA(p.slice()), b=nB(p.slice()); let ok=true; for(let i=0;i<256;i++) if(a[i]!==b[i]) ok=false; console.log('same',ok);
for (const [nm,f] of [['recip',nA],['mod',nB],['recip',nA],['mod',nB]]) { const q=p.slice(); for(let i=0;i<2000;i++)f(q); const s=performance.now(); for(let i=0;i<20000;i++)f(q); console.log(nm,((performance.now()-s)*1e3/20000).toFixed(2),'us/ntt'); }
