import { genCrystals } from '@noble/post-quantum/_crystals.js';
const N=256,Q=8380417,QINV=1/Q;
const c=genCrystals({N,Q,F:8347681,ROOT_OF_UNITY:1753,newPoly:(n)=>new Int32Array(n),isKyber:false,brvBits:8});
const ZETAS=new Int32Array(256);{for(let k=0;k<256;k++){let b=0;for(let i=0;i<8;i++)b|=((k>>i)&1)<<(7-i);let r=1;for(let i=0;i<b;i++)r=(r*1753)%Q;ZETAS[k]=r;}}
const ZETASF=Float64Array.from(ZETAS);
function nttC(p){let k=0;for(let len=128;len>=1;len>>=1){for(let start=0;start<N;start+=len<<1){const z=ZETASF[++k];const end=start+len;for(let j=start;j<end;j++){const m=z*p[j+len];let t=m-Math.floor(m*QINV)*Q;if(t>=Q)t-=Q;else if(t<0)t+=Q;const a=p[j];const u=a+t;const v=a-t;p[j]=u>=Q?u-Q:u;p[j+len]=v<0?v+Q:v;}}}return p;}
const p=new Int32Array(256); for(let i=0;i<256;i++)p[i]=(i*7919)%Q; const pf=Float64Array.from(p);
for (const [nm,f,q0] of [['noble',(x)=>c.NTT.encode(x),p],['C recip f64',nttC,pf],['noble',(x)=>c.NTT.encode(x),p],['C recip f64',nttC,pf]]) { const q=q0.slice(); for(let i=0;i<3000;i++)f(q); const s=performance.now(); for(let i=0;i<30000;i++)f(q); console.log(nm,((performance.now()-s)*1e3/30000).toFixed(2),'us/ntt'); }
