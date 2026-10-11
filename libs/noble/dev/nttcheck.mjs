import { genCrystals } from '@noble/post-quantum/_crystals.js';
const N=256,Q=8380417,QINV=1/Q,F=8347681;
const c=genCrystals({N,Q,F,ROOT_OF_UNITY:1753,newPoly:(n)=>new Int32Array(n),isKyber:false,brvBits:8});
const ZETAS=new Int32Array(256);{for(let k=0;k<256;k++){let b=0;for(let i=0;i<8;i++)b|=((k>>i)&1)<<(7-i);let r=1;for(let i=0;i<b;i++)r=(r*1753)%Q;ZETAS[k]=r;}}
const ZETASF=Float64Array.from(ZETAS), NZETASF=Float64Array.from(ZETAS,z=>Q-z);
function mulq(a,b){const t=a*b;return t-Math.floor(t*QINV)*Q;}
function canon(p){for(let i=0;i<N;i++){const v=p[i]%Q;p[i]=v<0?v+Q:v;}return p;}
function ntt(p){let k=0;for(let len=128;len>=1;len>>=1){for(let start=0;start<N;start+=len<<1){const z=ZETASF[++k];const end=start+len;for(let j=start;j<end;j++){const t=mulq(z,p[j+len]);const a=p[j];p[j]=a+t;p[j+len]=a-t;}}}return canon(p);}
function intt(p){let k=N;for(let len=1;len<N;len<<=1){for(let start=0;start<N;start+=len<<1){const z=NZETASF[--k];const end=start+len;for(let j=start;j<end;j++){const t=p[j];const b=p[j+len];const u=t+b;p[j]=u-Math.floor(u*QINV)*Q;p[j+len]=mulq(z,t-b);}}}for(let i=0;i<N;i++)p[i]=mulq(F,p[i]);return canon(p);}
let bad=0;
for (let trial=0; trial<200; trial++) {
  const x=new Int32Array(256); for(let i=0;i<256;i++) x[i]=Math.floor(Math.random()*Q) - (trial%2? Math.floor(Q/2):0);
  const a=c.NTT.encode(x.slice()); const b=ntt(Float64Array.from(x));
  for(let i=0;i<256;i++) if(a[i]!==b[i]) {bad++; if(bad<5) console.log('ntt mismatch',trial,i,a[i],b[i]); break;}
  const a2=c.NTT.decode(a.slice()); const b2=intt(Float64Array.from(a));
  for(let i=0;i<256;i++) if(a2[i]!==b2[i]) {bad++; if(bad<5) console.log('intt mismatch',trial,i,a2[i],b2[i]); break;}
}
console.log('bad',bad);
// max magnitude check in lazy ntt
function nttMax(p){let k=0,mx=0;for(let len=128;len>=1;len>>=1){for(let start=0;start<N;start+=len<<1){const z=ZETASF[++k];const end=start+len;for(let j=start;j<end;j++){const t=mulq(z,p[j+len]);const a=p[j];p[j]=a+t;p[j+len]=a-t;mx=Math.max(mx,Math.abs(p[j]),Math.abs(p[j+len]));}}}return mx/Q;}
const x=new Float64Array(256); for(let i=0;i<256;i++) x[i]=Q-1-i; console.log('max/Q', nttMax(x));
