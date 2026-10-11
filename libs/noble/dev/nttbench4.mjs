const N=256,Q=8380417,QINV=1/Q;
const ZETAS=new Int32Array(256);{for(let k=0;k<256;k++){let b=0;for(let i=0;i<8;i++)b|=((k>>i)&1)<<(7-i);let r=1;for(let i=0;i<b;i++)r=(r*1753)%Q;ZETAS[k]=r;}}
const ZETASF=Float64Array.from(ZETAS);
function nttC(p){let k=0;for(let len=128;len>=1;len>>=1){for(let start=0;start<N;start+=len<<1){const z=ZETASF[++k];const end=start+len;for(let j=start;j<end;j++){const m=z*p[j+len];let t=m-Math.floor(m*QINV)*Q;if(t>=Q)t-=Q;else if(t<0)t+=Q;const a=p[j];const u=a+t;const v=a-t;p[j]=u>=Q?u-Q:u;p[j+len]=v<0?v+Q:v;}}}return p;}
// E: lazy reduction (no add/sub corrections), canonicalize at end
function nttE(p){let k=0;for(let len=128;len>=1;len>>=1){for(let start=0;start<N;start+=len<<1){const z=ZETASF[++k];const end=start+len;for(let j=start;j<end;j++){const m=z*p[j+len];let t=m-Math.floor(m*QINV)*Q;if(t>=Q)t-=Q;else if(t<0)t+=Q;const a=p[j];p[j]=a+t;p[j+len]=a-t;}}}
 for(let i=0;i<N;i++){let v=p[i]%Q;if(v<0)v+=Q;p[i]=v;}return p;}
// F: lazy + radix-4 style unroll of j loop by 2 for len>=2? keep simple: unroll inner loop x2
function nttF(p){let k=0;for(let len=128;len>=2;len>>=1){for(let start=0;start<N;start+=len<<1){const z=ZETASF[++k];const end=start+len;for(let j=start;j<end;j+=2){const m0=z*p[j+len],m1=z*p[j+len+1];let t0=m0-Math.floor(m0*QINV)*Q;let t1=m1-Math.floor(m1*QINV)*Q;if(t0>=Q)t0-=Q;else if(t0<0)t0+=Q;if(t1>=Q)t1-=Q;else if(t1<0)t1+=Q;const a0=p[j],a1=p[j+1];p[j]=a0+t0;p[j+1]=a1+t1;p[j+len]=a0-t0;p[j+len+1]=a1-t1;}}}
 {const len=1;for(let start=0;start<N;start+=2){const z=ZETASF[++k];const m=z*p[start+1];let t=m-Math.floor(m*QINV)*Q;if(t>=Q)t-=Q;else if(t<0)t+=Q;const a=p[start];p[start]=a+t;p[start+1]=a-t;}}
 for(let i=0;i<N;i++){let v=p[i]%Q;if(v<0)v+=Q;p[i]=v;}return p;}
const p=new Int32Array(256); for(let i=0;i<256;i++)p[i]=(i*7919)%Q; const pf=Float64Array.from(p);
const ref=nttC(pf.slice());
for (const [nm,f,q0] of [['C',nttC,pf],['E lazy',nttE,pf],['F lazy unroll',nttF,pf],['C',nttC,pf],['E lazy',nttE,pf],['F lazy unroll',nttF,pf]]) { const r=f(q0.slice()); let ok=true; for(let i=0;i<256;i++) if(r[i]!==ref[i]) ok=false; const q=q0.slice(); for(let i=0;i<3000;i++)f(q); const s=performance.now(); for(let i=0;i<30000;i++)f(q); console.log(nm,ok,((performance.now()-s)*1e3/30000).toFixed(2),'us/ntt'); }
