const N=256,Q=8380417,QINV=1/Q;
const ZETAS=new Int32Array(256);{for(let k=0;k<256;k++){let b=0;for(let i=0;i<8;i++)b|=((k>>i)&1)<<(7-i);let r=1;for(let i=0;i<b;i++)r=(r*1753)%Q;ZETAS[k]=r;}}
const ZETASF=Float64Array.from(ZETAS);
function nttE(p){let k=0;for(let len=128;len>=1;len>>=1){for(let start=0;start<N;start+=len<<1){const z=ZETASF[++k];const end=start+len;for(let j=start;j<end;j++){const m=z*p[j+len];let t=m-Math.floor(m*QINV)*Q;if(t>=Q)t-=Q;else if(t<0)t+=Q;const a=p[j];p[j]=a+t;p[j+len]=a-t;}}}
 for(let i=0;i<N;i++){let v=p[i]%Q;if(v<0)v+=Q;p[i]=v;}return p;}
function nttG(p){let k=0;for(let len=128;len>=1;len>>=1){for(let start=0;start<N;start+=len<<1){const z=ZETASF[++k];const end=start+len;for(let j=start;j<end;j++){const m=z*p[j+len];const t=m-Math.floor(m*QINV)*Q;const a=p[j];p[j]=a+t;p[j+len]=a-t;}}}
 for(let i=0;i<N;i++){let v=p[i]%Q;if(v<0)v+=Q;p[i]=v;}return p;}
// G on Int32Array input
const p=new Int32Array(256); for(let i=0;i<256;i++)p[i]=(i*7919)%Q; const pf=Float64Array.from(p);
const ref=nttE(pf.slice());
for (const [nm,f,q0] of [['E lazy f64',nttE,pf],['G branchless f64',nttG,pf],['G branchless i32',nttG,p],['E lazy f64',nttE,pf],['G branchless f64',nttG,pf],['G branchless i32',nttG,p]]) { const r=f(q0.slice()); let ok=true; for(let i=0;i<256;i++) if(r[i]!==ref[i]) ok=false; const q=q0.slice(); for(let i=0;i<3000;i++)f(q); const s=performance.now(); for(let i=0;i<30000;i++)f(q); console.log(nm,ok,((performance.now()-s)*1e3/30000).toFixed(2),'us/ntt'); }
