package org.bouncycastle.crypto.signers.slhdsa;

import java.io.ByteArrayOutputStream;
import java.lang.management.ManagementFactory;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.SLHDSAKeyPairGenerator;
import org.bouncycastle.crypto.params.ParametersWithContext;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.SLHDSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.SLHDSAParameters;
import org.bouncycastle.crypto.params.SLHDSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.SLHDSAPublicKeyParameters;
import org.bouncycastle.crypto.signers.SLHDSASigner;
import org.bouncycastle.util.Pack;

/** Experiment-only package access; production classes have no timing instrumentation. */
public final class SlhDeepProbe
{
    static final String[] STAGES = {"verify.decode", "sign.prf_msg", "hmsg", "fors.indices",
        "verify.fors_leaves", "verify.fors_auth", "verify.fors_compress", "verify.fors",
        "verify.wots_chains", "verify.wots_compress", "verify.wots", "verify.xmss_auth", "verify.hypertree",
        "sign.fors", "sign.wots", "sign.xmss_auth", "sign.hypertree", "sign.serialize"};
    static final String[] TOTALS = {"keygen.total", "sign.total", "verify.total"};
    static final com.sun.management.OperatingSystemMXBean CPU =
        (com.sun.management.OperatingSystemMXBean)ManagementFactory.getOperatingSystemMXBean();
    static final com.sun.management.ThreadMXBean THREAD =
        (com.sun.management.ThreadMXBean)ManagementFactory.getThreadMXBean();
    static volatile Object sink;

    static final class FixedRandom extends SecureRandom
    {
        final byte[] input;
        int position;
        FixedRandom(byte[] input) { this.input = input; }
        public void nextBytes(byte[] out)
        {
            if (position + out.length > input.length) throw new AssertionError("entropy overrun");
            System.arraycopy(input, position, out, 0, out.length);
            position += out.length;
        }
        void check() { require(position == input.length, "entropy consumption"); }
    }

    static final class Case
    {
        final String parameter, phase;
        final int index;
        final byte[] seed, message, context, entropy, pk, sk, signature, prefix;
        final SLHDSAParameters params;
        final SLHDSAPrivateKeyParameters privateKey;
        final SLHDSAPublicKeyParameters publicKey;
        final String inputs;
        SLHDSAEngine engine;
        SIG decoded;
        IndexedDigest indexed;
        int[] indices;
        byte[] pkSeed, skSeed, pkRoot, forsPk;
        byte[][] leaves, forsRoots, layerMessages, wotsPks, roots;
        byte[][][] chains;
        ADRS[] layerAddresses;
        int[] layerIndices;
        FixedRandom random;
        String stageInputs;

        Case(String[] row) throws Exception
        {
            require(row.length == 10, "fixture columns");
            phase = row[0]; parameter = row[1]; index = Integer.parseInt(row[2]);
            params = (SLHDSAParameters)SLHDSAParameters.class.getField(parameter).get(null);
            require(!params.isPreHash(), "stage corpus is pure SLH-DSA");
            seed = unhex(row[3]); message = unhex(row[4]); context = unhex(row[5]); entropy = unhex(row[6]);
            pk = unhex(row[7]); sk = unhex(row[8]); signature = unhex(row[9]);
            require(seed.length == 3 * params.getN() && entropy.length == params.getN() && context.length <= 255,
                "fixture dimensions");
            privateKey = new SLHDSAPrivateKeyParameters(params, sk);
            publicKey = new SLHDSAPublicKeyParameters(params, pk);
            prefix = new byte[2 + context.length]; prefix[1] = (byte)context.length;
            System.arraycopy(context, 0, prefix, 2, context.length);
            inputs = inputHash();
        }

        String inputHash() throws Exception { return hash(flat(new Object[]{seed,message,context,entropy,pk,sk,signature,prefix})); }

        void prepareStages() throws Exception
        {
            engine = params.getEngine();
            skSeed = privateKey.getSeed(); pkSeed = publicKey.getSeed(); pkRoot = publicKey.getRoot();
            engine.init(pkSeed);
            decoded = new SIG(engine.N, engine.K, engine.A, engine.D, engine.H_PRIME, engine.WOTS_LEN, signature);
            indexed = engine.H_msg(decoded.getR(), pkSeed, pkRoot, prefix, message);
            indices = Fors.base2B(indexed.digest, engine.A, engine.K);
            leaves = forsLeaves(); forsRoots = forsAuth();
            forsPk = new Fors(engine).pkFromSig(decoded.getSIG_FORS(), indexed.digest, pkSeed, forsAddress());
            require(Arrays.equals(forsPk, (byte[])execute("verify.fors_compress")), "FORS stage composition");
            layerMessages = new byte[engine.D][]; wotsPks = new byte[engine.D][]; roots = new byte[engine.D][];
            chains = new byte[engine.D][][]; layerAddresses = new ADRS[engine.D]; layerIndices = new int[engine.D];
            byte[] current = forsPk;
            long tree = indexed.idx_tree; int leaf = indexed.idx_leaf;
            WotsPlus wots = new WotsPlus(engine);
            for (int layer = 0; layer < engine.D; ++layer)
            {
                if (layer != 0) { leaf = (int)(tree & ((1 << engine.H_PRIME) - 1)); tree >>>= engine.H_PRIME; }
                ADRS address = new ADRS(); address.setLayerAddress(layer); address.setTreeAddress(tree);
                address.setTypeAndClear(ADRS.WOTS_HASH); address.setKeyPairAddress(leaf);
                layerAddresses[layer] = address; layerIndices[layer] = leaf; layerMessages[layer] = current;
                SIG_XMSS xmss = decoded.getSIG_HT()[layer];
                chains[layer] = wotsChains(layer);
                wotsPks[layer] = wots.pkFromSig(xmss.sig, current, pkSeed, new ADRS(address));
                ADRS compression = new ADRS(address); compression.setTypeAndClear(ADRS.WOTS_PK); compression.setKeyPairAddress(leaf);
                require(Arrays.equals(wotsPks[layer], engine.T_l(pkSeed, compression, org.bouncycastle.util.Arrays.concatenate(chains[layer]))), "WOTS stage composition");
                roots[layer] = auth(wotsPks[layer], xmss.auth, leaf, address);
                current = roots[layer];
            }
            require(Arrays.equals(pkRoot, current), "stage final root");
            stageInputs = stageHash();
        }

        String stageHash() throws Exception
        {
            return hash(flat(new Object[]{skSeed,pkSeed,pkRoot,decoded,indexed,indices,leaves,forsRoots,forsPk,
                layerMessages,wotsPks,roots,chains,layerAddresses,layerIndices}));
        }

        ADRS forsAddress()
        {
            ADRS address = new ADRS(); address.setTypeAndClear(ADRS.FORS_TREE);
            address.setTreeAddress(indexed.idx_tree); address.setKeyPairAddress(indexed.idx_leaf);
            return address;
        }

        byte[][] forsLeaves()
        {
            byte[][] out = new byte[engine.K][]; ADRS address = forsAddress();
            for (int i = 0; i < out.length; ++i)
            {
                address.setTreeHeight(0); address.setTreeIndex((i << engine.A) + indices[i]);
                out[i] = engine.F(pkSeed, address, decoded.getSIG_FORS()[i].sk);
            }
            return out;
        }

        byte[][] forsAuth()
        {
            byte[][] out = new byte[engine.K][]; ADRS address = forsAddress();
            for (int i = 0; i < out.length; ++i)
            {
                byte[] node = leaves[i]; int index = indices[i];
                address.setTreeIndex((i << engine.A) + index);
                for (int j = 0; j < engine.A; ++j)
                {
                    address.setTreeHeight(j + 1); address.setTreeIndex(address.getTreeIndex() >>> 1);
                    byte[] sibling = decoded.getSIG_FORS()[i].authPath[j];
                    node = (index & (1 << j)) == 0 ? engine.H(pkSeed,address,node,sibling) : engine.H(pkSeed,address,sibling,node);
                }
                out[i] = node;
            }
            return out;
        }

        byte[][] wotsChains(int layer)
        {
            WotsPlus wots = new WotsPlus(engine);
            int[] digits = new int[engine.WOTS_LEN];
            wots.base_w(layerMessages[layer], 0, engine.WOTS_W, digits, 0, engine.WOTS_LEN1);
            int checksum = 0;
            for (int j = 0; j < engine.WOTS_LEN1; ++j) checksum += engine.WOTS_W - 1 - digits[j];
            checksum <<= 8 - (engine.WOTS_LEN2 * engine.WOTS_LOGW) % 8;
            wots.base_w(Pack.intToBigEndian(checksum), 4 - (engine.WOTS_LEN2 * engine.WOTS_LOGW + 7) / 8,
                engine.WOTS_W, digits, engine.WOTS_LEN1, engine.WOTS_LEN2);
            byte[][] out = new byte[engine.WOTS_LEN][]; ADRS address = new ADRS(layerAddresses[layer]);
            byte[] sig = decoded.getSIG_HT()[layer].sig;
            byte[] input = new byte[engine.N];
            for (int j = 0; j < out.length; ++j)
            {
                address.setChainAddress(j);
                System.arraycopy(sig,j * engine.N,input,0,engine.N);
                out[j] = wots.chain(input,digits[j],15-digits[j],pkSeed,address);
            }
            return out;
        }

        byte[] auth(byte[] leaf, byte[][] path, int index, ADRS input)
        {
            ADRS address = new ADRS(input); address.setTypeAndClear(ADRS.TREE); address.setTreeIndex(index);
            byte[] node = leaf;
            for (int j = 0; j < path.length; ++j)
            {
                address.setTreeHeight(j+1); address.setTreeIndex(address.getTreeIndex() >>> 1);
                node = (index & (1 << j)) == 0 ? engine.H(pkSeed,address,node,path[j]) : engine.H(pkSeed,address,path[j],node);
            }
            return node;
        }

        Object execute(String operation) throws Exception
        {
            if (operation.equals("keygen.total"))
            {
                random = new FixedRandom(seed); SLHDSAKeyPairGenerator generator = new SLHDSAKeyPairGenerator();
                generator.init(new SLHDSAKeyGenerationParameters(random,params)); return generator.generateKeyPair();
            }
            if (operation.equals("sign.total"))
            {
                random = new FixedRandom(entropy); SLHDSASigner signer = new SLHDSASigner();
                signer.init(true,new ParametersWithContext(new ParametersWithRandom(privateKey,random),context));
                return signer.generateSignature(message);
            }
            if (operation.equals("verify.total")) return verify(signature);
            if (operation.equals("verify.decode")) return new SIG(engine.N,engine.K,engine.A,engine.D,engine.H_PRIME,engine.WOTS_LEN,signature);
            if (operation.equals("sign.prf_msg")) return engine.PRF_msg(privateKey.getPrf(),entropy,prefix,message);
            if (operation.equals("hmsg")) return engine.H_msg(decoded.getR(),pkSeed,pkRoot,prefix,message);
            if (operation.equals("fors.indices")) return Fors.base2B(indexed.digest,engine.A,engine.K);
            if (operation.equals("verify.fors_leaves")) return forsLeaves();
            if (operation.equals("verify.fors_auth")) return forsAuth();
            if (operation.equals("verify.fors_compress"))
            {
                ADRS address = forsAddress(); address.setTypeAndClear(ADRS.FORS_PK); address.setKeyPairAddress(indexed.idx_leaf);
                return engine.T_l(pkSeed,address,org.bouncycastle.util.Arrays.concatenate(forsRoots));
            }
            if (operation.equals("verify.fors")) return new Fors(engine).pkFromSig(decoded.getSIG_FORS(),indexed.digest,pkSeed,forsAddress());
            if (operation.equals("verify.wots_chains"))
            {
                byte[][][] out = new byte[engine.D][][]; for (int j=0;j<out.length;++j) out[j]=wotsChains(j); return out;
            }
            if (operation.equals("verify.wots_compress"))
            {
                byte[][] out = new byte[engine.D][];
                for (int j=0;j<out.length;++j)
                {
                    ADRS address = new ADRS(layerAddresses[j]); address.setTypeAndClear(ADRS.WOTS_PK); address.setKeyPairAddress(layerIndices[j]);
                    out[j]=engine.T_l(pkSeed,address,org.bouncycastle.util.Arrays.concatenate(chains[j]));
                }
                return out;
            }
            if (operation.equals("verify.wots"))
            {
                WotsPlus wots = new WotsPlus(engine); byte[][] out = new byte[engine.D][];
                for(int j=0;j<out.length;++j) out[j]=wots.pkFromSig(decoded.getSIG_HT()[j].sig,layerMessages[j],pkSeed,new ADRS(layerAddresses[j]));
                return out;
            }
            if (operation.equals("verify.xmss_auth"))
            {
                byte[][] out=new byte[engine.D][];
                for(int j=0;j<out.length;++j) out[j]=auth(wotsPks[j],decoded.getSIG_HT()[j].auth,layerIndices[j],layerAddresses[j]);
                return out;
            }
            if (operation.equals("verify.hypertree")) return new HT(engine,null,pkSeed).verify(forsPk,decoded.getSIG_HT(),pkSeed,indexed.idx_tree,indexed.idx_leaf,pkRoot);
            if (operation.equals("sign.fors")) return new Fors(engine).sign(indexed.digest,skSeed,pkSeed,forsAddress());
            if (operation.equals("sign.wots"))
            {
                WotsPlus wots = new WotsPlus(engine); byte[][] out=new byte[engine.D][];
                for(int j=0;j<out.length;++j) out[j]=wots.sign(layerMessages[j],skSeed,pkSeed,new ADRS(layerAddresses[j])); return out;
            }
            if (operation.equals("sign.xmss_auth"))
            {
                HT ht=new HT(engine,skSeed,pkSeed); byte[][][] out=new byte[engine.D][engine.H_PRIME][];
                for(int layer=0;layer<engine.D;++layer) for(int j=0;j<engine.H_PRIME;++j)
                    out[layer][j]=ht.treehash(skSeed,((layerIndices[layer] >>> j)^1)<<j,j,pkSeed,new ADRS(layerAddresses[layer]));
                return out;
            }
            if (operation.equals("sign.hypertree")) return new HT(engine,skSeed,pkSeed).sign(forsPk,indexed.idx_tree,indexed.idx_leaf);
            if (operation.equals("sign.serialize"))
            {
                byte[][] ht=new byte[engine.D][];
                for(int j=0;j<ht.length;++j) ht[j]=org.bouncycastle.util.Arrays.concatenate(decoded.getSIG_HT()[j].sig,org.bouncycastle.util.Arrays.concatenate(decoded.getSIG_HT()[j].auth));
                byte[][] components=new byte[engine.K+2][];components[0]=decoded.getR();
                for(int j=0;j<engine.K;++j) components[j+1]=org.bouncycastle.util.Arrays.concatenate(decoded.getSIG_FORS()[j].sk,org.bouncycastle.util.Arrays.concatenate(decoded.getSIG_FORS()[j].authPath));
                components[components.length-1]=org.bouncycastle.util.Arrays.concatenate(ht);
                return org.bouncycastle.util.Arrays.concatenate(components);
            }
            throw new IllegalArgumentException(operation);
        }

        byte[] expected(String operation) throws Exception
        {
            if(operation.equals("keygen.total")) return flat(new Object[]{pk,sk});
            if(operation.equals("sign.total") || operation.equals("verify.decode") || operation.equals("sign.serialize")) return signature;
            if(operation.equals("verify.total") || operation.equals("verify.hypertree")) return new byte[]{1};
            if(operation.equals("sign.prf_msg")) return decoded.getR();
            if(operation.equals("hmsg")) return flat(indexed);
            if(operation.equals("fors.indices")) return flat(indices);
            if(operation.equals("verify.fors_leaves")) return flat(leaves);
            if(operation.equals("verify.fors_auth")) return flat(forsRoots);
            if(operation.equals("verify.fors_compress") || operation.equals("verify.fors")) return forsPk;
            if(operation.equals("verify.wots_chains")) return flat(chains);
            if(operation.equals("verify.wots_compress") || operation.equals("verify.wots")) return flat(wotsPks);
            if(operation.equals("verify.xmss_auth")) return flat(roots);
            if(operation.equals("sign.fors")) return flat(decoded.getSIG_FORS());
            if(operation.equals("sign.hypertree")) return flat(decoded.getSIG_HT());
            if(operation.equals("sign.wots"))
            { byte[][] out=new byte[engine.D][]; for(int j=0;j<out.length;++j) out[j]=decoded.getSIG_HT()[j].sig; return flat(out); }
            if(operation.equals("sign.xmss_auth"))
            { byte[][][] out=new byte[engine.D][][]; for(int j=0;j<out.length;++j) out[j]=decoded.getSIG_HT()[j].auth; return flat(out); }
            throw new IllegalArgumentException(operation);
        }

        boolean verify(byte[] sig)
        {
            SLHDSASigner verifier = new SLHDSASigner(); verifier.init(false,new ParametersWithContext(publicKey,context));
            return verifier.verifySignature(message,sig);
        }

        void checked(String operation,Object value,byte[] expected) throws Exception
        {
            require(Arrays.equals(expected,flat(value)),operation+" output mismatch");
            if(operation.equals("keygen.total") || operation.equals("sign.total")) random.check();
            if(operation.endsWith(".total"))
            {
                byte[] sig=operation.equals("sign.total") ? (byte[])value : signature;
                require(verify(sig),"valid signature"); byte[] changed=sig.clone(); changed[changed.length-1]^=1;
                require(!verify(changed),"tamper rejection");
            }
            require(inputs.equals(inputHash()),"caller input mutation");
            require(Arrays.equals(privateKey.getEncoded(),sk) && Arrays.equals(publicKey.getEncoded(),pk),"caller key-object mutation");
            if(stageInputs!=null) require(stageInputs.equals(stageHash()),"prepared stage input mutation");
        }
    }

    static byte[] flat(Object value) throws Exception
    {
        if(value instanceof byte[]) return (byte[])value;
        if(value instanceof Boolean) return new byte[]{(byte)((Boolean)value?1:0)};
        if(value instanceof int[])
        { int[] values=(int[])value; byte[] out=new byte[values.length*4]; Pack.intToBigEndian(values,out,0); return out; }
        if(value instanceof ADRS) return ((ADRS)value).value;
        if(value instanceof IndexedDigest)
        {
            IndexedDigest v=(IndexedDigest)value; byte[] suffix=new byte[12]; Pack.longToBigEndian(v.idx_tree,suffix,0); Pack.intToBigEndian(v.idx_leaf,suffix,8);
            return flat(new Object[]{v.digest,suffix});
        }
        if(value instanceof AsymmetricCipherKeyPair)
        { AsymmetricCipherKeyPair pair=(AsymmetricCipherKeyPair)value; return flat(new Object[]{((SLHDSAPublicKeyParameters)pair.getPublic()).getEncoded(),((SLHDSAPrivateKeyParameters)pair.getPrivate()).getEncoded()}); }
        if(value instanceof SIG)
        { SIG sig=(SIG)value; return flat(new Object[]{sig.getR(),sig.getSIG_FORS(),sig.getSIG_HT()}); }
        if(value instanceof SIG_FORS)
        { SIG_FORS sig=(SIG_FORS)value; return flat(new Object[]{sig.sk,sig.authPath}); }
        if(value instanceof SIG_XMSS)
        { SIG_XMSS sig=(SIG_XMSS)value; return flat(new Object[]{sig.sig,sig.auth}); }
        if(value instanceof Object[])
        { ByteArrayOutputStream out=new ByteArrayOutputStream(); for(Object part:(Object[])value) out.write(flat(part)); return out.toByteArray(); }
        throw new IllegalArgumentException(value.getClass().getName());
    }
    static byte[] unhex(String hex)
    {
        require(hex.length()%2==0,"hex length"); byte[] out=new byte[hex.length()/2];
        for(int i=0;i<out.length;++i) { int a=Character.digit(hex.charAt(2*i),16),b=Character.digit(hex.charAt(2*i+1),16); require(a>=0&&b>=0,"hex digit");out[i]=(byte)((a<<4)|b); } return out;
    }
    static String hash(byte[] value) throws Exception
    { StringBuilder out=new StringBuilder(); for(byte b:MessageDigest.getInstance("SHA-256").digest(value))out.append(String.format("%02x",b&255));return out.toString(); }
    static void require(boolean condition,String message) { if(!condition)throw new AssertionError(message); }
    static String quote(String value) { return "\""+value.replace("\\","\\\\").replace("\"","\\\"")+"\""; }

    public static void main(String[] args) throws Exception
    {
        require(args.length>=4,"MODE FIXTURES PARAMETER VARIANT [OP FORK ROUNDS BUDGET_MS WARM_CYCLES]");
        String mode=args[0], parameter=args[2],variant=args[3];
        require(variant.equals("baseline")||variant.equals("candidate")||variant.equals("combined"),"variant");
        List<String> lines=Files.readAllLines(Paths.get(args[1])); require(lines.remove(0).equals("pqc-tenkeys-v1/bouncycastle"),"fixture header");
        List<Case> cases=new ArrayList<Case>();
        for(String line:lines) { String[] fields=line.split("\t",-1); if(fields[1].equals(parameter))cases.add(new Case(fields)); }
        require(cases.size()==12,"fixture coverage");
        String source=Paths.get(SLHDSAEngine.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toRealPath().toString();
        if(mode.equals("check")||mode.equals("stages-check"))
        {
            for(Case c:cases)
            {
                if(mode.equals("stages-check") && (!c.phase.equals("measured") || !(c.index==0||c.index==3||c.index==6||c.index==9)))continue;
                String[] operations=mode.equals("check")?TOTALS:STAGES;
                if(mode.equals("stages-check"))c.prepareStages();
                for(String operation:operations)
                {
                    Object result=c.execute(operation); byte[] expected=c.expected(operation);c.checked(operation,result,expected);
                    System.out.println("{\"variant\":"+quote(variant)+",\"parameter\":"+quote(parameter)+",\"phase\":"+quote(c.phase)+",\"case\":"+c.index+",\"operation\":"+quote(operation)+",\"output_sha256\":"+quote(hash(flat(result)))+",\"class_source\":"+quote(source)+",\"checked\":true}");
                }
            }
            return;
        }
        require(args.length==9 && (mode.equals("bench")||mode.equals("allocation")),"measurement mode");
        String operation=args[4]; require(Arrays.asList(TOTALS).contains(operation)||Arrays.asList(STAGES).contains(operation),"operation");
        int fork=Integer.parseInt(args[5]),rounds=Integer.parseInt(args[6]),budget=Integer.parseInt(args[7]),warm=Integer.parseInt(args[8]);
        require(fork>=0&&rounds>=1&&rounds<=20&&budget>=1&&budget<=10000&&warm>=1&&warm<=1000,"numeric options");
        List<Case> measured=new ArrayList<Case>(),warmup=new ArrayList<Case>();
        for(Case c:cases)
        {
            if(c.phase.equals("warmup"))warmup.add(c); else if(c.index==0||c.index==3||c.index==6||c.index==9)measured.add(c);
        }
        require(warmup.size()==2&&measured.size()==4,"case split");
        for(Case c:cases)if(!operation.endsWith(".total"))c.prepareStages();
        for(int j=0;j<warm;++j)for(Case c:warmup)c.checked(operation,c.execute(operation),c.expected(operation));
        long threadId=Thread.currentThread().getId();
        require(THREAD.isCurrentThreadCpuTimeSupported()&&THREAD.isThreadAllocatedMemorySupported(),"thread counters");
        THREAD.setThreadAllocatedMemoryEnabled(true);
        THREAD.setThreadCpuTimeEnabled(true);
        require(THREAD.isThreadCpuTimeEnabled(),"thread CPU enabled");
        for(int round=0;round<rounds;++round)
        {
            long total=0; int cycle=0;
            do
            {
                for(Case c:measured)
                {
                    byte[] expected=c.expected(operation);
                    long cpu=0,thread=0,start=0,allocation=0;
                    if(mode.equals("allocation"))allocation=THREAD.getThreadAllocatedBytes(threadId);
                    else { cpu=CPU.getProcessCpuTime();thread=THREAD.getCurrentThreadCpuTime();start=System.nanoTime(); }
                    Object result=c.execute(operation);
                    long wall=0;
                    if(mode.equals("allocation"))allocation=THREAD.getThreadAllocatedBytes(threadId)-allocation;
                    else { wall=System.nanoTime()-start;thread=THREAD.getCurrentThreadCpuTime()-thread;cpu=CPU.getProcessCpuTime()-cpu; }
                    require(wall>=0&&cpu>=0&&thread>=0&&allocation>=0,"negative counter");
                    sink=result;c.checked(operation,result,expected);total+=wall;
                    System.out.println("{\"variant\":"+quote(variant)+",\"parameter\":"+quote(parameter)+",\"operation\":"+quote(operation)+",\"fork\":"+fork+",\"round\":"+round+",\"cycle\":"+cycle+",\"case\":"+c.index+",\"warmup_calls\":"+(2*warm)+",\"wall_ns\":"+wall+",\"cpu_ns\":"+cpu+",\"thread_cpu_ns\":"+thread+",\"allocated_bytes\":"+allocation+",\"output_sha256\":"+quote(hash(flat(result)))+",\"class_source\":"+quote(source)+",\"checked\":true}");
                }
                ++cycle;
            }
            while(mode.equals("bench")&&total<budget*1000000L);
        }
    }
}
