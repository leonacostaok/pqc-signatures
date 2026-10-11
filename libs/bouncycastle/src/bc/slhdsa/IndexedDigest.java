package bc.slhdsa;

class IndexedDigest
{
    final long idx_tree;
    final int idx_leaf;
    final byte[] digest;
    final byte[] full; // complete H_msg output (m bytes), kept for the stage canonical output

    IndexedDigest(long idx_tree, int idx_leaf, byte[] digest)
    {
        this(idx_tree, idx_leaf, digest, null);
    }

    IndexedDigest(long idx_tree, int idx_leaf, byte[] digest, byte[] full)
    {
        this.full = full;
        this.idx_tree = idx_tree;
        this.idx_leaf = idx_leaf;
        this.digest = digest;
    }
}
