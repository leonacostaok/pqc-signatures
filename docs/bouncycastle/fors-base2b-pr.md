SLH-DSA FORS index decoding uses a growing `BigInteger` for a bit window that needs at most 21 bits. Replace it with integer shifts and a mask, preserving the MSB-first indices while eliminating temporary `BigInteger` allocations.

[Measurements and methodology (private repository)](fors-base2b.md).
