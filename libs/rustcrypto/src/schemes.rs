//! Thin byte-oriented wrappers around the RustCrypto `ml-dsa` and `slh-dsa` crates.
//!
//! Every scheme exposes the three measured processes on plain byte slices (the "plain, documented"
//! way a stateless caller would use the library: decode the key from bytes on every call), plus
//! "cached" constructors that decode the key once and return a closure that only does the
//! cryptographic operation (used by the `keycache` variants).

use core::marker::PhantomData;

pub type SignFn = Box<dyn Fn(&[u8]) -> Vec<u8> + Send + Sync>;
pub type VerifyFn = Box<dyn Fn(&[u8], &[u8]) -> bool + Send + Sync>;

pub trait Scheme: Send + Sync {
    fn name(&self) -> &'static str;
    /// seed -> (pk, sk) in FIPS encodings.
    fn keygen(&self, seed: &[u8]) -> (Vec<u8>, Vec<u8>);
    /// FIPS-encoded sk + message -> signature (deterministic, pure mode, empty context).
    fn sign(&self, sk: &[u8], msg: &[u8]) -> Vec<u8>;
    /// FIPS-encoded pk + message + signature -> valid?
    fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> bool;
    /// Decode sk once, return a signer closure.
    fn cached_signer(&self, sk: &[u8]) -> SignFn;
    /// Decode pk once, return a verifier closure.
    fn cached_verifier(&self, pk: &[u8]) -> VerifyFn;
}

// ---------------------------------------------------------------------------------------------
// ML-DSA (FIPS 204)
// ---------------------------------------------------------------------------------------------

pub struct MlDsa<P>(pub &'static str, pub PhantomData<P>);

impl<P> Scheme for MlDsa<P>
where
    P: ml_dsa::MlDsaParams + Send + Sync + 'static,
{
    fn name(&self) -> &'static str {
        self.0
    }

    fn keygen(&self, seed: &[u8]) -> (Vec<u8>, Vec<u8>) {
        use ml_dsa::Keypair;
        let xi = ml_dsa::Seed::try_from(seed).expect("ML-DSA seed must be 32 bytes");
        // ML-DSA.KeyGen_internal (FIPS 204 Alg. 6)
        let sk = ml_dsa::SigningKey::<P>::from_seed(&xi);
        let pk = sk.verifying_key().encode(); // pkEncode (Alg. 22)
        #[allow(deprecated)] // skEncode (Alg. 24): the expanded FIPS form is deprecated but available
        let skb = sk.expanded_key().to_expanded();
        (pk.to_vec(), skb.to_vec())
    }

    fn sign(&self, sk: &[u8], msg: &[u8]) -> Vec<u8> {
        let enc = <&ml_dsa::ExpandedSigningKeyBytes<P>>::try_from(sk).expect("bad sk length");
        #[allow(deprecated)] // skDecode (Alg. 25), re-expands A_hat on every call
        let esk = ml_dsa::ExpandedSigningKey::<P>::from_expanded(enc);
        // ML-DSA.Sign, optional deterministic variant (rnd = 0^32), empty context
        esk.sign_deterministic(msg, &[]).expect("sign").encode().to_vec()
    }

    fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        let Ok(enc) = <&ml_dsa::EncodedVerifyingKey<P>>::try_from(pk) else { return false };
        let vk = ml_dsa::VerifyingKey::<P>::decode(enc); // pkDecode (Alg. 23) + A_hat expansion
        let Ok(senc) = <&ml_dsa::EncodedSignature<P>>::try_from(sig) else { return false };
        let Some(s) = ml_dsa::Signature::<P>::decode(senc) else { return false };
        vk.verify_with_context(msg, &[], &s)
    }

    fn cached_signer(&self, sk: &[u8]) -> SignFn {
        let enc = <&ml_dsa::ExpandedSigningKeyBytes<P>>::try_from(sk).expect("bad sk length");
        #[allow(deprecated)]
        let esk = ml_dsa::ExpandedSigningKey::<P>::from_expanded(enc);
        Box::new(move |msg: &[u8]| esk.sign_deterministic(msg, &[]).expect("sign").encode().to_vec())
    }

    fn cached_verifier(&self, pk: &[u8]) -> VerifyFn {
        let enc = <&ml_dsa::EncodedVerifyingKey<P>>::try_from(pk).expect("bad pk length");
        let vk = ml_dsa::VerifyingKey::<P>::decode(enc);
        Box::new(move |msg: &[u8], sig: &[u8]| {
            let Ok(senc) = <&ml_dsa::EncodedSignature<P>>::try_from(sig) else { return false };
            let Some(s) = ml_dsa::Signature::<P>::decode(senc) else { return false };
            vk.verify_with_context(msg, &[], &s)
        })
    }
}

// ---------------------------------------------------------------------------------------------
// SLH-DSA (FIPS 205)
// ---------------------------------------------------------------------------------------------

pub struct SlhDsa<P>(pub &'static str, pub PhantomData<P>);

impl<P> Scheme for SlhDsa<P>
where
    P: slh_dsa::ParameterSet + Send + Sync + 'static,
{
    fn name(&self) -> &'static str {
        self.0
    }

    fn keygen(&self, seed: &[u8]) -> (Vec<u8>, Vec<u8>) {
        use signature::Keypair;
        let n = seed.len() / 3;
        assert_eq!(seed.len(), 3 * n, "SLH-DSA seed must be SK.seed||SK.prf||PK.seed");
        // slh_keygen_internal (FIPS 205 Alg. 18)
        let sk = slh_dsa::SigningKey::<P>::slh_keygen_internal(&seed[..n], &seed[n..2 * n], &seed[2 * n..]);
        let pk = sk.verifying_key().to_bytes();
        (pk.to_vec(), sk.to_bytes().to_vec())
    }

    fn sign(&self, sk: &[u8], msg: &[u8]) -> Vec<u8> {
        use signature::Signer;
        let key = slh_dsa::SigningKey::<P>::try_from(sk).expect("bad sk");
        // Signer::try_sign = slh_sign with empty ctx and opt_rand = None => PK.seed (deterministic)
        key.try_sign(msg).expect("sign").to_bytes().to_vec()
    }

    fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        use signature::Verifier;
        let Ok(vk) = slh_dsa::VerifyingKey::<P>::try_from(pk) else { return false };
        let Ok(s) = slh_dsa::Signature::<P>::try_from(sig) else { return false };
        vk.verify(msg, &s).is_ok()
    }

    fn cached_signer(&self, sk: &[u8]) -> SignFn {
        use signature::Signer;
        let key = slh_dsa::SigningKey::<P>::try_from(sk).expect("bad sk");
        Box::new(move |msg: &[u8]| key.try_sign(msg).expect("sign").to_bytes().to_vec())
    }

    fn cached_verifier(&self, pk: &[u8]) -> VerifyFn {
        use signature::Verifier;
        let vk = slh_dsa::VerifyingKey::<P>::try_from(pk).expect("bad pk");
        Box::new(move |msg: &[u8], sig: &[u8]| {
            let Ok(s) = slh_dsa::Signature::<P>::try_from(sig) else { return false };
            vk.verify(msg, &s).is_ok()
        })
    }
}

/// All parameter sets this harness supports, in contract order.
pub fn all_schemes() -> Vec<Box<dyn Scheme>> {
    use slh_dsa::*;
    vec![
        Box::new(MlDsa::<ml_dsa::MlDsa44>("ML-DSA-44", PhantomData)),
        Box::new(MlDsa::<ml_dsa::MlDsa65>("ML-DSA-65", PhantomData)),
        Box::new(MlDsa::<ml_dsa::MlDsa87>("ML-DSA-87", PhantomData)),
        Box::new(SlhDsa::<Sha2_128s>("SLH-DSA-SHA2-128s", PhantomData)),
        Box::new(SlhDsa::<Sha2_128f>("SLH-DSA-SHA2-128f", PhantomData)),
        Box::new(SlhDsa::<Sha2_192s>("SLH-DSA-SHA2-192s", PhantomData)),
        Box::new(SlhDsa::<Sha2_192f>("SLH-DSA-SHA2-192f", PhantomData)),
        Box::new(SlhDsa::<Sha2_256s>("SLH-DSA-SHA2-256s", PhantomData)),
        Box::new(SlhDsa::<Sha2_256f>("SLH-DSA-SHA2-256f", PhantomData)),
        Box::new(SlhDsa::<Shake128s>("SLH-DSA-SHAKE-128s", PhantomData)),
        Box::new(SlhDsa::<Shake128f>("SLH-DSA-SHAKE-128f", PhantomData)),
        Box::new(SlhDsa::<Shake192s>("SLH-DSA-SHAKE-192s", PhantomData)),
        Box::new(SlhDsa::<Shake192f>("SLH-DSA-SHAKE-192f", PhantomData)),
        Box::new(SlhDsa::<Shake256s>("SLH-DSA-SHAKE-256s", PhantomData)),
        Box::new(SlhDsa::<Shake256f>("SLH-DSA-SHAKE-256f", PhantomData)),
    ]
}
