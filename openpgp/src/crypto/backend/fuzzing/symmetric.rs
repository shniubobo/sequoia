use std::borrow::Cow;

use crate::Result;
use crate::crypto::{
    SymmetricAlgorithm,
    self,
    mem::Protected,
    symmetric::{BlockCipherMode, Context},
};

impl crypto::backend::interface::Symmetric for super::Backend {
    fn supports_algo(algo: SymmetricAlgorithm) -> bool {
        true
    }

    fn encryptor_impl(algo: SymmetricAlgorithm, _mode: BlockCipherMode,
		      _key: &Protected, _iv: Cow<'_, [u8]>)
                      -> Result<Box<dyn Context>>
    {
        Ok(Box::new(NullCipher(algo.block_size().unwrap_or(16))))
    }

    fn decryptor_impl(algo: SymmetricAlgorithm, _mode: BlockCipherMode,
		      _key: &Protected, _iv: Cow<'_, [u8]>)
                      -> Result<Box<dyn Context>>
    {
        Ok(Box::new(NullCipher(algo.block_size().unwrap_or(16))))
    }
}

struct NullCipher(usize);

impl Context for NullCipher {
    fn block_size(&self) -> usize {
        self.0
    }

    fn encrypt(
        &mut self,
        dst: &mut [u8],
        src: &[u8],
    ) -> Result<()> {
        dst.copy_from_slice(src);
        Ok(())
    }

    fn decrypt(
        &mut self,
        dst: &mut [u8],
        src: &[u8],
    ) -> Result<()> {
        dst.copy_from_slice(src);
        Ok(())
    }
}
