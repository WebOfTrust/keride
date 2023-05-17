pub(crate) mod acdc;
pub(crate) mod kmi;
pub(crate) mod labels;
pub(crate) mod parsing;
pub(crate) mod verification;

use crate::error::{err, Error, Result};
use cesride::{Diger, Matter, Siger, Signer, Verfer};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Serialize, Deserialize, Zeroize)]
pub struct KeySet {
    pub keys: Vec<String>,
    pub index_offset: usize,
    pub transferable: bool,
}

impl KeySet {
    pub fn signers(&self) -> Result<Vec<Signer>> {
        let mut result = vec![];
        for key in &self.keys {
            let signer = Signer::new_with_qb64(key, Some(self.transferable))?;
            result.push(signer);
        }
        Ok(result)
    }

    pub fn verfers(&self) -> Result<Vec<Verfer>> {
        let mut verfers = vec![];

        for signer in &self.signers()? {
            verfers.push(signer.verfer());
        }

        Ok(verfers)
    }

    // if you pass in digers, this will throw a Validation error if the number of digers matched
    // is not equal to the number of keys represented by `self`
    pub fn sign(&self, ser: &[u8], digers: Option<&[Diger]>) -> Result<Vec<Siger>> {
        let mut sigers = vec![];
        let mut index = self.index_offset as u32;
        let mut ondex = None;
        let mut digers_matched = 0;

        for signer in &self.signers()? {
            if let Some(digers) = digers {
                for (i, diger) in digers.iter().enumerate() {
                    if diger.verify(&signer.verfer().qb64b()?)? {
                        ondex = Some(i as u32);
                        digers_matched += 1;
                        break;
                    }
                }
            }

            let siger = signer.sign_indexed(ser, false, index, ondex)?;
            sigers.push(siger);

            index += 1;
            ondex = None;
        }

        if digers.is_some() && self.keys.len() != digers_matched {
            return err!(Error::Validation);
        }

        Ok(sigers)
    }
}

pub trait KeriStore {
    fn prefix(&self) -> String;

    fn insert_keys(
        &mut self,
        pre: &str,
        keys: &[String],
        index_offset: usize,
        transferable: bool,
    ) -> Result<KeySet>;
    fn insert_sad(&mut self, sad: &str) -> Result<()>;
    fn insert_acdc(&mut self, acdc: &str) -> Result<()>;
    fn insert_key_event(&mut self, pre: &str, event: &str) -> Result<()>;
    fn insert_transaction_event(&mut self, pre: &str, event: &str) -> Result<()>;

    fn get_current_keys(&self, pre: &str) -> Result<KeySet>;
    fn get_next_keys(&self, pre: &str) -> Result<KeySet>;

    fn get_sad(&self, said: &str) -> Result<String>;
    fn get_acdc(&self, said: &str) -> Result<String>;
    fn get_key_event(&self, pre: &str, version: u32) -> Result<String>;
    fn get_transaction_event(&self, pre: &str, version: u32) -> Result<String>;
    fn get_latest_establishment_event(&self, pre: &str) -> Result<(String, u128)>;
    fn get_latest_establishment_event_as_of_sn(&self, pre: &str, sn: u32)
        -> Result<(String, u128)>;
    fn get_latest_transaction_event(&self, pre: &str) -> Result<String>;

    fn get_latest_key_event_said(&self, pre: &str) -> Result<String>;
    fn get_latest_establishment_event_said(&self, pre: &str) -> Result<(String, u128)>;
    fn get_latest_establishment_event_said_as_of_sn(
        &self,
        pre: &str,
        sn: u32,
    ) -> Result<(String, u128)>;

    fn get_kel(&self, pre: &str) -> Result<Vec<String>>;
    fn get_tel(&self, pre: &str) -> Result<Vec<String>>;

    fn count_key_events(&self, pre: &str) -> Result<usize>;
    fn count_transaction_events(&self, pre: &str) -> Result<usize>;
    fn count_establishment_events(&self, pre: &str) -> Result<usize>;
}
