use anyhow::Ok;
use zeroize::ZeroizeOnDrop;

use crate::cesr::common::Tierage;
use crate::cesr::Salter;

use crate::cesr::core::matter::tables as matter;
use crate::error::Result;
use crate::signing::Signer;

pub const STEM: &str = "signify:aid";

/// Creating a key pair based on algorithm.
// pub trait Creator: Default {
//     #[allow(clippy::too_many_arguments)]
//     fn create(
//         &self,
//         codes: Option<Vec<&str>>,
//         count: Option<u16>,
//         code: Option<&str>,
//         pidx: Option<u16>,
//         ridx: Option<u16>,
//         kidx: Option<u16>,
//         stem: Option<&str>,
//         transferable: Option<bool>,
//         temp: bool,
//     ) -> Vec<Signer>;
// }

#[derive(Debug, ZeroizeOnDrop)]
pub struct SaltyCreator {
    salt: String,
    #[zeroize(skip)]
    stem: String,
    #[zeroize(skip)]
    tier: String,
    #[zeroize(skip)]
    salter: Salter,
}

impl SaltyCreator {
    pub fn new(
        salt: Option<&str>,
        stem: Option<&str>,
        tier: Option<&str>,
        salter: Option<Salter>,
    ) -> Result<Self> {
        let mut salty_creator = Self::default();

        if let Some(stm) = stem {
            salty_creator.stem = stm.to_string();
        }

        if let Some(s) = salter {
            salty_creator.salter = s;
        } else {
            salty_creator.salter = Salter::new(tier, None, None, None, salt, None).unwrap();
        }

        Ok(salty_creator)
    }

    fn set_salt(&mut self, salt: &str) {
        self.salt = salt.to_string();
    }

    fn set_stem(&mut self, stem: &str) {
        self.stem = stem.to_string();
    }

    fn set_tier(&mut self, tier: &str) {
        self.tier = tier.to_string();
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create(
        &self,
        codes: Option<Vec<&str>>,
        count: Option<u16>,
        code: Option<&str>,
        pidx: Option<u16>,
        ridx: Option<u16>,
        kidx: Option<u16>,
        stem: Option<&str>,
        transferable: Option<bool>,
        temp: bool,
    ) -> Vec<Signer> {
        let code = code.unwrap_or(matter::Codex::Ed25519_Seed);
        let count = count.unwrap_or(1);
        let mut codes = codes.unwrap_or(vec![]);
        let pidx = pidx.unwrap_or(0);
        let ridx = ridx.unwrap_or(0);
        let kidx = kidx.unwrap_or(0);
        let ps = format!("{:x}", pidx.to_owned());
        let transferable = transferable.unwrap_or(true);

        let stem =
            if !self.stem.is_empty() { self.stem.as_str() } else { stem.unwrap_or(ps.as_str()) };

        if codes.is_empty() {
            codes = (0..count).map(|_| code).collect();
        }

        let mut signers = vec![];
        for (i, c) in codes.iter().enumerate() {
            let path = format!("{}{:x}{:x}", stem, &ridx, kidx + i as u16);
            signers.push(
                self.salter
                    .signer(Some(c), Some(transferable), Some(&path), Some(&self.tier), Some(temp))
                    .unwrap(),
            );
        }
        signers
    }
}

impl Default for SaltyCreator {
    fn default() -> Self {
        SaltyCreator {
            salt: "".to_string(),
            stem: "".to_string(),
            tier: Tierage::low.to_string(),
            salter: Salter::new(Some(Tierage::low), None, None, None, None, None).unwrap(),
        }
    }
}

#[derive(Debug, Default)]
pub struct RandyCreator {}

impl RandyCreator {
    fn new() -> Self {
        Self::default()
    }

    fn create(
        &self,
        codes: Option<Vec<&str>>,
        count: Option<u16>,
        code: Option<&str>,
        transferable: Option<bool>,
    ) -> Vec<Signer> {
        let code = code.unwrap_or(matter::Codex::Ed25519_Seed);
        let count = count.unwrap_or(1);
        let mut codes = codes.unwrap_or(vec![]);
        let transferable = transferable.unwrap_or(true);

        if codes.is_empty() {
            codes = (0..count).map(|_| code).collect();
        }

        codes
            .iter()
            .map(|c| Signer::new(Some(transferable), Some(c), None, None, None, None).unwrap())
            .collect()
    }
}

#[cfg(test)]
mod test {
    use crate::cesr::{
        core::matter::{tables as matter, Matter},
        Salter,
    };

    use super::{RandyCreator, SaltyCreator};

    #[test]
    fn test_salty_python_interop() {
        let sc = SaltyCreator::new(None, None, None, None).unwrap();
        assert_eq!(sc.salter.code(), matter::Codex::Salt_128);
        assert_eq!(sc.stem, "");
        assert_eq!(sc.tier, sc.salter.tier());

        let signers = sc.create(None, None, None, None, None, None, None, None, false);
        assert_eq!(signers.len(), 1);

        let signer = &signers[0];
        assert_eq!(signer.code(), matter::Codex::Ed25519_Seed);
        assert_eq!(signer.verfer().code(), matter::Codex::Ed25519);

        let signers = sc.create(None, Some(2), None, None, None, None, None, Some(false), false);
        assert_eq!(signers.len(), 2);

        for s in signers.iter() {
            assert_eq!(s.code(), matter::Codex::Ed25519_Seed);
            assert_eq!(s.verfer().code(), matter::Codex::Ed25519N);
        }

        let raw = b"0123456789abcdef";
        let salter = Salter::new(None, None, Some(raw), None, None, None).unwrap();
        let salt = salter.qb64().unwrap();

        assert_eq!(salt, "0AAwMTIzNDU2Nzg5YWJjZGVm");
        let sc = SaltyCreator::new(Some(&salt), None, None, None).unwrap();

        assert_eq!(sc.salter.code(), matter::Codex::Salt_128);
        assert_eq!(sc.salter.raw(), raw);
        assert_eq!(sc.salter.qb64().unwrap(), salt);

        let signers = sc.create(None, None, None, None, None, None, None, None, false);
        assert_eq!(signers.len(), 1);

        let signer = &signers[0];
        assert_eq!(signer.code(), matter::Codex::Ed25519_Seed);
        assert_eq!(signer.qb64().unwrap(), "APMJe0lwOpwnX9PkvX1mh26vlzGYl6RWgWGclc8CAQJ9");

        assert_eq!(signer.verfer().code(), matter::Codex::Ed25519);
        assert_eq!(signer.verfer().qb64().unwrap(), "DMZy6qbgnKzvCE594tQ4SPs6pIECXTYQBH7BkC4hNY3E");

        let signers = sc.create(None, Some(1), None, None, None, None, None, Some(false), true);
        assert_eq!(signers.len(), 1);

        let signer = &signers[0];
        assert_eq!(signer.code(), matter::Codex::Ed25519_Seed);
        assert_eq!(signer.qb64().unwrap(), "AMGrAM0noxLpRteO9mxGT-yzYSrKFwJMuNI4KlmSk26e");
        assert_eq!(signer.verfer().code(), matter::Codex::Ed25519N);
        assert_eq!(signer.verfer().qb64().unwrap(), "BFRtyHAjSuJaRX6TDPva35GN11VHAruaOXMc79ZYDKsT");

        let sc = SaltyCreator::new(Some(&salt), Some("0123456789abcdefghijk"), None, None).unwrap();
        let signers = sc.create(None, None, None, None, None, None, None, None, false);
        assert_eq!(signers.len(), 1);
        let signer = &signers[0];
        println!("{:?}", signer.qb64().unwrap());
        println!("{:?}", signer.verfer().qb64().unwrap());
        assert_eq!(signer.code(), matter::Codex::Ed25519_Seed);
        assert_eq!(signer.qb64().unwrap(), "AKs7xnPXuqeGHjuz73YcxRp7AS608EQLv1XxJg_owymy");
        assert_eq!(signer.verfer().code(), matter::Codex::Ed25519);
        assert_eq!(signer.verfer().qb64().unwrap(), "DDz3MqwHaEmcMmGflJb-Y48xeBDeub50d7jDA6ED09Pk");
    }

    #[test]
    fn test_randy_python_interop() {
        let rc = RandyCreator::new();
        let signers = rc.create(None, None, None, None);
        assert_eq!(signers.len(), 1);

        let signer = &signers[0];
        assert_eq!(signer.code(), matter::Codex::Ed25519_Seed);
        assert_eq!(signer.verfer().code(), matter::Codex::Ed25519);

        let signers = rc.create(None, Some(2), None, Some(false));
        assert_eq!(signers.len(), 2);

        for signer in signers.iter() {
            assert_eq!(signer.code(), matter::Codex::Ed25519_Seed);
            assert_eq!(signer.verfer().code(), matter::Codex::Ed25519N);
        }
    }
}
