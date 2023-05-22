use crate::error::{err, Error, Result};
use cesride::{counter, Counter, Creder, Sadder};

pub(crate) fn messagize_creder(creder: &Creder, proof: &str) -> Result<String> {
    let mut message = String::from_utf8(creder.raw())?;
    if proof.len() % 4 != 0 {
        return err!(Error::Value);
    }

    message += &Counter::new_with_code_and_count(
        counter::Codex::AttachedMaterialQuadlets,
        proof.len() as u32 / 4,
    )?
    .qb64()?;
    message += proof;

    Ok(message)
}
