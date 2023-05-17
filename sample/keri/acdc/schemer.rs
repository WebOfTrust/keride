use std::collections::HashMap;

use boon::{Compiler, SchemaIndex, Schemas};
use cesride::{
    common::{Ids, Serialage},
    dat,
    data::Value,
    matter, Matter, Saider,
};
use parking_lot::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::error::{err, Error, Result};

struct SchemaCache {
    resolver: RwLock<Schemas>,
    map: RwLock<HashMap<String, SchemaIndex>>,
}

impl SchemaCache {
    fn resolver(&self) -> RwLockReadGuard<Schemas> {
        self.resolver.read()
    }

    fn resolver_mut(&mut self) -> RwLockWriteGuard<Schemas> {
        self.resolver.write()
    }

    fn map(&self) -> RwLockReadGuard<HashMap<String, SchemaIndex>> {
        self.map.read()
    }

    fn map_mut(&self) -> RwLockWriteGuard<HashMap<String, SchemaIndex>> {
        self.map.write()
    }

    pub(crate) fn add(&mut self, key: &str, schema: &str, sed: &Value) -> Result<()> {
        if self.map().contains_key(&key.to_string()) {
            return Ok(());
        }

        let saider = Saider::new_with_qb64(key)?;
        if !saider.verify(
            sed,
            Some(false),
            Some(false),
            Some(Serialage::JSON),
            Some(Ids::dollar),
            None,
        )? {
            return err!(Error::Verification);
        }

        let mut compiler = Compiler::new();
        let value: serde_json::Value = serde_json::from_str(schema)?;
        match compiler.add_resource(key, value) {
            Ok(_) => (),
            Err(_) => return err!(Error::Value),
        };

        let index = match compiler.compile(key, &mut self.resolver_mut()) {
            Ok(index) => index,
            Err(_) => return err!(Error::Value),
        };

        self.map_mut().insert(key.to_string(), index);

        Ok(())
    }

    pub(crate) fn validate(&mut self, uri: &str, instance: &str) -> Result<bool> {
        let map = self.map();
        let loc = map.get(&uri.to_string());
        if let Some(loc) = loc {
            let value: serde_json::Value = serde_json::from_str(instance)?;
            match self.resolver().validate(&value, *loc) {
                Ok(()) => Ok(true),
                Err(_) => Ok(false),
            }
        } else {
            Ok(false)
        }
    }
}

fn schema_cache() -> &'static mut SchemaCache {
    static mut CACHE: std::mem::MaybeUninit<SchemaCache> = std::mem::MaybeUninit::uninit();
    static ONCE: std::sync::Once = std::sync::Once::new();

    unsafe {
        ONCE.call_once(|| {
            let cache = SchemaCache {
                resolver: RwLock::new(Schemas::new()),
                map: RwLock::new(HashMap::new()),
            };
            CACHE.write(cache);
        });

        CACHE.assume_init_mut()
    }
}

#[allow(dead_code)]
pub(crate) struct SchemerCache {
    map: RwLock<HashMap<String, Schemer>>,
}

#[allow(dead_code)]
impl SchemerCache {
    fn map(&self) -> RwLockReadGuard<HashMap<String, Schemer>> {
        self.map.read()
    }

    fn map_mut(&self) -> RwLockWriteGuard<HashMap<String, Schemer>> {
        self.map.write()
    }

    pub fn prime(&self, schemers: &[Schemer]) -> Result<()> {
        for schemer in schemers {
            self.map_mut().insert(schemer.said()?, schemer.clone());
        }

        Ok(())
    }

    pub fn get(&self, said: &str) -> Result<Schemer> {
        Ok(self.map()[&said.to_string()].clone())
    }

    pub fn verify(&self, said: &str, json: &str) -> Result<bool> {
        self.map()[&said.to_string()].verify(json.as_bytes())
    }
}

#[allow(dead_code)]
pub(crate) fn cache() -> &'static mut SchemerCache {
    static mut CACHE: std::mem::MaybeUninit<SchemerCache> = std::mem::MaybeUninit::uninit();
    static ONCE: std::sync::Once = std::sync::Once::new();

    unsafe {
        ONCE.call_once(|| {
            let cache = SchemerCache { map: RwLock::new(HashMap::new()) };
            CACHE.write(cache);
        });

        CACHE.assume_init_mut()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Schemer {
    raw: Vec<u8>,
    sed: Value,
    kind: String,
    saider: Saider,
}

#[allow(dead_code)]
impl Schemer {
    pub fn new(
        raw: Option<&[u8]>,
        sed: Option<&Value>,
        kind: Option<&str>,
        code: Option<&str>,
    ) -> Result<Self> {
        let code = code.unwrap_or(matter::Codex::Blake3_256);

        let (raw, sed, kind, saider) = if let Some(raw) = raw {
            let (sed, kind, saider) = Self::inhale(raw)?;
            (raw.to_vec(), sed, kind, saider)
        } else if let Some(sed) = sed {
            Self::exhale(sed, code, kind)?
        } else {
            return err!(Error::Value);
        };

        schema_cache().add(&saider.qb64()?, std::str::from_utf8(&raw)?, &sed)?;

        Ok(Schemer { raw, sed, kind, saider })
    }

    fn inhale(raw: &[u8]) -> Result<(Value, String, Saider)> {
        let value: serde_json::Value = serde_json::from_slice(raw)?;
        let sed = Value::from(&value);

        let map = sed.to_map()?;
        let label = &Ids::dollar.to_string();
        let saider = if map.contains_key(label) {
            let said = map[label].to_string()?;
            let saider = Saider::new_with_qb64(&said)?;
            if !saider.verify(&sed, Some(true), None, Some(Serialage::JSON), Some(label), None)? {
                return err!(Error::Validation);
            }

            saider
        } else {
            return err!(Error::Validation);
        };

        Ok((sed, Serialage::JSON.to_string(), saider))
    }

    fn exhale(
        sed: &Value,
        code: &str,
        kind: Option<&str>,
    ) -> Result<(Vec<u8>, Value, String, Saider)> {
        let kind = kind.unwrap_or(Serialage::JSON);
        if kind != Serialage::JSON {
            return err!(Error::Value);
        }

        let label = &Ids::dollar.to_string();
        let saider =
            Saider::new(Some(sed), Some(label), None, None, Some(code), None, None, None, None)?;
        let mut sed = sed.clone();
        sed["$id"] = dat!(&saider.qb64()?);
        let raw = sed.to_json()?.as_bytes().to_vec();

        Ok((raw, sed, kind.to_string(), saider))
    }

    pub(crate) fn raw(&self) -> Vec<u8> {
        self.raw.clone()
    }

    pub(crate) fn sed(&self) -> Value {
        self.sed.clone()
    }

    pub(crate) fn kind(&self) -> String {
        self.kind.clone()
    }

    pub(crate) fn said(&self) -> Result<String> {
        self.saider.qb64()
    }

    pub(crate) fn saider(&self) -> Saider {
        self.saider.clone()
    }

    pub(crate) fn verify(&self, raw: &[u8]) -> Result<bool> {
        schema_cache().validate(&self.said()?, std::str::from_utf8(raw)?)
    }
}

#[cfg(test)]
mod test {
    use super::{cache, Schemer};
    use cesride::data::dat;

    #[test]
    fn schemas() {
        let mut schemers = vec![];

        let sed = dat!({
            "$id": "", //
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "title": "Example Block",
            "description": "An example block",
            "credentialType": "ExampleBlockACDCAttributes",
            "type": "object",
            "required": [
              "d",
              "i",
            ],
            "properties": {
              "d": {
                "description": "Attributes SAID",
                "type": "string"
              },
              "i": {
                "description": "Issuee (Holder) AID",
                "type": "string"
              },
            },
            "additionalProperties": false
        });

        schemers.push(Schemer::new(None, Some(&sed), None, None).unwrap());

        cache().prime(&schemers).unwrap();

        assert!(cache()
            .verify(&schemers[0].said().unwrap(), "{\"d\":\"foo\",\"i\":\"bar\"}")
            .unwrap());
        assert!(!cache().verify(&schemers[0].said().unwrap(), "{\"i\":\"bar\"}").unwrap());
        assert!(!cache().verify(&schemers[0].said().unwrap(), "{\"d\":\"foo\"}").unwrap());
        assert!(!cache()
            .verify(&schemers[0].said().unwrap(), "{\"d\":\"foo\",\"i\":\"bar\",\"j\":\"baz\"}")
            .unwrap());

        let sed = dat!({
            "$id": "ELT1L3PG16r4RIloH_nDw_1O432xHrAW1oaH3NTbDQwu",
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "title": "Role Block",
            "description": "A position held by a user",
            "credentialType": "RoleBlockACDCAttributes",
            "type": "object",
            "required": [
                "d",
                "i",
                "holders",
                "supportingURL",
                "logo",
                "position",
                "organizationName",
                "status",
                "startDate"
            ],
            "properties": {
                "d": {
                    "description": "Attributes SAID",
                    "type": "string"
                },
                "i": {
                    "description": "Issuee (Holder) AID",
                    "type": "string"
                },
                "holders": {
                    "description": "AIDs of all holders of this block",
                    "type": "array",
                    "items": {
                        "type": "string"
                    }
                },
                "shortDescription": {
                    "description": "A brief description of the block",
                    "type": "string"
                },
                "longDescription": {
                    "description": "A more detailed description of the block",
                    "type": "string"
                },
                "headerTitle": {
                    "description": "The title of the header for the block",
                    "type": "string"
                },
                "headerImage": {
                    "description": "The URL of the image associated with the header",
                    "type": "string"
                },
                "supportingURL": {
                    "description": "A URL that provides additional information on the role",
                    "type": "string"
                },
                "logo": {
                    "description": "The URL of the logo of the organization associated with the block",
                    "type": "string"
                },
                "backgroundImage": {
                    "description": "URL of image used to add a custom background and themify a block",
                    "type": "string"
                },
                "blockTags": {
                    "description": "Custom user input metadata in the block (e.g. instructor block can have cohorts mentioned)",
                    "type": "array",
                    "items": {
                        "type": "string"
                    }
                },
                "position": {
                    "description": "Title of a role",
                    "type": "string"
                },
                "organizationName": {
                    "description": "The name of the organization associated with the block",
                    "type": "string"
                },
                "status": {
                    "description": "The current status of the role",
                    "type": "string"
                },
                "startDate": {
                    "description": "The date the role or education starts",
                    "type": "string"
                },
                "endDate": {
                    "description": "The date the role or education ends",
                    "type": "string"
                },
                "index": {
                    "description": "Indexing data",
                    "type": "object",
                    "properties": {
                        "d": {
                            "description": "Index (SAID)",
                            "type": "string"
                        },
                        "u": {
                            "description": "Salty nonce for uniqueness",
                            "type": "string"
                        },
                        "label": {
                            "description": "A label for the versioned ACDC instance",
                            "type": "string"
                        }
                    }
                }
            },
            "additionalProperties": false
        });
        assert!(Schemer::new(Some(sed.to_json().unwrap().as_bytes()), None, None, None).is_ok());
    }
}
