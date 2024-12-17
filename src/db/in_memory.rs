use crate::params::DGSP_POS_BYTES;
use std::collections::HashSet;

struct PLMEntry {
    ctr_certs: u64,
    is_active: bool,
    username: String,
}

#[derive(Default)]
pub struct PLM {
    vec: Vec<PLMEntry>,
    set: HashSet<String>,
}

impl PLM {
    pub fn open() -> Result<Self, crate::error::Error> {
        Ok(Self::default())
    }

    pub fn add_new_user(&mut self, username: &str) -> Result<u64, crate::error::Error> {
        if self.set.contains(username) {
            return Err(crate::error::Error::UsernameAlreadyExists(username.into()));
        }
        let new_id = self.vec.len() as u64;
        self.vec.push(PLMEntry {
            ctr_certs: 0,
            is_active: true,
            username: username.to_owned(),
        });
        self.set.insert(username.to_owned());
        Ok(new_id)
    }

    pub fn deactivate_id(&mut self, id: u64) -> Result<(), crate::error::Error> {
        self.id_exists(id)?;
        self.vec[id as usize].is_active = false;
        Ok(())
    }

    pub fn get_ctr_id(&self, id: u64) -> Result<u64, crate::error::Error> {
        self.id_exists(id)?;
        Ok(self.vec[id as usize].ctr_certs)
    }

    pub fn get_username(&self, id: u64) -> Result<String, crate::error::Error> {
        self.id_exists(id)?;
        Ok(self.vec[id as usize].username.clone())
    }

    pub fn id_exists(&self, id: u64) -> Result<bool, crate::error::Error> {
        if id < (self.vec.len() as u64) {
            Ok(true)
        } else {
            Err(crate::error::Error::IdNotFound(id))
        }
    }

    pub fn id_is_active(&self, id: u64) -> Result<bool, crate::error::Error> {
        self.id_exists(id)?;
        Ok(self.vec[id as usize].is_active)
    }

    pub fn increment_ctr_id_by(&mut self, id: u64, add: u64) -> Result<(), crate::error::Error> {
        if self.vec[id as usize].ctr_certs > u64::MAX - add {
            return Err(crate::error::Error::DbInternalError(format!(
                "Exceeds max certificate generation for the user {}",
                id
            )));
        }
        self.vec[id as usize].ctr_certs += add;
        Ok(())
    }
}

#[derive(Default)]
pub struct RevokedList(HashSet<[u8; DGSP_POS_BYTES]>);

impl RevokedList {
    pub fn open() -> Result<Self, crate::error::Error> {
        Ok(RevokedList::default())
    }
    pub fn contains(&self, pos: &[u8; DGSP_POS_BYTES]) -> Result<bool, crate::error::Error> {
        Ok(self.0.contains(pos))
    }

    pub fn insert(&mut self, pos: [u8; DGSP_POS_BYTES]) -> Result<(), crate::error::Error> {
        self.0.insert(pos);
        Ok(())
    }
}
