use crate::params::DGSP_POS_BYTES;
use std::collections::HashSet;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};

impl<T> From<PoisonError<T>> for crate::error::Error {
    fn from(err: PoisonError<T>) -> Self {
        Self::DbInternalError(format!("Lock error: {}", err))
    }
}

struct PLMEntry {
    ctr_certs: u64,
    is_active: bool,
    username: String,
}

#[derive(Default)]
struct PLMData {
    vec: Vec<PLMEntry>,
    set: HashSet<String>,
}

impl PLMData {
    fn ensure_id_exists(&self, id: u64) -> Result<(), crate::error::Error> {
        if id < (self.vec.len() as u64) {
            Ok(())
        } else {
            Err(crate::error::Error::IdNotFound(id))
        }
    }
}

#[derive(Default)]
pub struct PLM {
    data: Arc<Mutex<PLMData>>,
}

impl PLM {
    pub fn open() -> Result<Self, crate::error::Error> {
        Self::open_with_path("database")
    }

    pub fn open_with_path<P: AsRef<Path>>(_: P) -> Result<Self, crate::error::Error> {
        Ok(Self {
            data: Arc::new(Mutex::new(PLMData::default())),
        })
    }

    pub fn add_new_user(&self, username: &str) -> Result<u64, crate::error::Error> {
        let mut data = self.data.lock()?;
        if data.set.contains(username) {
            return Err(crate::error::Error::UsernameAlreadyExists(username.into()));
        }
        let new_id = data.vec.len() as u64;
        data.vec.push(PLMEntry {
            ctr_certs: 0,
            is_active: true,
            username: username.to_owned(),
        });
        data.set.insert(username.to_owned());
        Ok(new_id)
    }

    pub fn deactivate_id(&self, id: u64) -> Result<(), crate::error::Error> {
        let mut data = self.data.lock()?;
        data.ensure_id_exists(id)?;
        data.vec[id as usize].is_active = false;
        Ok(())
    }

    pub fn get_ctr_id(&self, id: u64) -> Result<u64, crate::error::Error> {
        let data = self.data.lock()?;
        data.ensure_id_exists(id)?;
        Ok(data.vec[id as usize].ctr_certs)
    }

    pub fn get_username(&self, id: u64) -> Result<String, crate::error::Error> {
        let data = self.data.lock()?;
        data.ensure_id_exists(id)?;
        Ok(data.vec[id as usize].username.clone())
    }

    pub fn id_exists(&self, id: u64) -> Result<bool, crate::error::Error> {
        let data = self.data.lock()?;
        data.ensure_id_exists(id)?;
        Ok(true)
    }

    pub fn id_is_active(&self, id: u64) -> Result<bool, crate::error::Error> {
        let data = self.data.lock()?;
        data.ensure_id_exists(id)?;
        Ok(data.vec[id as usize].is_active)
    }

    pub fn increment_ctr_id_by(&self, id: u64, add: u64) -> Result<(), crate::error::Error> {
        let mut data = self.data.lock()?;
        if data.vec[id as usize].ctr_certs > u64::MAX - add {
            return Err(crate::error::Error::DbInternalError(format!(
                "Exceeds max certificate generation for the user {}",
                id
            )));
        }
        data.vec[id as usize].ctr_certs += add;
        Ok(())
    }
}

#[derive(Default)]
pub struct RevokedList(Arc<Mutex<HashSet<[u8; DGSP_POS_BYTES]>>>);

impl RevokedList {
    pub fn open() -> Result<Self, crate::error::Error> {
        Self::open_with_path("database")
    }

    pub fn open_with_path<P: AsRef<Path>>(_: P) -> Result<Self, crate::error::Error> {
        Ok(RevokedList::default())
    }
    pub fn contains(&self, pos: &[u8; DGSP_POS_BYTES]) -> Result<bool, crate::error::Error> {
        let data = self.0.lock()?;
        Ok(data.contains(pos))
    }

    pub fn insert(&self, pos: [u8; DGSP_POS_BYTES]) -> Result<(), crate::error::Error> {
        let mut data = self.0.lock()?;
        data.insert(pos);
        Ok(())
    }
}
