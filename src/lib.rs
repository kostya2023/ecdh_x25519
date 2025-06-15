use pyo3::prelude::*;
use x25519_dalek::{EphemeralSecret, PublicKey};
use rand::rngs::OsRng;

#[pyclass]
pub struct EcdhX25519 {
    #[pyo3(get)]
    pub public_key: Option<[u8; 32]>,
    secret: Option<EphemeralSecret>,
}

#[pymethods]
impl EcdhX25519 {
    #[new]
    fn new() -> Self {
        Self {
            public_key: None,
            secret: None,
        }
    }

    fn generate_keypair(&mut self) -> Vec<u8> {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);

        self.secret = Some(secret);
        self.public_key = Some(public.to_bytes());

        public.to_bytes().to_vec()
    }

    fn generate_shared_secret(&mut self, another_public_key: [u8; 32]) -> PyResult<[u8; 32]> {
        let peer_pub = PublicKey::from(another_public_key);
        match self.secret.take() {
            Some(secret) => Ok(*secret.diffie_hellman(&peer_pub).as_bytes()),
            None => Err(pyo3::exceptions::PyValueError::new_err(
                "Secret key not initialized",
            )),
        }
    }
}

#[pymodule]
fn ecdh_x25519(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<EcdhX25519>()?;
    Ok(())
}