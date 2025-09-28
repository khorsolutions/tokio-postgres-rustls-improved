use rcgen::{
    CertificateParams, CertifiedIssuer, DistinguishedName, KeyPair, PKCS_RSA_SHA256,
    SignatureAlgorithm,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

pub(crate) struct CertStore {
    pub rootstore: rustls::RootCertStore,
    pub root_pem: String,
    pub client_certs: Vec<CertificateDer<'static>>,
    pub client_key: PrivateKeyDer<'static>,
    pub server_pem: String,
    pub server_key_pem: String,
}

impl CertStore {
    pub(crate) fn default() -> CertStore {
        CertStore::make_certs(&PKCS_RSA_SHA256)
    }
    fn rootstore(der: &CertificateDer) -> rustls::RootCertStore {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(der.to_owned()).expect("add root ca");
        roots
    }

    pub(crate) fn make_certs(algo: &'static SignatureAlgorithm) -> CertStore {
        let ca_key = KeyPair::generate_for(algo).unwrap();
        let issuer = CertifiedIssuer::self_signed(
            {
                let mut params = CertificateParams::default();
                params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
                params
            },
            &ca_key,
        )
        .unwrap();
        let mut client_params =
            CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()]).unwrap();
        client_params.distinguished_name = {
            let mut dn = DistinguishedName::new();
            dn.push(rcgen::DnType::CommonName, "ssl_user");
            dn
        };
        let client_key = KeyPair::generate_for(algo).unwrap();
        let client_cert = client_params.signed_by(&client_key, &issuer).unwrap();

        let server_params =
            CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()]).unwrap();
        let server_key = KeyPair::generate_for(algo).unwrap();
        let server_cert = server_params.signed_by(&server_key, &issuer).unwrap();

        CertStore {
            rootstore: CertStore::rootstore(issuer.der()),
            root_pem: issuer.pem(),
            client_certs: vec![client_cert.der().to_owned()],
            client_key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(client_key.serialize_der())),
            server_pem: server_cert.pem(),
            server_key_pem: server_key.serialize_pem(),
        }
    }
}
