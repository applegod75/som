pub mod logging;
use std::io::Write;
use base64::{Engine as _, engine::general_purpose::URL_SAFE};

pub struct Authenticator {
    state: String,
    tenant_uuid: String,
    code_challenge: String,
    username: String,
    password: String
}

fn generate_rand_str(len: i32, logger: &logging::Logger) -> String {
    let mut rtn: Vec<u8> = vec![];
    for _ in 0..(len - 1) {
        rtn.push(rand::random_range(32..127));
    }

    match String::from_utf8(rtn) {
        Ok(o) => return o,
        Err(e) => {
            logger.log(
                &format!("failed to create random string because of '{:?}'", e),
                logging::Level::Error
            );
            return String::new();
        }
    }
}


pub fn download_write_organisaties_json(logger: &logging::Logger) -> bool {
    logger.log("downloading organisaties.json ...", logging::Level::Debug);

    let data = match reqwest::blocking::get("https://raw.githubusercontent.com/NONtoday/organisaties.json/main/organisaties.json") {
        Ok(a) => {
            match a.text() {
                Ok(b) => b,
                Err(e) => {
                    logger.log(&format!("Failed to get organisaties.json's text: {:?}", e), logging::Level::Error);
                    return false;
                }
            }
        },
        Err(e) => {
            logger.log(&format!("failed to download organisaties.json: {:?}", e), logging::Level::Error);
            return false;
        }
    };

    logger.log("downloaded organisaties.json, writing ...", logging::Level::Trace);

    if std::path::Path::new("organisaties.json").exists() {
        logger.log("organisaties.json already exists, deleting existing copy", logging::Level::Debug);

        match std::fs::remove_file(std::path::Path::new("organisaties.json")) {
            Ok(_) => { logger.log("succcessfully deleted organisaties.json", logging::Level::Trace); },
            Err(msg) => {
                logger.log(
                    &format!("failed to delete existing copy of organisaties.json: '{:?}'", msg),
                    logging::Level::Error
                );
                return false;
            }
        };
    }

    let file = match std::fs::File::create("organisaties.json") {
        Ok(a) => a,
        Err(e) => {
            logger.log(&format!("failed to create organisaties.json: '{:?}'", e), logging::Level::Error);
            return false;
        }
    };

    let mut writer = std::io::BufWriter::new(file);
    match write!(writer, "{}", data) {
        Ok(_) => {}
        Err(e) => {
            logger.log(&format!("failed to write organisaties.json: '{:?}'", e), logging::Level::Error);
            return false;
        }
    }

    logger.log("successfully wrote data to organisaties.json", logging::Level::Debug);
    true
}

fn get_tenant_uuid(school: &str, logger: &logging::Logger) -> String {
    if !std::path::Path::new("organisaties.json").exists() {
        logger.log("organisaties.json not found, downloading ...", logging::Level::Debug);

        if !download_write_organisaties_json(logger) {
            return String::new();
        }
    }

    let contents: String = match std::fs::read_to_string(std::path::Path::new("organisaties.json")) {
        Ok(c) => c,
        Err(e) => {
            logger.log(
                &format!("could not read organisaties.json's contents: '{:?}'", e),
                logging::Level::Error
            );
            return String::new();
        }
    };

    let json_data: serde_json::Value = match serde_json::from_str(&contents) {
        Ok(d) => d,
        Err(e) => {
            logger.log(
                &format!("could not parse organisaties.json: '{:?}'", e),
                logging::Level::Error
            );
            return String::new();
        }
    };

    let schools: &Vec<serde_json::Value> = match json_data[0]["instellingen"] {
        serde_json::Value::Array(ref a) => a,
        _ => {
            logger.log(
                "organisaties.json is malformed",
                logging::Level::Error
            );
            return String::new();
        }
    };

    for school_inst in schools {
        let school_name: String = match school_inst["naam"].as_str() {
            Some(s) => String::from(s),
            None => {
                logger.log("organisaties.json is malformed", logging::Level::Error);
                return String::new();
            }
        };

        if school_name == *school {
            return match school_inst["uuid"].as_str(){
                Some(s) => String::from(s),
                None => {
                    logger.log("organisaties.json is malformed", logging::Level::Error);
                    String::new()
                }
            };
        }
    }

    logger.log(&format!("Could not find school {:?}", school), logging::Level::Error);
    String::new()
}

fn hash_b64enc(s: &String, logger: &logging::Logger) -> String {
    let hash = hmac_sha256::Hash::hash(s.as_bytes());
    let rtn = URL_SAFE.encode(hash);
    logger.log(&format!("hashed into '{}' from '{}'", rtn, s), logging::Level::Debug);
    rtn
}

impl Authenticator {
    pub fn new(username: &str, school: &str, password: &str, logger: &logging::Logger) -> Result<Authenticator, String> {
        let uuid = get_tenant_uuid(school, logger);
        if uuid == String::new() {
            return Err(String::from("failed to get uuid"));
        }

        let state = urlencoding::encode(&generate_rand_str(8, logger)).to_string();
        if state == String::new() {
            return Err(String::from("failed to generate state"));
        }

        let nonce = generate_rand_str(128, logger);
        if nonce == String::new() {
            return Err(String::from("failed to generate nonce"));
        }

        let code_challenge = urlencoding::encode(&hash_b64enc(&nonce, logger)).to_string();

        Ok(Authenticator {
            state,
            tenant_uuid: uuid,
            code_challenge,
            username: String::from(username),
            password: String::from(password)
        })
    }
}

#[derive(Debug)]
enum LoginFlow {
    UsernameFirst,
    UsernamePassword,
    Unknown
}

impl Authenticator {
    fn build_accesstoken_link(&self, logger: &logging::Logger) -> String {
        let mut rtn = String::from("https://inloggen.somtoday.nl/oauth2/authorize");
        rtn.push_str(&format!("?redirect_uri={}", urlencoding::encode("somtoday://nl.topicus.somtoday.leerling/oauth/callback")));
        rtn.push_str(&format!("&client_id={}", "somtoday-leerling-native"));
        rtn.push_str(&format!("&response_type={}", "code"));
        rtn.push_str(&format!("&state={}", self.state));
        rtn.push_str(&format!("&scope={}", "openid"));
        rtn.push_str(&format!("&tenant_uuid={}", self.tenant_uuid));
        rtn.push_str(&format!("&session={}", "no_session"));
        rtn.push_str(&format!("&code_challenge={}", self.code_challenge));
        rtn.push_str(&format!("&code_challenge_method={}", "S256"));
        logger.log(&format!("generated link: '{}'", rtn), logging::Level::Debug);
        rtn
    }

    fn find_login_flow(&self, client: &reqwest::blocking::Client, auth: &str, jsessionid: &str, inloggen_stickiness: &str, logger: &logging::Logger) -> LoginFlow {
        let res = match client.put(&format!("https://inloggen.somtoday.nl/0-1.-panel-signInForm?auth={}", auth))
            .body(format!("usernamefieldpanel:usernamefieldpanel_body:usernamefield={}", self.username))
            .header(reqwest::header::ORIGIN, "https://inloggen.somtoday.nl")
            .header(reqwest::header::COOKIE, &format!("JSESSIONID={}; inloggen-stickiness={}", jsessionid, inloggen_stickiness))
            .send() {

            Ok(res) => res,
            Err(e) => {
                logger.log(&format!("could not POST to find login flow type: '{}'", e), logging::Level::Error);
                return LoginFlow::Unknown;
            }
        };

        let loc = match res.headers().get(reqwest::header::LOCATION) {
            None => {
                logger.log(&format!("could not find location header in response: {:#?}", res), logging::Level::Error);
                return LoginFlow::Unknown;
            },
            Some(s) => {
                match s.to_str() {
                    Ok(s) => s,
                    Err(e) => {
                        logger.log(&format!("failed to convert location header to string: '{:?}'", e), logging::Level::Error);
                        return LoginFlow::Unknown;
                    }
                }
            }
        };

        match url::Url::parse(loc) {
            Err(e) => { logger.log(&format!("could not parse location header url: '{}'", e), logging::Level::Error); LoginFlow::Unknown }
            Ok(url) => {
                let auth: usize = url.query_pairs()
                    .filter(|(key, value)|{ key.to_string() == "auth" })
                    .collect::<Vec<_>>()
                    .len();
                
                if auth > 0 {
                    LoginFlow::UsernamePassword
                } else {
                    LoginFlow::UsernameFirst
                }
            }
        }
    }

    pub fn authenticate(&self, logger: &logging::Logger) -> bool {
        let client = match reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build() {

            Ok(o) => o,
            Err(e) => {
                logger.log(&format!("something went wrong when creating reqwest client: '{:?}'", e), logging::Level::Error);
                return false;
            }
        };

        let link = self.build_accesstoken_link(logger);
        let redir = match client.get(&link).send() {
            Ok(o) => o,
            Err(e) => {
                logger.log(&format!("failed to send request to fetch access token: '{:?}'", e), logging::Level::Error);
                return false;
            }
        };
        
        logger.log(&format!("first response: (GET original link) {:#?}", redir), logging::Level::Debug);

        if redir.status() != reqwest::StatusCode::FOUND {
            logger.log(&format!("SOM endpoint returned unexpected status code {:#?}.", redir.status()), logging::Level::Error);
            return false;
        }

        let mut inloggen_stickiness: Option<String> = None;
        
        for cook in redir.cookies() {
            if String::from(cook.name()) == String::from("inloggen-stickiness") {
                inloggen_stickiness = Some(String::from(cook.value()));
            }
        }


        let inloggen_stickiness: String = match inloggen_stickiness {
			Some(s) => s,
            None => {
                logger.log("could not find inloggen-stickiness cookie in response", logging::Level::Error);
                return false;
            }
        };

        let location: String;

        if let Some(loc) = redir.headers().get(reqwest::header::LOCATION) {
            location = String::from(loc.to_str().expect("failed to convert location header to str"));
        } else {
            logger.log("SOM endpoint returned unexpected headers", logging::Level::Error);
            return false;
        }

        let authorization_code: String = match url::Url::parse(&location) {
            Err(e) => {
                logger.log(&format!("could not parse url: '{:#?}'", e), logging::Level::Error);
                return false;
            },
            Ok(url) => {
                let mut result: String = String::new();
                
                for (key, value) in url.query_pairs() {
                    if key == "auth" {
                        result = value.to_string();
                        break;
                    }
                }
                
                if result == String::new() {
                    logger.log(&format!("could not parse auth query param '{:?}'", location), logging::Level::Error);
                    return false;
                }

                result
            }
        };

        logger.log(&format!("auth = {}", authorization_code), logging::Level::Debug);
        let redir = match client.get(&location).header(reqwest::header::COOKIE, &format!("inloggen-stickiness={}", inloggen_stickiness)).send() {
            Ok(o) => o,
            Err(e) => {
                logger.log(&format!("failed to send request to get authorization_code: '{:?}'", e), logging::Level::Error);
                return false;
            }
        };

        let mut jsessionid: Option<String> = None;
        
        for cook in redir.cookies() {
            if cook.name() == String::from("JSESSIONID") {
                jsessionid = Some(String::from(cook.value()));
            }
        }

        let jsessionid: String = match jsessionid {
            None => {
                logger.log("could not find JSESSIONID cookie in response", logging::Level::Error);
                logger.log(&format!("response was: {:#?}", redir), logging::Level::Error); 
                return false;
            },
            Some(s) => s,
        };

        logger.log(&format!("full response:\n{:#?}", redir), logging::Level::Trace);
        logger.log(&format!("inloggen-stickiness: {}, JSESSIONID: {}", inloggen_stickiness, jsessionid), logging::Level::Debug);

        let location: String;

        if let Some(loc) = redir.headers().get(reqwest::header::LOCATION) {
            location = String::from(loc.to_str().expect("failed to convert location header to str"));
        } else {
            logger.log("SOM endpoint returned unexpected headers", logging::Level::Error);
            return false;
        }

        let redir = match client.get(&location)
                .header(reqwest::header::COOKIE, &format!("inloggen-stickiness={}; JSESSIONID={}", inloggen_stickiness, jsessionid))
                .send() {
            Ok(o) => o,
            Err(e) => {
                logger.log(&format!("failed to send request to get authorization_code: '{:?}'", e), logging::Level::Error);
                return false;
            }
        };

        logger.log(&format!("got third response (GET previous location header + last JSESSIONID and inloggen-stickiness): {:#?}", redir), logging::Level::Debug);
        logger.log(&format!("login flow: {:#?}", self.find_login_flow(&client, &authorization_code, &jsessionid, &inloggen_stickiness, logger)), logging::Level::Debug);

        false
    }
}
