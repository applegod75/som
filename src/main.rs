pub mod somtoday;
use std::io::Write;

use somtoday::logging;

fn main() {
    let logger = logging::Logger::new(logging::Level::Warn, String::from("Main"));
    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 2 {
        if args[1] == "--force-redownload-organisaties-json" {
            if !somtoday::download_write_organisaties_json(&logger) {
                ()
            }
        }
    }

    let auth = somtoday::Authenticator::new("", "", "", &logger)
        .expect("something was entered incorrectly probably");
    auth.authenticate(&logger);
}
