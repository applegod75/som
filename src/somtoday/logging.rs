
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Trace,
    Debug,
    Warn,
    Error
}

pub struct Logger {
    selected: Level,
    name: String,
}

impl Logger {
    pub fn new(selected: Level, name: String) -> Logger {
        Logger {
            selected,
            name
        }
    }

    pub fn log(&self, msg: &str, severity: Level){
        if severity >= self.selected {
            println!("[{}/{:?}] {}", self.name, severity, msg);
        }
        ()
    }
}