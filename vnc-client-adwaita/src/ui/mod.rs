use std::cell::RefCell;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

pub mod connect_dialog;
pub mod history;
pub mod main_window;

pub type ConnectionVisibilityFn = Rc<dyn Fn(bool)>;
pub type RefreshHistoryFn = Rc<dyn Fn()>;
pub type RefreshHistoryRef = Rc<RefCell<Option<RefreshHistoryFn>>>;
pub type ReachabilityResults = Arc<Mutex<Vec<(usize, bool)>>>;
pub type ReachabilityResultsQueue = Rc<RefCell<ReachabilityResults>>;

pub use main_window::build_ui;
