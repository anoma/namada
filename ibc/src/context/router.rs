//! Functions to handle IBC modules

use std::collections::HashMap;
use std::rc::Rc;

use namada_core::ibc::core::host::types::identifiers::PortId;
use namada_core::ibc::core::router::module::Module;
use namada_core::ibc::core::router::router::Router;
use namada_core::ibc::core::router::types::module::ModuleId;

use super::super::ModuleWrapper;

/// IBC router
#[derive(Debug, Default)]
pub struct IbcRouter<'a> {
    modules: HashMap<ModuleId, Rc<dyn ModuleWrapper + 'a>>,
    ports: HashMap<PortId, ModuleId>,
}

impl<'a> IbcRouter<'a> {
    /// Make new Router
    pub fn new() -> Self {
        Self {
            modules: HashMap::new(),
            ports: HashMap::new(),
        }
    }

    /// Add TokenTransfer route
    pub fn add_transfer_module(
        &mut self,
        module_id: ModuleId,
        module: impl ModuleWrapper + 'a,
    ) {
        self.modules.insert(module_id.clone(), Rc::new(module));
        self.ports.insert(PortId::transfer(), module_id);
    }
}

impl<'a> Router for IbcRouter<'a> {
    fn get_route(&self, module_id: &ModuleId) -> Option<&dyn Module> {
        self.modules.get(module_id).map(|b| b.as_module())
    }

    fn get_route_mut(
        &mut self,
        module_id: &ModuleId,
    ) -> Option<&mut dyn Module> {
        self.modules
            .get_mut(module_id)
            .and_then(Rc::get_mut)
            .map(|b| b.as_module_mut())
    }

    fn lookup_module(&self, port_id: &PortId) -> Option<ModuleId> {
        self.ports.get(port_id).cloned()
    }
}
