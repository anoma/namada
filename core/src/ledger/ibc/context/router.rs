//! Functions to handle IBC modules

use std::rc::Rc;

use super::super::{IbcActions, IbcCommonContext};
use crate::ibc::core::ics24_host::identifier::PortId;
use crate::ibc::core::router::{Module, ModuleId, Router};

impl<C> Router for IbcActions<'_, C>
where
    C: IbcCommonContext,
{
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

    fn has_route(&self, module_id: &ModuleId) -> bool {
        self.modules.contains_key(module_id)
    }

    fn lookup_module_by_port(&self, port_id: &PortId) -> Option<ModuleId> {
        self.ports.get(port_id).cloned()
    }
}
