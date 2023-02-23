//! Functions to handle IBC modules

use std::ops::{Deref, DerefMut};

use super::super::{IbcActions, IbcStorageContext};
use crate::ibc::core::context::Router;
use crate::ibc::core::ics24_host::identifier::PortId;
use crate::ibc::core::ics26_routing::context::{Module, ModuleId};

impl<C> Router for IbcActions<C>
where
    C: IbcStorageContext,
{
    fn get_route(&self, module_id: &ModuleId) -> Option<&dyn Module> {
        self.modules.get(module_id).map(|b| b.deref())
    }

    fn get_route_mut(
        &mut self,
        module_id: &ModuleId,
    ) -> Option<&mut dyn Module> {
        self.modules.get_mut(module_id).map(|b| b.deref_mut())
    }

    fn has_route(&self, module_id: &ModuleId) -> bool {
        self.modules.contains_key(module_id)
    }

    fn lookup_module_by_port(&self, port_id: &PortId) -> Option<ModuleId> {
        self.ports.get(port_id).cloned()
    }
}
