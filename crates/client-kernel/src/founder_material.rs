use std::{future::Future, pin::Pin};

use egopulse_domain_contracts::v01::egopulse::localapi::v1::{
    CreateFounderSupportingMaterialRequest, CreateFounderSupportingMaterialResponse,
};

use crate::{AuthorizedCommand, ClientKernel, KernelError};

const CREATE_FOUNDER_SUPPORTING_MATERIAL_RPC: &str =
    "LocalCommandGatewayService/CreateFounderSupportingMaterial";
const CREATE_FOUNDER_SUPPORTING_MATERIAL_COMMAND: &str = "create_founder_supporting_material";

impl ClientKernel {
    /// Authorizes the supporting-material composition port through its frozen
    /// per-command rule. The top-level RPC is deliberately not a grant path.
    pub fn authorize_create_founder_supporting_material(
        &self,
    ) -> Result<AuthorizedCommand, KernelError> {
        let session = self.session().ok_or(KernelError::SessionUnavailable)?;
        self.profiles().authorize_command(
            CREATE_FOUNDER_SUPPORTING_MATERIAL_RPC,
            CREATE_FOUNDER_SUPPORTING_MATERIAL_COMMAND,
            &session.granted_permission_codes,
        )
    }
}

pub type FounderMaterialRpcFuture<'a> = Pin<
    Box<dyn Future<Output = Result<CreateFounderSupportingMaterialResponse, String>> + Send + 'a>,
>;

/// Narrow client-kernel seam for the existing authenticated gateway RPC.
pub trait CreateFounderSupportingMaterialRpc: Send {
    fn create_founder_supporting_material<'a>(
        &'a mut self,
        request: CreateFounderSupportingMaterialRequest,
    ) -> FounderMaterialRpcFuture<'a>;
}

#[derive(Default)]
pub struct FakeCreateFounderSupportingMaterialRpc {
    pub requests: Vec<CreateFounderSupportingMaterialRequest>,
    pub responses: Vec<Result<CreateFounderSupportingMaterialResponse, String>>,
}

impl CreateFounderSupportingMaterialRpc for FakeCreateFounderSupportingMaterialRpc {
    fn create_founder_supporting_material<'a>(
        &'a mut self,
        request: CreateFounderSupportingMaterialRequest,
    ) -> FounderMaterialRpcFuture<'a> {
        self.requests.push(request);
        let response = if self.responses.is_empty() {
            Err("fake founder material response unavailable".to_owned())
        } else {
            self.responses.remove(0)
        };
        Box::pin(async move { response })
    }
}
