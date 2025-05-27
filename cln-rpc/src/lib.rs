
mod cln;
pub use cln::*;

mod convert;

pub mod plugins;

pub type ClnGrpcClient = cln::node_client::NodeClient<tonic::transport::Channel>;
