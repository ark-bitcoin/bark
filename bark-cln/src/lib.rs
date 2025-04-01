
mod cln;
pub use cln::*;

mod convert;

pub type ClnGrpcClient = cln::node_client::NodeClient<tonic::transport::Channel>;
