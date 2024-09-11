#[macro_use]
extern crate log;

pub mod convert;
pub mod grpc;
pub mod subscribe_sendpay;

pub type ClnGrpcClient = grpc::node_client::NodeClient<tonic::transport::Channel>;
