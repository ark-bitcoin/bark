
mod cln {
	tonic::include_proto!("cln");
}
pub use cln::*;

mod convert;

pub mod plugins {
	pub mod hold {
		tonic::include_proto!("hold");
	}
}

pub type ClnGrpcClient = cln::node_client::NodeClient<tonic::transport::Channel>;
