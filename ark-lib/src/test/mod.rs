
use crate::Vtxo;
use crate::vtxo::GenesisTransition;

impl Vtxo {
	pub fn invalidate_final_sig(&mut self) {
		let fake = "cc8b93e9f6fbc2506bb85ae8bbb530b178daac49704f5ce2e3ab69c266fd59320b28d028eef212e3b9fdc42cfd2e0760a0359d3ea7d2e9e8cfe2040e3f1b71ea".parse().unwrap();
		let item = self.genesis.last_mut().unwrap();
		match item.transition {
			GenesisTransition::Cosigned { ref mut signature, .. } => *signature = fake,
			GenesisTransition::Arkoor { ref mut signature, .. } => {
				signature.replace(fake).expect("didn't have arkoor signature");
			},
		}
	}
}
