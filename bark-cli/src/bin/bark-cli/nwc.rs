use bark_cli::util::output_json;
use bark_rest_client::apis::configuration::Configuration;
use bark_rest_client::apis::nwc_api;
use bark_rest_client::models;

use crate::connect::RestResultExt;

#[derive(clap::Subcommand)]
pub enum NwcCommand {
	/// Create a connection and print its nostr+walletconnect:// URI
	///
	/// The connection may call every method bark supports, pay_invoice
	/// included, unless it is turned off with one of the --no-<method> flags.
	///
	/// The URI holds the connection's secret and is only shown once. A lost
	/// URI has to be revoked and recreated.
	#[command()]
	Create {
		/// A name for the connection, shown when listing it
		name: String,
		#[command(flatten)]
		methods: MethodFlags,
	},

	/// List connections
	#[command()]
	List,

	/// Revoke a connection
	#[command()]
	Revoke {
		/// The connection's client public key, as shown by `nwc list`
		client_pubkey: String,
	},

	/// Manage the relays NWC is served on
	#[command(subcommand)]
	Relays(RelaysCommand),
}

#[derive(clap::Subcommand)]
pub enum RelaysCommand {
	/// List relays
	#[command()]
	List,

	/// Add a relay
	///
	/// Existing connection URIs keep the relays they were created with.
	#[command()]
	Add {
		/// The relay, as a ws:// or wss:// url
		relay: String,
	},

	/// Remove a relay
	///
	/// An app whose URI names no remaining relay is cut off until it is given
	/// a new connection.
	#[command()]
	Remove {
		/// The relay, as listed by `nwc relays list`
		relay: String,
	},
}

/// Turns methods off for a new connection. A method without its flag keeps its
/// default, which is allowed.
#[derive(clap::Args)]
#[command(next_help_heading = "Methods")]
pub struct MethodFlags {
	/// Don't let the app read the wallet's network and block height
	#[arg(long)]
	no_get_info: bool,
	/// Don't let the app read the balance
	#[arg(long)]
	no_get_balance: bool,
	/// Don't let the app create invoices
	#[arg(long)]
	no_make_invoice: bool,
	/// Don't let the app look up invoices and payments
	#[arg(long)]
	no_lookup_invoice: bool,
	/// Don't let the app pay invoices, which keeps it from spending
	#[arg(long)]
	no_pay_invoice: bool,
	/// Don't let the app read the payment history
	#[arg(long)]
	no_list_transactions: bool,
}

impl MethodFlags {
	/// The flags as a request, leaving the methods without a flag unset so
	/// barkd applies its defaults to them.
	fn to_request(&self) -> models::NwcMethods {
		fn turned_off(flag: bool) -> Option<bool> {
			if flag { Some(false) } else { None }
		}

		models::NwcMethods {
			get_info: turned_off(self.no_get_info),
			get_balance: turned_off(self.no_get_balance),
			make_invoice: turned_off(self.no_make_invoice),
			lookup_invoice: turned_off(self.no_lookup_invoice),
			pay_invoice: turned_off(self.no_pay_invoice),
			list_transactions: turned_off(self.no_list_transactions),
		}
	}
}

pub async fn execute_nwc_command(
	nwc_command: NwcCommand,
	config: &Configuration,
) -> anyhow::Result<()> {
	match nwc_command {
		NwcCommand::Create { name, methods } => {
			let req = models::NwcConnectionRequest { name, methods: Some(methods.to_request()) };
			let resp = nwc_api::create_connection(config, req).await.rest()?;
			output_json(&resp);
		},
		NwcCommand::List => {
			let resp = nwc_api::list_connections(config).await.rest()?;
			output_json(&resp);
		},
		NwcCommand::Revoke { client_pubkey } => {
			nwc_api::revoke_connection(config, &client_pubkey).await.rest()?;
		},
		NwcCommand::Relays(RelaysCommand::List) => {
			let resp = nwc_api::list_relays(config).await.rest()?;
			output_json(&resp);
		},
		NwcCommand::Relays(RelaysCommand::Add { relay }) => {
			let req = models::NwcRelayRequest { relay };
			let resp = nwc_api::add_relay(config, req).await.rest()?;
			output_json(&resp);
		},
		NwcCommand::Relays(RelaysCommand::Remove { relay }) => {
			let resp = nwc_api::remove_relay(config, &relay).await.rest()?;
			output_json(&resp);
		},
	}

	Ok(())
}
