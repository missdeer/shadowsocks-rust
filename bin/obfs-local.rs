// SPDX-License-Identifier: GPL-3.0-or-later

use std::{io, sync::Arc};

use obfs_local::{
    config::{self, Config},
    relay, system,
};

fn main() {
    let matches = config::command().get_matches();
    let environment = std::env::vars().filter(|(key, _)| key.starts_with("SS_")).collect();
    let result = Config::from_matches(&matches, &environment).and_then(|config| {
        system::prepare(&config)?;
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(run(config))
    });
    if let Err(error) = result {
        eprintln!("[obfs-local] {error}");
        std::process::exit(1);
    }
}

async fn run(config: Config) -> io::Result<()> {
    let remotes = relay::resolve_remotes(&config).await?;
    let listener = system::bind(&config).await?;
    system::switch_user(&config)?;
    eprintln!(
        "[obfs-local] {:?} obfuscation enabled; listening on {}",
        config.parameters.mode,
        listener.local_addr()?
    );
    relay::serve(listener, Arc::new(config), remotes).await
}
