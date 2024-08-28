use clap::Parser;
use ishare::ishare::ISHARE;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    target_id: Option<String>,

    #[arg(short, long)]
    id_client: String,

    #[arg(short, long)]
    password: String,

    #[arg(short, long)]
    cert_file: String,

    #[arg(long)]
    perm_ishare: Option<String>,

    #[arg(short, long)]
    sattelite_url: String,

    #[arg(short, long)]
    eori_sattelite: String,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let ishare = ISHARE::new(
        args.cert_file,
        args.password,
        args.sattelite_url,
        args.perm_ishare,
        args.id_client.clone(),
        args.eori_sattelite,
    )
    .unwrap();
    let token = ishare.create_client_assertion(args.target_id).unwrap();

    println!("{}", token);
}
