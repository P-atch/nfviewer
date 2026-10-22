mod netlink;
mod pacp_writer;
use crate::netlink::{NfnlPayload, Socket, Verdict};
use crate::pacp_writer::PcapWriter;
use clap::Parser;
use std::fs::File;
use std::io::{Write, stdout};
use std::time::SystemTime;

#[derive(Parser)]
#[clap(author="Patch", about="A basic tool to listen for packets in Netfilter Queues", long_about = None)]
struct Args {
    #[clap(short, long)]
    queue_id: u16,
    #[clap(short, long, help = "Write raw packets to stdout")]
    write_stdout: bool,
    #[clap(
        short,
        long,
        help = "Write packets to this file (ignored if -w is used)"
    )]
    filename: Option<String>,
}

fn main() {
    let args = Args::parse();
    let mut socket = Socket::new();
    socket.bind(args.queue_id).unwrap();

    let writer: Option<Box<dyn Write>> = if args.write_stdout {
        eprintln!("Capture enabled on stdout");
        Some(Box::new(stdout()))
    } else if let Some(filename) = args.filename {
        eprintln!("Capture enabled with output to '{}'", filename);
        Some(Box::new(File::create(filename).unwrap()))
    } else {
        None
    };
    eprintln!("Listening on queue {}", args.queue_id);

    let mut capture = if let Some(writer) = writer {
        Some(PcapWriter::<Box<dyn Write>>::new(writer, pacp_writer::LinkType::Raw).unwrap())
    } else {
        None
    };

    loop {
        let ret = socket.receive_packet();
        let ret = if let Ok(ret) = ret {
            ret
        } else if let Err(err) = ret {
            eprintln!("Packet reception error: {}", err);
            continue;
        } else {
            unreachable!()
        };

        for (_hdr, payload) in ret {
            match payload {
                NfnlPayload::NfqnlMsgPacket {
                    queue_id: _,
                    packet_id,
                    mut payload,
                    hook: _,
                } => {
                    socket
                        .verdict(args.queue_id, packet_id, Verdict::Accept)
                        .unwrap();

                    let ip_payload = payload.drain(20..).collect();
                    eprintln!("IP Payload: {:?}", ip_payload);

                    let time = SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap();
                    if let Some(capture) = &mut capture {
                        capture
                            .add_packet(time.as_secs() as u32, time.subsec_millis(), ip_payload)
                            .unwrap();
                    }
                }
                _ => {}
            }
        }
    }
}
