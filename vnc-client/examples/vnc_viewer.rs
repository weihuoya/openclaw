use std::env;
use std::thread;
use std::time::Duration;

use vnc_client::auth::NoAuthHandler;
use vnc_client::{encodings::Encoding, VncClient, VncEvent};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <host:port> [--password]", args[0]);
        std::process::exit(1);
    }

    let addr = &args[1];
    println!("Connecting to {}...", addr);

    let mut client = VncClient::new();
    client.connect(addr)?;

    let mut auth = NoAuthHandler;
    let events = client.handshake(&mut auth)?;

    for event in &events {
        println!("Event: {:?}", event);
    }

    let (width, height) = client.dimensions();
    println!("Connected! Desktop: {}x{}", width, height);
    println!("Name: {}", client.name());

    // Request 32-bit RGBA
    client.set_pixel_format(vnc_client::PixelFormat::rgba32())?;

    // Set encodings
    client.set_encodings(&[
        Encoding::Zrle,
        Encoding::Hextile,
        Encoding::Raw,
        Encoding::CopyRect,
        Encoding::DesktopSize,
    ])?;

    // Request full framebuffer update
    client.request_update(false, 0, 0, width, height)?;

    // Read server messages
    println!("Waiting for framebuffer updates...");
    let mut update_count = 0;
    loop {
        match client.read_messages() {
            Ok(events) => {
                for event in events {
                    match event {
                        VncEvent::FramebufferUpdate {
                            x,
                            y,
                            width,
                            height,
                        } => {
                            update_count += 1;
                            println!(
                                "Update #{}: {}x{} at ({}, {})",
                                update_count, width, height, x, y
                            );

                            if update_count >= 5 {
                                println!("Received 5 updates, disconnecting.");
                                return Ok(());
                            }

                            // Request next incremental update
                            let (w, h) = client.dimensions();
                            client.request_update(true, 0, 0, w, h)?;
                        }
                        other => println!("Event: {:?}", other),
                    }
                }
            }
            Err(e) => {
                println!("Error: {}", e);
                break;
            }
        }
        thread::sleep(Duration::from_millis(10));
    }

    Ok(())
}
