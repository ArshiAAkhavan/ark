use std::io::Read;
use std::io::Write;
use std::net;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::TcpListener;
use std::net::TcpStream;
use std::thread;
use std::time;
use std::usize;

use threadpool;

use log::info;
use log::warn;

fn main() -> std::io::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let pool = threadpool::ThreadPool::new(5);

    let target_proxy_host = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 215, 14)), 80);

    let bind_address = "127.0.0.1:8080";
    let listener = TcpListener::bind(bind_address)?;
    info!("listening on {bind_address}");
    info!("proxying to {target_proxy_host}");

    for stream in listener.incoming() {
        info!("received request");
        match stream {
            Ok(stream) => {
                let target_proxy_host = target_proxy_host.clone();
                pool.execute(move || {
                    let target = TcpStream::connect_timeout(
                        &target_proxy_host,
                        time::Duration::from_secs(5),
                    )
                    .unwrap();
                    
                    let src = stream.try_clone().unwrap();
                    let dst = target.try_clone().unwrap();
                    let h1 = thread::spawn(move || pipe(src, dst));

                    let src = stream.try_clone().unwrap();
                    let dst = target.try_clone().unwrap();
                    let h2 = thread::spawn(move || pipe(dst, src));
                    
                    h1.join().unwrap();
                    h2.join().unwrap();
                })
            }
            Err(_) => todo!(),
        }
    }
    Ok(())
}

fn pipe(mut src: TcpStream, mut dst: TcpStream) {
    const BUFF_LEN: usize = 1 << 16;
    let mut buf = [0; BUFF_LEN];

    info!("handling connection on {:?}", src.local_addr());
    loop {
        match src.read(&mut buf) {
            Ok(nbytes @ 1..) => {
                info!("received {nbytes} on {:?}", src.peer_addr());
                let _ = dst.write_all(&buf[0..nbytes]).unwrap();
            }
            Ok(0) => {
                // 0 means that the Read channel of src is closed
                let _ = dst.shutdown(net::Shutdown::Write).unwrap();
                return;
            }
            Err(e) => {
                warn!("error occurred! {e}");
                let _ = src.shutdown(net::Shutdown::Read).unwrap();
                let _ = dst.shutdown(net::Shutdown::Write).unwrap();
                return;
            }
        }
    }
}
