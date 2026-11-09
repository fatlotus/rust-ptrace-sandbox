#[macro_use]
mod common;

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::unix::io::AsRawFd;
use std::thread;

nondeterminism_test!(
    ephemeral_port_allocation_is_deterministic,
    || {
        let l1 = TcpListener::bind("127.0.0.1:0").unwrap();
        let l2 = TcpListener::bind("127.0.0.1:0").unwrap();
        (l1.local_addr().unwrap().port(), l2.local_addr().unwrap().port())
    },
    |&(p1, p2)| {
        assert_eq!(p1, 1024);
        assert_eq!(p2, 1025);
    }
);

sandbox_test!(
    tcp_loopback_echo_shutdown_and_peername,
    || {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server = thread::spawn(move || {
            let (mut stream, accepted_peer) = listener.accept().unwrap();
            let peer_via_syscall = stream.peer_addr().unwrap();
            assert_eq!(accepted_peer, peer_via_syscall);

            let mut received = Vec::new();
            stream.read_to_end(&mut received).unwrap();
            stream.write_all(&received).unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
            accepted_peer.port()
        });

        let mut client = TcpStream::connect(server_addr).unwrap();
        assert!(client.take_error().unwrap().is_none());
        let client_port = client.local_addr().unwrap().port();
        assert_eq!(client.peer_addr().unwrap(), server_addr);

        client.write_all(b"ping-pong-payload").unwrap();
        client.shutdown(Shutdown::Write).unwrap();

        let mut echoed = String::new();
        client.read_to_string(&mut echoed).unwrap();
        let server_saw_port = server.join().unwrap();
        assert_eq!(client_port, server_saw_port);

        (server_addr.port(), client_port, echoed)
    },
    |(server_port, client_port, echoed)| {
        assert_eq!(*server_port, 1024);
        assert_eq!(*client_port, 1025);
        assert_eq!(echoed, "ping-pong-payload");
    }
);

sandbox_test!(
    virtual_socket_sendmsg_recvmsg_and_peek,
    || unsafe {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();

        let cfd = client.as_raw_fd();
        let sfd = server.as_raw_fd();

        // 1. MSG_DONTWAIT on empty socket must return EAGAIN
        let mut tmp = [0u8; 4];
        let empty_ret = libc::recv(
            sfd,
            tmp.as_mut_ptr() as *mut libc::c_void,
            tmp.len(),
            libc::MSG_DONTWAIT,
        );
        assert_eq!(empty_ret, -1);
        assert_eq!(*libc::__errno_location(), libc::EAGAIN);

        // 2. sendmsg with 2 scatter/gather iovecs ("hel" + "lo!")
        let part1 = b"hel";
        let part2 = b"lo!";
        let mut send_iov = [
            libc::iovec {
                iov_base: part1.as_ptr() as *mut libc::c_void,
                iov_len: part1.len(),
            },
            libc::iovec {
                iov_base: part2.as_ptr() as *mut libc::c_void,
                iov_len: part2.len(),
            },
        ];
        let mut send_hdr: libc::msghdr = std::mem::zeroed();
        send_hdr.msg_iov = send_iov.as_mut_ptr();
        send_hdr.msg_iovlen = send_iov.len() as _;
        let sent = libc::sendmsg(cfd, &send_hdr, 0);
        assert_eq!(sent, 6);

        // 3. MSG_PEEK should read "hel" without consuming it from the virtual socket buffer
        let mut peek_buf = [0u8; 3];
        let peek_n = libc::recv(
            sfd,
            peek_buf.as_mut_ptr() as *mut libc::c_void,
            peek_buf.len(),
            libc::MSG_PEEK,
        );
        assert_eq!(peek_n, 3);

        // 4. recvmsg into 2 iovecs (2 bytes + 4 bytes) should still receive all 6 bytes ("he" + "llo!")
        let mut r1 = [0u8; 2];
        let mut r2 = [0u8; 4];
        let mut recv_iov = [
            libc::iovec {
                iov_base: r1.as_mut_ptr() as *mut libc::c_void,
                iov_len: r1.len(),
            },
            libc::iovec {
                iov_base: r2.as_mut_ptr() as *mut libc::c_void,
                iov_len: r2.len(),
            },
        ];
        let mut recv_hdr: libc::msghdr = std::mem::zeroed();
        recv_hdr.msg_iov = recv_iov.as_mut_ptr();
        recv_hdr.msg_iovlen = recv_iov.len() as _;
        let recvd = libc::recvmsg(sfd, &mut recv_hdr, 0);
        assert_eq!(recvd, 6);

        (peek_buf, r1, r2)
    },
    |(peek_buf, r1, r2)| {
        assert_eq!(peek_buf, b"hel");
        assert_eq!(r1, b"he");
        assert_eq!(r2, b"llo!");
    }
);

sandbox_test!(
    virtual_socket_inaddr_any_and_stat_edge_cases,
    || unsafe {
        let lsock = libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0);
        assert!(lsock >= 0);

        let eagain_acc = libc::accept(lsock, std::ptr::null_mut(), std::ptr::null_mut());
        assert_eq!(eagain_acc, -1);
        assert_eq!(*libc::__errno_location(), libc::EAGAIN);

        let mut sin: libc::sockaddr_in = std::mem::zeroed();
        sin.sin_family = libc::AF_INET as u16;
        sin.sin_addr.s_addr = 0; // INADDR_ANY (0.0.0.0)
        sin.sin_port = 0;
        assert_eq!(
            libc::bind(
                lsock,
                &sin as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as u32,
            ),
            0
        );
        assert_eq!(libc::listen(lsock, 1), 0);

        let mut bound_sin: libc::sockaddr_in = std::mem::zeroed();
        let mut bound_len: u32 = std::mem::size_of::<libc::sockaddr_in>() as u32;
        assert_eq!(
            libc::getsockname(
                lsock,
                &mut bound_sin as *mut _ as *mut libc::sockaddr,
                &mut bound_len,
            ),
            0
        );

        let csock = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        let mut dst_sin: libc::sockaddr_in = std::mem::zeroed();
        dst_sin.sin_family = libc::AF_INET as u16;
        dst_sin.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
        dst_sin.sin_port = bound_sin.sin_port;
        assert_eq!(
            libc::connect(
                csock,
                &dst_sin as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as u32,
            ),
            0
        );

        // Accept with a 4-byte buffer and sentinel bytes after it to verify no buffer overflow
        let mut tiny_buf = [0xAAu8; 16];
        let mut tiny_len: u32 = 4;
        let asock = libc::accept(
            lsock,
            tiny_buf.as_mut_ptr() as *mut libc::sockaddr,
            &mut tiny_len,
        );
        assert!(asock >= 0);

        let mut st_fstat: libc::stat = std::mem::zeroed();
        assert_eq!(libc::fstat(asock, &mut st_fstat), 0);

        let mut st_fstatat: libc::stat = std::mem::zeroed();
        assert_eq!(
            libc::syscall(
                libc::SYS_newfstatat,
                asock,
                b"\0".as_ptr(),
                &mut st_fstatat as *mut libc::stat,
                libc::AT_EMPTY_PATH,
            ),
            0
        );

        const STATX_BASIC_STATS: libc::c_uint = 0x000007ff;
        let mut stx = [0u8; 256];
        assert_eq!(
            libc::syscall(
                libc::SYS_statx,
                asock,
                b"\0".as_ptr(),
                libc::AT_EMPTY_PATH,
                STATX_BASIC_STATS,
                stx.as_mut_ptr(),
            ),
            0
        );
        let stx_mode = u16::from_ne_bytes(stx[28..30].try_into().unwrap());

        libc::close(asock);
        libc::close(csock);
        libc::close(lsock);

        (
            tiny_len,
            tiny_buf[4],
            st_fstat.st_mode & libc::S_IFMT,
            st_fstatat.st_mode & libc::S_IFMT,
            (stx_mode as u32) & libc::S_IFMT,
        )
    },
    |&(tiny_len, sentinel, mode1, mode2, mode3)| {
        assert_eq!(tiny_len, 16);
        assert_eq!(sentinel, 0xAA);
        assert_eq!(mode1, libc::S_IFSOCK);
        assert_eq!(mode2, libc::S_IFSOCK);
        assert_eq!(mode3, libc::S_IFSOCK);
    }
);

sandbox_test!(
    socketpair_and_pipe2_ipc,
    || unsafe {
        let mut sv = [-1i32; 2];
        assert_eq!(
            libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()),
            0
        );
        assert_eq!(libc::write(sv[0], b"unix".as_ptr() as *const _, 4), 4);
        let mut sbuf = [0u8; 4];
        assert_eq!(libc::read(sv[1], sbuf.as_mut_ptr() as *mut _, 4), 4);
        libc::close(sv[0]);
        libc::close(sv[1]);

        let mut pfd = [-1i32; 2];
        assert_eq!(libc::pipe2(pfd.as_mut_ptr(), libc::O_CLOEXEC), 0);
        assert_eq!(libc::write(pfd[1], b"pipe".as_ptr() as *const _, 4), 4);
        let mut pbuf = [0u8; 4];
        assert_eq!(libc::read(pfd[0], pbuf.as_mut_ptr() as *mut _, 4), 4);
        libc::close(pfd[0]);
        libc::close(pfd[1]);

        (sbuf, pbuf)
    },
    |(sbuf, pbuf)| {
        assert_eq!(sbuf, b"unix");
        assert_eq!(pbuf, b"pipe");
    }
);
