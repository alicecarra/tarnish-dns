use std::net::UdpSocket;

use tarnish_dns::buffer::PacketBuffer;
use tarnish_dns::protocol::DnsPacket;
use tarnish_dns::protocol::DnsQuestion;
use tarnish_dns::protocol::QueryType;
use tarnish_dns::DnsError;

fn main() -> tarnish_dns::Result<()> {
    let qname = "www.github.com";
    let qtype = QueryType::MX;
    let server = ("8.8.8.8", 53);

    let socket = UdpSocket::bind(("0.0.0.0", 5454))
        .map_err(|error| DnsError::SocketBind { source: error })?;

    let mut packet = DnsPacket::new();

    packet.header.id = 42;
    packet.header.questions = 1;
    packet.header.recursion_desired = true;
    packet
        .questions
        .push(DnsQuestion::new(qname.to_string(), qtype));

    let mut request_buffer = PacketBuffer::new();
    packet.write(&mut request_buffer)?;

    socket
        .send_to(&request_buffer.buffer[0..request_buffer.position], server)
        .map_err(|source| DnsError::SocketIO { source })?;

    let mut response_buffer = PacketBuffer::new();
    socket
        .recv_from(&mut response_buffer.buffer)
        .map_err(|source| DnsError::SocketIO { source })?;

    let response_packet = DnsPacket::from_buffer(&mut response_buffer)?;

    // TODO: impl display for Packet?
    println!("{:#?}", response_packet.header);

    for question in response_packet.questions {
        println!("{:#?}", question);
    }
    for record in response_packet.answers {
        println!("{:#?}", record);
    }
    for record in response_packet.authorities {
        println!("{:#?}", record);
    }
    for record in response_packet.resources {
        println!("{:#?}", record);
    }

    Ok(())
}
