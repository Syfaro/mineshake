use std::io::prelude::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};

use serde_derive::{Deserialize, Serialize};

fn encode_varint(num: u32) -> Vec<u8> {
    let mut val = num;
    let mut varint: Vec<u8> = vec![];

    while val & 0xFFFF_FF80 != 0 {
        let item = (val & 0x7F) | 0x80;
        varint.push(item as u8);
        val >>= 7;
    }

    varint.push((val & 0x7F) as u8);

    varint
}

fn read_varint<T>(reader: &mut T) -> Result<u32, std::io::Error>
where
    T: Read,
{
    // Storage for each byte as its read
    let mut buf: Vec<u8> = vec![0; 1];
    // Final result value
    let mut result: u32 = 0;
    // How many bits have been read
    let mut index = 0;

    loop {
        // Read a single byte
        reader.read_exact(&mut buf)?;

        // Ignore top bit, only care about 7 bits right now
        // However, we need 32 bits of working space to shift
        let value = u32::from(buf[0] & 0b0111_1111);

        // Merge bits into previous bits after shifting to correct position
        result |= value << (7 * index);

        index += 1;
        // If length is greater than 5, something is wrong
        if index > 5 {
            break;
        }

        // If top bit was zero, we're done
        if buf[0] & 0b1000_0000 == 0 {
            break;
        }
    }

    Ok(result)
}

fn u16_to_u8(num: u16) -> [u8; 2] {
    [((num >> 8) & 0xFF) as u8, (num & 0xFF) as u8]
}

fn build_packet(data: Vec<u8>, id: u32) -> Vec<u8> {
    let id = encode_varint(id);
    let len = encode_varint((data.len() + id.len()) as u32);

    let mut packet = vec![];

    packet.extend(len);
    packet.extend(id);
    packet.extend(data);

    packet
}

fn build_handshake(host: &str, port: u16) -> Vec<u8> {
    let mut data = vec![];

    data.extend(encode_varint(0x47));
    data.extend(encode_varint(host.len() as u32));
    data.extend(host.as_bytes());
    data.extend(&u16_to_u8(port));
    data.extend(encode_varint(1));

    data
}

#[cfg(unix)]
fn get_dns_config() -> Result<resolve::DnsConfig, resolve::Error> {
    resolve::DnsConfig::load_default()?
}

#[cfg(windows)]
fn get_dns_config() -> Result<resolve::DnsConfig, resolve::Error> {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    // TODO: make configurable
    Ok(resolve::DnsConfig::with_name_servers(vec![
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)), 53),
    ]))
}

fn resolve_srv(host: &str) -> Result<Option<String>, resolve::Error> {
    let config = get_dns_config()?;
    let resolver = resolve::DnsResolver::new(config)?;

    let name = format!("_minecraft._tcp.{}", host);

    match resolver.resolve_record::<resolve::record::Srv>(&name) {
        Err(_) => Ok(None),
        Ok(records) => {
            let result = if records.is_empty() {
                None
            } else {
                Some(format!("{}:{}", records[0].target, records[0].port))
            };

            Ok(result)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Version {
    pub name: String,
    pub protocol: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlayerSample {
    pub name: String,
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Players {
    pub max: u32,
    pub online: u32,
    pub sample: Option<Vec<PlayerSample>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ping {
    pub version: Version,
    pub players: Players,
    pub description: serde_json::Value,
    pub favicon: Option<String>,
}

impl Ping {
    pub fn get_motd(&self) -> Option<String> {
        // TODO: make this handle parsing extra fields
        match &self.description {
            serde_json::Value::Object(desc) => match desc.get("text") {
                Some(text) => match text {
                    serde_json::Value::String(text) => Some(text.to_string()),
                    _ => None,
                },
                None => None,
            },
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct Error {
    /// If the server was unable to be resolved or connected to.
    pub bad_server: bool,
    message: String,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for Error {
    fn description(&self) -> &str {
        &self.message
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self {
            message: error.to_string(),
            bad_server: true,
        }
    }
}

impl From<std::string::FromUtf8Error> for Error {
    fn from(error: std::string::FromUtf8Error) -> Self {
        Self {
            message: error.to_string(),
            bad_server: false,
        }
    }
}

impl From<serde_json::error::Error> for Error {
    fn from(error: serde_json::error::Error) -> Self {
        Self {
            message: error.to_string(),
            bad_server: false,
        }
    }
}

fn resolve(host: &str, port: u16) -> Result<std::net::SocketAddr, Error> {
    let resolved = resolve_srv(&host);

    let host = if let Ok(resolved) = resolved {
        if let Some(host) = resolved {
            host
        } else {
            format!("{}:{}", host, port)
        }
    } else {
        format!("{}:{}", host, port)
    };

    let mut addrs = host.to_socket_addrs()?;

    match addrs.next() {
        Some(addr) => Ok(addr),
        None => return Err(Error {
            message: "unable to resolve".to_string(),
            bad_server: true,
        })
    }
}

pub fn send_ping(host: &str, port: u16) -> Result<Ping, Error> {
    let conn = resolve(host, port)?;

    // TODO: allow configuration for read timeout
    let second = std::time::Duration::new(1, 0);

    let mut stream = TcpStream::connect_timeout(&conn, second)?;
    stream.set_read_timeout(Some(second))?;

    let handshake = build_packet(build_handshake(&host, port), 0x00);
    stream.write_all(&handshake)?;

    let request = build_packet(vec![], 0x00);
    stream.write_all(&request)?;

    let _packet_length = read_varint(&mut stream)?;
    let _packet_id = read_varint(&mut stream)?;

    let string_len = read_varint(&mut stream)? as usize;

    let mut data: Vec<u8> = vec![0; string_len];
    stream.read_exact(&mut data)?;

    let s = String::from_utf8(data)?;
    let ping: Ping = serde_json::from_str(&s)?;

    Ok(ping)
}

#[cfg(test)]
mod tests {
    use super::{build_packet, encode_varint, read_varint, resolve_srv, send_ping};

    #[test]
    fn test_encode_varint() {
        assert_eq!(vec![0x00], encode_varint(0));
        assert_eq!(vec![0x01], encode_varint(1));
        assert_eq!(vec![0xFF, 0x01], encode_varint(255));
        assert_eq!(
            vec![0xFF, 0xFF, 0xFF, 0xFF, 0x07],
            encode_varint(2_147_483_647)
        );
    }

    #[test]
    fn test_read_varint() {
        let src: Vec<u8> = vec![0x00];
        assert_eq!(0, read_varint(&mut src.as_slice()).unwrap());

        let src: Vec<u8> = vec![0x01];
        assert_eq!(1, read_varint(&mut src.as_slice()).unwrap());

        let src: Vec<u8> = vec![0xFF, 0x01];
        assert_eq!(255, read_varint(&mut src.as_slice()).unwrap());

        let src: Vec<u8> = vec![0b1000_0100, 0b0100_0000];
        assert_eq!(8196, read_varint(&mut src.as_slice()).unwrap());

        let src: Vec<u8> = vec![0xFF, 0xFF, 0xFF, 0xFF, 0x07];
        assert_eq!(2_147_483_647, read_varint(&mut src.as_slice()).unwrap());
    }

    #[test]
    fn test_build_packet() {
        let packet = build_packet(vec![], 0x00);
        assert_eq!(packet, vec![0x01, 0x00]);

        let packet = build_packet(vec![0x00], 0x00);
        assert_eq!(packet, vec![0x02, 0x00, 0x00]);
    }

    #[test]
    fn test_resolve_srv() {
        let resolved = match resolve_srv("ping.minecraft.syfaro.net") {
            Ok(resolved) => resolved,
            Err(_) => {
                assert!(false, "should be able to resolve srv record");
                return;
            }
        };

        let host = match resolved {
            Some(host) => host,
            None => {
                assert!(false, "should be able to find host from srv");
                return;
            }
        };

        assert_eq!(host, "play.gotpvp.com.:25565");

        let resolved = match resolve_srv("norecord.syfaro.net") {
            Ok(resolved) => resolved,
            Err(_) => {
                assert!(
                    false,
                    "should not cause error when srv record does not exist"
                );
                return;
            }
        };

        assert!(resolved.is_none());
    }

    #[test]
    fn test_send_ping() {
        match send_ping("ping.minecraft.syfaro.net", 25565) {
            Ok(ping) => println!("{:?}", ping),
            Err(_) => assert!(false, "should not error"),
        }

        match send_ping("Play.AspiriaMc.Com", 25565) {
            Ok(ping) => println!("{:?}", ping),
            Err(_) => assert!(false, "should not error"),
        }
    }
}
