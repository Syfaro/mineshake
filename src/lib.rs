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

fn u32_to_u8(num: u32) -> [u8; 4] {
    [
        ((num >> 24) & 0xFF) as u8,
        ((num >> 16) & 0xFF) as u8,
        ((num >> 8) & 0xFF) as u8,
        (num & 0xFF) as u8,
    ]
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
    Ok(resolve::DnsConfig::load_default()?)
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

impl From<std::num::ParseIntError> for Error {
    fn from(error: std::num::ParseIntError) -> Self {
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
        None => {
            return Err(Error {
                message: "unable to resolve".to_string(),
                bad_server: true,
            })
        }
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

fn parse_plugins(plugins: Option<String>) -> (String, Vec<String>) {
    let plugins = match plugins {
        None => return ("".to_string(), vec![]),
        Some(plugins) => plugins,
    };

    let mut parts = plugins.split(": ");

    let server_mod_name = parts.next().unwrap();
    let plugins: Vec<String> = match parts.next() {
        Some(plugins) => plugins
            .split("; ")
            .map(|plugin| plugin.to_string())
            .collect(),
        None => vec![],
    };

    return (server_mod_name.to_string(), plugins);
}

#[derive(Debug, Serialize)]
pub struct Query {
    pub hostname: String,
    pub gametype: String,
    pub game_id: String,
    pub version: String,
    pub plugins: (String, Vec<String>),
    pub map: String,
    pub numplayers: usize,
    pub maxplayers: usize,
    pub hostport: u16,
    pub hostip: String,
    pub players: Vec<String>,
}

fn string_until_zero<T>(reader: &mut T) -> Option<String>
where
    T: Read,
{
    let mut items: Vec<u8> = vec![];

    let mut buf = [0; 1];
    loop {
        if reader.read_exact(&mut buf).is_err() {
            return None;
        }

        match buf[0] {
            0x00 => break,
            _ => items.push(buf[0]),
        }
    }

    if items.is_empty() {
        return None;
    }

    Some(String::from_utf8_lossy(&items).to_string())
}

fn string_until_zero_expected<T>(mut reader: &mut T, expected: &str) -> Option<String>
where
    T: Read,
{
    let key = match string_until_zero(&mut reader) {
        Some(key) => key,
        None => return None,
    };

    if &key != expected {
        return None;
    }

    string_until_zero(&mut reader)
}

fn parse_players<T>(mut reader: &mut T) -> Vec<String>
where
    T: Read,
{
    let mut players = vec![];

    let mut _garbage = vec![0; 11];
    let _err = reader.read_exact(&mut _garbage);

    loop {
        match string_until_zero(&mut reader) {
            Some(player) => players.push(player),
            None => break,
        }
    }

    players
}

pub fn send_query(host: &str, port: u16) -> Result<Query, Error> {
    use std::net::UdpSocket;

    let conn = resolve(host, port)?;

    let socket = UdpSocket::bind("127.0.0.1:0")?;
    socket.connect(conn)?;

    let session_id = rand::random::<u32>() & 0x0F0F0F0F;

    let mut request = vec![0xFE, 0xFD, 0x09];
    request.extend(&u32_to_u8(session_id));

    socket.send(&request)?;

    let mut buf: Vec<u8> = vec![0; 2048];
    let len = socket.recv(&mut buf)?;

    let challenge_token: i32 = String::from_utf8_lossy(&buf[5..len - 1]).parse()?;

    let mut request = vec![0xFE, 0xFD, 0x00];
    request.extend(&u32_to_u8(session_id));
    request.extend(&u32_to_u8(challenge_token as u32));
    request.extend(vec![0x00, 0x00, 0x00, 0x00]);

    socket.send(&request)?;

    let len = socket.recv(&mut buf)?;
    let mut cursor = std::io::Cursor::new(&buf[16..len - 1]);

    Ok(Query {
        hostname: string_until_zero_expected(&mut cursor, "hostname").unwrap(),
        gametype: string_until_zero_expected(&mut cursor, "gametype").unwrap(),
        game_id: string_until_zero_expected(&mut cursor, "game_id").unwrap(),
        version: string_until_zero_expected(&mut cursor, "version").unwrap(),
        plugins: parse_plugins(string_until_zero_expected(&mut cursor, "plugins")),
        map: string_until_zero_expected(&mut cursor, "map").unwrap(),
        numplayers: string_until_zero_expected(&mut cursor, "numplayers")
            .unwrap()
            .parse()
            .unwrap_or(0),
        maxplayers: string_until_zero_expected(&mut cursor, "maxplayers")
            .unwrap()
            .parse()
            .unwrap_or(0),
        hostport: string_until_zero_expected(&mut cursor, "hostport")
            .unwrap()
            .parse()
            .unwrap_or(0),
        hostip: string_until_zero_expected(&mut cursor, "hostip").unwrap(),
        players: parse_players(&mut cursor),
    })
}

#[cfg(test)]
mod tests {
    use super::{
        build_packet, encode_varint, parse_players, parse_plugins, read_varint, resolve_srv,
        send_ping, send_query, string_until_zero, string_until_zero_expected,
    };

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
    fn test_string_until_zero() {
        let mut cursor = std::io::Cursor::new(vec![102, 111, 120, 0, 104, 105, 0]);

        let msg = string_until_zero(&mut cursor);

        assert!(!msg.is_none());
        assert_eq!(msg.unwrap(), "fox");

        let msg = string_until_zero(&mut cursor);

        assert!(!msg.is_none());
        assert_eq!(msg.unwrap(), "hi");

        let msg = string_until_zero(&mut cursor);

        assert!(msg.is_none());
    }

    #[test]
    fn test_string_until_zero_expected() {
        let mut cursor = std::io::Cursor::new(vec![107, 0, 118, 0]);

        let msg = string_until_zero_expected(&mut cursor, "k");

        assert!(!msg.is_none());
        assert_eq!(msg.unwrap(), "v");
    }

    #[test]
    fn test_parse_plugins() {
        let plugins = parse_plugins(None);
        assert_eq!(plugins.0, "");
        assert_eq!(plugins.1.len(), 0);

        let plugins = parse_plugins(Some("CraftBukkit on Bukkit 1.2.5-R4.0".to_string()));
        assert_eq!(plugins.0, "CraftBukkit on Bukkit 1.2.5-R4.0");
        assert_eq!(plugins.1.len(), 0);

        let plugins = parse_plugins(Some(
            "CraftBukkit on Bukkit 1.2.5-R4.0: WorldEdit 5.3; CommandBook 2.1".to_string(),
        ));
        assert_eq!(plugins.0, "CraftBukkit on Bukkit 1.2.5-R4.0");
        assert_eq!(plugins.1, vec!["WorldEdit 5.3", "CommandBook 2.1"]);
    }

    #[test]
    fn test_parse_players() {
        let mut cursor = std::io::Cursor::new(vec![97, 0, 98, 0, 99, 0, 0]);
        let players = parse_players(&mut cursor);

        assert_eq!(players, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_send_ping() {
        match send_ping("ping.minecraft.syfaro.net", 25565) {
            Ok(ping) => println!("{:?}", ping),
            Err(_) => assert!(false, "should not error"),
        }

        match send_ping("s.nerd.nu", 25565) {
            Ok(ping) => println!("{:?}", ping),
            Err(_) => assert!(false, "should not error"),
        }
    }

    #[test]
    fn test_send_query() {
        match send_query("127.0.0.1", 25565) {
            Ok(query) => println!("{:?}", query),
            Err(_e) => assert!(false, "should not error"),
        }
    }
}
