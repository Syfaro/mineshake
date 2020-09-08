use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{lookup_host, TcpStream, UdpSocket},
};

use serde::{Deserialize, Serialize};

/// Encode a u32 into a VarInt.
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

/// Read a VarInt into a u32 from an AsyncRead type.
async fn read_varint<T>(reader: &mut T) -> Result<u32, std::io::Error>
where
    T: AsyncRead + Unpin,
{
    // Storage for each byte as its read
    let mut buf: Vec<u8> = vec![0; 1];
    // Final result value
    let mut result: u32 = 0;
    // How many bits have been read
    let mut index = 0;

    loop {
        // Read a single byte
        reader.read_exact(&mut buf).await?;

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

/// Build a packet by:
/// * Encoding a representation of the ID into a VarInt
/// * Encoding the length of the ID and data into a VarInt
/// * Creating a Vec to store that metadata along with the data
fn build_packet(data: Vec<u8>, id: u32) -> Vec<u8> {
    let id = encode_varint(id);
    let len = encode_varint((data.len() + id.len()) as u32);

    // We know the exact size of the packet, so allocate exactly that.
    let mut packet = Vec::with_capacity(id.len() + len.len() + data.len());

    packet.extend(len);
    packet.extend(id);
    packet.extend(data);

    packet
}

/// Build a handshake packet by adding:
/// * Magic data
/// * Host length as a VarInt, the host, and the port
/// * Next state of status
fn build_handshake(host: &str, port: u16) -> Vec<u8> {
    // Default capacity calculated by expected values.
    // Explanation commented on each item as they are added.
    let mut data = Vec::with_capacity(5 + host.len());

    data.extend(encode_varint(0x47)); // 1 byte
    data.extend(encode_varint(host.len() as u32)); // probably 1 byte
    data.extend(host.as_bytes()); // `host.len()` bytes
    data.extend(&port.to_be_bytes()); // 2 bytes
    data.extend(encode_varint(1)); // 1 byte

    data
}

/// Resolve the Minecraft SRV record for a given host.
///
/// Looks up `_minecraft._tcp.` prepended to the given host.
/// On successful result, returns the data as a string in the
/// `host:port` format.
#[tracing::instrument]
async fn resolve_srv(host: &str) -> Option<String> {
    let resolver = trust_dns_resolver::TokioAsyncResolver::tokio(
        trust_dns_resolver::config::ResolverConfig::default(),
        trust_dns_resolver::config::ResolverOpts::default(),
    )
    .await
    .ok()?; // Discard any errors, assume it couldn't be resolved.

    let name = format!("_minecraft._tcp.{}", host);
    let lookup = resolver.srv_lookup(name).await;

    tracing::debug!("host srv resolved to {:?}", lookup);

    match lookup {
        Err(_err) => None,
        Ok(lookup) => lookup
            .iter()
            .next()
            // Need to convert the SRV record into a common format
            // so it can later be used by ToSocketAddrs.
            .map(|item| format!("{}:{}", item.target(), item.port())),
    }
}

/// Server version info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Version {
    pub name: String,
    pub protocol: u32,
}

/// A player on the server and their ID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlayerSample {
    pub name: String,
    pub id: String,
}

/// Info about players on a server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Players {
    pub max: u32,
    pub online: u32,
    /// A subset of the players on the server.
    pub sample: Option<Vec<PlayerSample>>,
}

/// All info returned from a ping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ping {
    pub version: Version,
    pub players: Players,
    /// The description is arbitrary JSON data that may
    /// be parsed to get colors, etc.
    pub description: serde_json::Value,
    pub favicon: Option<String>,
}

impl Ping {
    /// Extract all text fields from the server description.
    /// Useful for environments that may only display plain text.
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

/// An error response.
#[derive(Debug)]
pub struct Error {
    /// If the server was unable to be resolved or connected to.
    pub bad_server: bool,
    /// A message explaining the error. May be from this library
    /// or underlying libraries.
    pub message: String,

    /// Keep the underlying error, if it exists.
    inner: Option<Box<dyn std::error::Error>>,
}

impl Into<Option<Box<dyn std::error::Error>>> for Error {
    fn into(self) -> Option<Box<dyn std::error::Error>> {
        self.inner
    }
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
            inner: Some(Box::new(error)),
        }
    }
}

impl From<std::string::FromUtf8Error> for Error {
    fn from(error: std::string::FromUtf8Error) -> Self {
        Self {
            message: error.to_string(),
            bad_server: false,
            inner: Some(Box::new(error)),
        }
    }
}

impl From<serde_json::error::Error> for Error {
    fn from(error: serde_json::error::Error) -> Self {
        Self {
            message: error.to_string(),
            bad_server: false,
            inner: Some(Box::new(error)),
        }
    }
}

impl From<std::num::ParseIntError> for Error {
    fn from(error: std::num::ParseIntError) -> Self {
        Self {
            message: error.to_string(),
            bad_server: false,
            inner: Some(Box::new(error)),
        }
    }
}

/// Resolve a host and port into a SocketAddr.
///
/// Unlike resolving SRV records, no result is an error
/// as it means that the provided data cannot be connected to.
#[tracing::instrument]
async fn resolve(host: &str, port: u16) -> Result<std::net::SocketAddr, Error> {
    // Start by looking up SRV record.
    if let Some(addr) = resolve_srv(&host).await {
        // Try looking up this SRV record.
        let mut addr = lookup_host(addr).await?;

        // Return the SocketAddr from the SRV, or generate an Error.
        return addr.next().ok_or_else(|| Error {
            message: "unable to resolve".to_string(),
            bad_server: true,
            inner: None,
        });
    }

    // Attempt to resolve the host, before checking for SRV records.
    let mut addr = lookup_host(format!("{}:{}", host, port)).await?;

    // If we got an address, we're done and it can be returned.
    if let Some(addr) = addr.next() {
        tracing::debug!("host resolved to {:?}", addr);
        return Ok(addr);
    }

    // There's nothing left we can do, given combination does not work.
    Err(Error {
        message: "unable to resolve".to_string(),
        bad_server: true,
        inner: None,
    })
}

/// Attempt to send a ping to a server.
///
/// Both server offline errors and resolution errors will be returned  as an
/// error. If the `bad_server` field in error is true it means that it is a
/// resolution or other failure. If it is false, the error was caused by not
/// being able to communicate with the server.
///
/// In order to avoid resource exhaustion it is advisable to wrap this in
/// a timeout as none are implemented within the library.
#[tracing::instrument]
pub async fn send_ping(host: &str, port: u16) -> Result<Ping, Error> {
    // Resolve our host and port to a SocketAddr,
    // then open a TCP connection.
    let addr = resolve(host, port).await?;
    let mut stream = TcpStream::connect(&addr).await?;

    // Create a handshake and write it.
    let handshake = build_packet(build_handshake(&host, port), 0x00);
    stream.write_all(&handshake).await?;

    // Send a request packet.
    let request = build_packet(vec![], 0x00);
    stream.write_all(&request).await?;

    // Read the packet ID length and packet ID, discard values.
    // We do not care about what they were.
    let _packet_length = read_varint(&mut stream).await?;
    let _packet_id = read_varint(&mut stream).await?;

    // Read the data length then read that much data into a vec.
    let string_len = read_varint(&mut stream).await? as usize;
    let mut data: Vec<u8> = vec![0; string_len];
    stream.read_exact(&mut data).await?;

    // Attempt to parse the data into a UTF8 string and deserialize its
    // JSON contents.
    let s = String::from_utf8(data)?;
    let ping: Ping = serde_json::from_str(&s)?;

    Ok(ping)
}

/// Parse plugins from an optional string.
fn parse_plugins(plugins: Option<String>) -> (String, Vec<String>) {
    // Ensure that we have plugins to parse. If not, return empty data.
    let plugins = match plugins {
        None => return ("".to_string(), vec![]),
        Some(plugins) => plugins,
    };

    // Plugin data is provided in a format like this:
    // `server_name: plugin1; plugin2`
    // Start by splitting off the server name.
    let mut parts = plugins.split(": ");

    // We always have a first part given that we had a string.
    let server_mod_name = parts.next().unwrap();

    // If we have another match, attempt to parse plugins.
    let plugins: Vec<String> = match parts.next() {
        Some(plugins) => plugins
            .split("; ")
            .map(|plugin| plugin.to_string())
            .collect(),
        None => vec![],
    };

    (server_mod_name.to_string(), plugins)
}

/// Info from a server query.
#[derive(Debug, Serialize)]
pub struct Query {
    pub hostname: String,
    pub gametype: String,
    pub game_id: String,
    pub version: String,
    /// Server mod name and plugins, may be empty.
    pub plugins: (String, Vec<String>),
    pub map: String,
    pub numplayers: usize,
    pub maxplayers: usize,
    pub hostport: u16,
    pub hostip: String,
    pub players: Vec<String>,
}

/// Read data from an AsyncRead until a null byte is received, then convert data
/// into a string lossily.
///
/// If no data was received before a null byte, it returns none. If an error
/// occurs while reading, it discards the data and returns none.
async fn string_until_zero<T>(reader: &mut T) -> Option<String>
where
    T: AsyncRead + Unpin,
{
    let mut items: Vec<u8> = vec![];

    let mut buf = [0; 1];
    loop {
        if reader.read_exact(&mut buf).await.is_err() {
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

/// A variant of [string_until_zero] used for reading key value pairs.
///
/// It reads until a null byte, then asserts that string is equal to `expected`.
/// If it is, it reads the next value and returns that. If not, returns none.
async fn string_until_zero_expected<T>(mut reader: &mut T, expected: &str) -> Option<String>
where
    T: AsyncRead + Unpin,
{
    let key = string_until_zero(&mut reader).await?;

    if key != expected {
        return None;
    }

    string_until_zero(&mut reader).await
}

/// Extract a list of players from an AsyncRead.
///
/// `ignore_garbage` is used to ignore the padding bytes between previous data
/// and the list of players.
async fn parse_players<T>(mut reader: &mut T, ignore_garbage: bool) -> Vec<String>
where
    T: AsyncRead + Unpin,
{
    let mut players = vec![];

    // 10 bytes of padding to ignore if desired.
    if ignore_garbage {
        // TODO: maybe assert that this is the expected padding?
        // 01 70 6C 61 79 65 72 5F 00 00
        let mut _garbage = vec![0; 10];
        let _err = reader.read_exact(&mut _garbage).await;
    }

    // Keep reading strings until there's nothing left. Each string is a
    // player's username.
    while let Some(player) = string_until_zero(&mut reader).await {
        players.push(player);
    }

    players
}

/// Send a query to a server and get the response.
///
/// See [send_ping] for more information about timeouts and errors.
///
/// If data was missing, it is possible for fields to have empty values.
pub async fn send_query(host: &str, port: u16) -> Result<Query, Error> {
    // Resolve our host and port to a SocketAddr, bind a socket,
    // and open a UDP connection to the host.
    let addr = resolve(host, port).await?;
    let mut socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect(addr).await?;

    // Generate and send a random session ID for our packet.
    let session_id = rand::random::<u32>() & 0x0F0F_0F0F;
    let mut request = vec![0xFE, 0xFD, 0x09];
    request.extend(&session_id.to_be_bytes());
    socket.send(&request).await?;

    // Receive up to 2KiB from connection.
    let mut buf: Vec<u8> = vec![0; 2048];
    let len = socket.recv(&mut buf).await?;

    // Get the challenge token from the response.
    let challenge_token: i32 = String::from_utf8_lossy(&buf[5..len - 1]).parse()?;

    // Create a packet with our session ID and magic to generate a response.
    let mut request = vec![0xFE, 0xFD, 0x00];
    request.extend(&session_id.to_be_bytes());
    request.extend(&challenge_token.to_be_bytes());
    request.extend(vec![0x00, 0x00, 0x00, 0x00]);
    socket.send(&request).await?;

    // Receive data
    // TODO: do we need handling for packets larger than 2KiB?
    let len = socket.recv(&mut buf).await?;
    // Ignore type, session ID, and padding before trying to parse data.
    let mut cursor = std::io::Cursor::new(&buf[16..len - 1]);

    // TODO: find a cleaner way of doing this
    Ok(Query {
        hostname: string_until_zero_expected(&mut cursor, "hostname")
            .await
            .unwrap_or_else(String::new),
        gametype: string_until_zero_expected(&mut cursor, "gametype")
            .await
            .unwrap_or_else(String::new),
        game_id: string_until_zero_expected(&mut cursor, "game_id")
            .await
            .unwrap_or_else(String::new),
        version: string_until_zero_expected(&mut cursor, "version")
            .await
            .unwrap_or_else(String::new),
        plugins: parse_plugins(string_until_zero_expected(&mut cursor, "plugins").await),
        map: string_until_zero_expected(&mut cursor, "map")
            .await
            .unwrap_or_else(String::new),
        numplayers: string_until_zero_expected(&mut cursor, "numplayers")
            .await
            .unwrap()
            .parse()
            .unwrap_or(0),
        maxplayers: string_until_zero_expected(&mut cursor, "maxplayers")
            .await
            .unwrap()
            .parse()
            .unwrap_or(0),
        hostport: string_until_zero_expected(&mut cursor, "hostport")
            .await
            .unwrap()
            .parse()
            .unwrap_or(0),
        hostip: string_until_zero_expected(&mut cursor, "hostip")
            .await
            .unwrap_or_else(String::new),
        players: parse_players(&mut cursor, true).await,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[tokio::test]
    async fn test_read_varint() {
        let src: Vec<u8> = vec![0x00];
        assert_eq!(0, read_varint(&mut src.as_slice()).await.unwrap());

        let src: Vec<u8> = vec![0x01];
        assert_eq!(1, read_varint(&mut src.as_slice()).await.unwrap());

        let src: Vec<u8> = vec![0xFF, 0x01];
        assert_eq!(255, read_varint(&mut src.as_slice()).await.unwrap());

        let src: Vec<u8> = vec![0b1000_0100, 0b0100_0000];
        assert_eq!(8196, read_varint(&mut src.as_slice()).await.unwrap());

        let src: Vec<u8> = vec![0xFF, 0xFF, 0xFF, 0xFF, 0x07];
        assert_eq!(
            2_147_483_647,
            read_varint(&mut src.as_slice()).await.unwrap()
        );
    }

    #[test]
    fn test_build_packet() {
        let packet = build_packet(vec![], 0x00);
        assert_eq!(packet, vec![0x01, 0x00]);

        let packet = build_packet(vec![0x00], 0x00);
        assert_eq!(packet, vec![0x02, 0x00, 0x00]);
    }

    #[tokio::test]
    async fn test_resolve_srv() {
        let host = match resolve_srv("ping.minecraft.syfaro.net").await {
            Some(resolved) => resolved,
            None => {
                assert!(false, "should be able to resolve srv record");
                return;
            }
        };

        assert_eq!(host, "play.gotpvp.com.:25565");
    }

    #[tokio::test]
    async fn test_string_until_zero() {
        let mut cursor = std::io::Cursor::new(vec![102, 111, 120, 0, 104, 105, 0]);

        let msg = string_until_zero(&mut cursor).await;

        assert!(!msg.is_none());
        assert_eq!(msg.unwrap(), "fox");

        let msg = string_until_zero(&mut cursor).await;

        assert!(!msg.is_none());
        assert_eq!(msg.unwrap(), "hi");

        let msg = string_until_zero(&mut cursor).await;

        assert!(msg.is_none());
    }

    #[tokio::test]
    async fn test_string_until_zero_expected() {
        let mut cursor = std::io::Cursor::new(vec![107, 0, 118, 0]);

        let msg = string_until_zero_expected(&mut cursor, "k").await;

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

    #[tokio::test]
    async fn test_parse_players() {
        let mut cursor = std::io::Cursor::new(vec![97, 0, 98, 0, 99, 0, 0]);
        let players = parse_players(&mut cursor, false).await;

        assert_eq!(players, vec!["a", "b", "c"]);
    }

    #[tokio::test]
    async fn test_send_ping() {
        match send_ping("s.nerd.nu", 25565).await {
            Ok(ping) => println!("{:?}", ping),
            Err(err) => assert!(false, "should not error: {:?}", err),
        }
    }

    #[tokio::test]
    async fn test_send_query() {
        match send_query("minescape.me", 25565).await {
            Ok(query) => println!("{:?}", query),
            Err(err) => assert!(false, "should not error: {:?}", err),
        }
    }
}
