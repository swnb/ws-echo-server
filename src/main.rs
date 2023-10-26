use base64::{engine::general_purpose, Engine as _};
use ring::digest;
use std::{
    collections::BTreeMap,
    error::Error,
    io::{self, BufRead, BufReader, BufWriter, Write},
    net::TcpListener,
};

fn main() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("0.0.0.0:8080")?;

    while let Ok((stream, _)) = listener.accept() {
        let mut reader = BufReader::new(&stream);
        let mut writer = BufWriter::new(&stream);
        handshake(&mut reader, &mut writer)?;
        handle_connection(&mut reader, &mut writer)?;
    }

    Ok(())
}

fn handle_connection(
    reader: &mut impl BufRead,
    writer: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    while let Ok(message) = decode_message(reader) {
        writer.write_all(&message.encode())?;
        writer.flush()?;
    }
    Ok(())
}

// 握手
fn handshake(reader: &mut impl BufRead, writer: &mut impl Write) -> Result<(), Box<dyn Error>> {
    let mut buffer = String::new();
    let size = reader.read_line(&mut buffer)?;
    // 读取 http 请求行
    let request_line: &str = &buffer[0..size];
    let _ = request_line;
    buffer.truncate(0);

    let mut headers = BTreeMap::<String, String>::new();

    loop {
        let size = reader.read_line(&mut buffer)?;
        // 读取每一个头信息
        let header_line: &str = &buffer[0..size];
        // 头信息完结
        if header_line == "\r\n" {
            break;
        }

        let header_line = &header_line[0..(size - 2)];

        if let Some((k, v)) = header_line.split_once(':') {
            headers.insert(k.to_lowercase(), v.trim_start().into());
        };

        buffer.truncate(0);
    }

    let sec_websocket_key = headers.get("sec-websocket-key").ok_or(io::Error::new(
        io::ErrorKind::ConnectionRefused,
        "no header Sec-Websocket-Key",
    ))?;

    const UUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    // sha1 加 base64
    let concat_str = [sec_websocket_key.as_bytes(), UUID].concat();
    let hash_result = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &concat_str);
    let sec_websocket_accept = general_purpose::STANDARD.encode(hash_result.as_ref());

    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
        Upgrade: websocket\r\n\
        Connection: Upgrade\r\n\
        Sec-WebSocket-Accept: {}\r\n\r\n",
        sec_websocket_accept
    );

    writer.write_all(response.as_bytes())?;

    writer.flush()?;

    Ok(())
}

enum Message {
    Text(String),
    Binary(Vec<u8>),
}

impl Message {
    fn as_bytes(&self) -> &[u8] {
        match &self {
            Message::Binary(data) => data,
            Message::Text(data) => data.as_bytes(),
        }
    }

    fn opcode(&self) -> u8 {
        match &self {
            Message::Binary(_) => 2,
            Message::Text(_) => 1,
        }
    }

    fn encode(&self) -> Vec<u8> {
        let payload_data = self.as_bytes();
        let payload_length = payload_data.len() as u64;

        // 初始的长度是 2个 字节 fin,rsv1...payload_length
        let mut total_frame_length = 2;

        if payload_length > 125 {
            // 扩展payload_length
            if payload_length > u16::MAX as u64 {
                total_frame_length += 8;
            } else {
                total_frame_length += 2;
            }
        }

        total_frame_length += payload_length;

        let mut frame: Vec<u8> = Vec::with_capacity(total_frame_length as usize);

        let opcode = self.opcode();
        frame.push(0b1000_0000); // fin 是 1
        frame[0] |= opcode;

        if payload_length <= 125 {
            frame.push(payload_length as u8);
        } else if payload_length > u16::MAX as u64 {
            frame.push(127);
            frame.extend_from_slice(&payload_length.to_be_bytes());
        } else {
            frame.push(126);
            frame.extend_from_slice(&(payload_length as u16).to_be_bytes());
        }

        // 服务端不需要 mask, 直接拼接数据
        frame.extend_from_slice(payload_data);

        frame
    }
}

fn decode_message(reader: &mut impl BufRead) -> Result<Message, Box<dyn Error>> {
    let mut buffer = [0; 2];
    // 先获取前面两个字节
    reader.read_exact(&mut buffer)?;

    // 不考虑 fin 不为 1 的情况, 一次读取一个 frame 然后拼接成 message
    let opcode = buffer[0] & 0b1111;
    let mask = buffer[1] >> 7;
    if mask != 1 {
        // 客户端发来的消息必须是掩码的
        return Err(io::Error::new(io::ErrorKind::ConnectionRefused, "mask require").into());
    }

    let mut payload_length = (buffer[1] & 0b0111_1111) as u64;

    if payload_length == 126 {
        reader.read_exact(&mut buffer)?;
        payload_length = u16::from_be_bytes(buffer) as u64;
    } else if payload_length == 127 {
        let mut buffer = [0; 8];
        reader.read_exact(&mut buffer)?;
        payload_length = u64::from_be_bytes(buffer);
    }

    let mut mask_key = [0; 4];
    reader.read_exact(&mut mask_key)?;

    let mut payload_data: Vec<u8> = vec![0; payload_length as usize];
    reader.read_exact(&mut payload_data)?;

    // 还原原始的 payload_data
    (0..payload_data.len()).for_each(|i| {
        let j = i % 4;
        let cur_mask_key = mask_key[j];
        payload_data[i] ^= cur_mask_key;
    });

    Ok(if opcode == 1 {
        Message::Text(String::from_utf8_lossy(&payload_data).to_string())
    } else {
        Message::Binary(payload_data)
    })
}
