use anyhow::anyhow;
use byteorder::{LittleEndian, WriteBytesExt};
use nom::{
    bytes::complete::{take, take_until},
    error::{make_error, ErrorKind},
    number::complete::le_u32,
    Finish, IResult,
};
use std::{io::Write, str::from_utf8};

// Implementation of ConnectionHeader is based off of ROS documentation here:
// wiki.ros.org/ROS/Connection%20Header
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ConnectionHeader {
    pub caller_id: String,
    pub latching: bool,
    pub msg_definition: String,
    pub md5sum: String,
    pub topic: String,
    pub topic_type: String,
    pub tcp_nodelay: bool,
}

impl ConnectionHeader {
    pub fn from_bytes(header_data: &[u8]) -> std::io::Result<ConnectionHeader> {
        Self::parse(header_data)
            .finish()
            .map(|(_, h)| h)
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    anyhow!("{:?}, {:?}", e.code, e.input),
                )
            })
    }

    fn parse_header_field(input: &[u8]) -> IResult<&[u8], (&str, &str)> {
        let (input, len) = le_u32(input)?;
        let (input, field_name) = take_until("=")(input)?;
        let (input, _eq) = take(1usize)(input)?;
        let Some(remaining_len) = len.checked_sub(field_name.len() as u32 + 1) else {
            log::warn!("Underflow in header bytes, nothing remaining after =");
            return Err(nom::Err::Error(make_error(input, ErrorKind::LengthValue)));
        };
        let (input, value) = take(remaining_len)(input)?;
        let Ok(field_name) = from_utf8(field_name) else {
            log::warn!(
                "Header Field name {} (lossy) is invalid UTF8",
                String::from_utf8_lossy(field_name)
            );
            return Err(nom::Err::Error(make_error(input, ErrorKind::AlphaNumeric)));
        };

        let Ok(value) = from_utf8(value) else {
            log::warn!(
                "Header Value {} (lossy) is invalid UTF8",
                String::from_utf8_lossy(value)
            );
            return Err(nom::Err::Error(make_error(input, ErrorKind::AlphaNumeric)));
        };
        Ok((input, (field_name, value)))
    }

    fn parse(input: &[u8]) -> IResult<&[u8], ConnectionHeader> {
        let (mut input, mut len) = le_u32(input)?;

        let mut header = ConnectionHeader::default();

        while len > 0 {
            let input_len = input.len();
            let (shorter_input, (key, value)) = Self::parse_header_field(input)?;
            let value = value.to_string();
            match key {
                "callerid" => header.caller_id = value,
                "message_definition" => header.msg_definition = value,
                "md5sum" => header.md5sum = value,
                "topic" => header.topic = value,
                "type" => header.topic_type = value,
                "latching" => header.latching = value != "0",
                "tcp_nodelay" => header.tcp_nodelay = value != "0",
                _ => log::warn!("Unknown ros header field with name {} encountered", key),
            };
            let diff = input_len - shorter_input.len();
            let Some(shorter) = len.checked_sub(diff as u32) else {
                log::warn!("Underflow in header bytes, too many bytes read");
                return Err(nom::Err::Error(make_error(input, ErrorKind::Count)));
            };
            len = shorter;
            input = shorter_input;
        }
        Ok((input, header))
    }

    pub fn to_bytes(&self, to_publisher: bool) -> std::io::Result<Vec<u8>> {
        let mut header_data = Vec::with_capacity(1024);
        // Start by skipping the length header since we don't know yet
        header_data.write_u32::<LittleEndian>(0)?;

        let caller_id_str = format!("callerid={}", self.caller_id);
        header_data.write_u32::<LittleEndian>(caller_id_str.len() as u32)?;
        header_data.write(caller_id_str.as_bytes())?;

        let latching_str = format!("latching={}", if self.latching { 1 } else { 0 });
        header_data.write_u32::<LittleEndian>(latching_str.len() as u32)?;
        header_data.write(latching_str.as_bytes())?;

        let md5sum = format!("md5sum={}", self.md5sum);
        header_data.write_u32::<LittleEndian>(md5sum.len() as u32)?;
        header_data.write(md5sum.as_bytes())?;

        let msg_definition = format!("message_definition={}", self.msg_definition);
        header_data.write_u32::<LittleEndian>(msg_definition.len() as u32)?;
        header_data.write(msg_definition.as_bytes())?;

        if to_publisher {
            let tcp_nodelay = format!("tcp_nodelay={}", if self.tcp_nodelay { 1 } else { 0 });
            header_data.write_u32::<LittleEndian>(tcp_nodelay.len() as u32)?;
            header_data.write(tcp_nodelay.as_bytes())?;
        }

        let topic = format!("topic={}", self.topic);
        header_data.write_u32::<LittleEndian>(topic.len() as u32)?;
        header_data.write(topic.as_bytes())?;

        let topic_type = format!("type={}", self.topic_type);
        header_data.write_u32::<LittleEndian>(topic_type.len() as u32)?;
        header_data.write(topic_type.as_bytes())?;

        let total_length = (header_data.len() - 4) as u32;
        for (idx, byte) in total_length.to_le_bytes().iter().enumerate() {
            header_data[idx] = *byte;
        }

        Ok(header_data)
    }
}

#[cfg(test)]
mod test {
    use super::ConnectionHeader;

    #[test]
    fn test_header_parse() {
        let valid_header: [u8; 180] = [
            0xb0, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67,
            0x65, 0x5f, 0x64, 0x65, 0x66, 0x69, 0x6e, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x3d, 0x73,
            0x74, 0x72, 0x69, 0x6e, 0x67, 0x20, 0x64, 0x61, 0x74, 0x61, 0x0a, 0x0a, 0x25, 0x00,
            0x00, 0x00, 0x63, 0x61, 0x6c, 0x6c, 0x65, 0x72, 0x69, 0x64, 0x3d, 0x2f, 0x72, 0x6f,
            0x73, 0x74, 0x6f, 0x70, 0x69, 0x63, 0x5f, 0x34, 0x37, 0x36, 0x37, 0x5f, 0x31, 0x33,
            0x31, 0x36, 0x39, 0x31, 0x32, 0x37, 0x34, 0x31, 0x35, 0x35, 0x37, 0x0a, 0x00, 0x00,
            0x00, 0x6c, 0x61, 0x74, 0x63, 0x68, 0x69, 0x6e, 0x67, 0x3d, 0x31, 0x27, 0x00, 0x00,
            0x00, 0x6d, 0x64, 0x35, 0x73, 0x75, 0x6d, 0x3d, 0x39, 0x39, 0x32, 0x63, 0x65, 0x38,
            0x61, 0x31, 0x36, 0x38, 0x37, 0x63, 0x65, 0x63, 0x38, 0x63, 0x38, 0x62, 0x64, 0x38,
            0x38, 0x33, 0x65, 0x63, 0x37, 0x33, 0x63, 0x61, 0x34, 0x31, 0x64, 0x31, 0x0e, 0x00,
            0x00, 0x00, 0x74, 0x6f, 0x70, 0x69, 0x63, 0x3d, 0x2f, 0x63, 0x68, 0x61, 0x74, 0x74,
            0x65, 0x72, 0x14, 0x00, 0x00, 0x00, 0x74, 0x79, 0x70, 0x65, 0x3d, 0x73, 0x74, 0x64,
            0x5f, 0x6d, 0x73, 0x67, 0x73, 0x2f, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67,
        ];

        let parsed = ConnectionHeader::from_bytes(&valid_header).unwrap();
        let model = ConnectionHeader {
            caller_id: String::from("/rostopic_4767_1316912741557"),
            latching: true,
            msg_definition: String::from("string data\n\n"),
            md5sum: String::from("992ce8a1687cec8c8bd883ec73ca41d1"),
            topic: String::from("/chatter"),
            topic_type: String::from("std_msgs/String"),
            tcp_nodelay: false,
        };

        assert_eq!(parsed, model);
    }

    #[test]
    fn test_header_read_write() {
        let model_1 = ConnectionHeader {
            caller_id: String::from("/rostopic_4861_131237898261"),
            latching: true,
            msg_definition: String::from("garbage data\n\n"),
            md5sum: String::from("992ce8a1687cec8c8bd883ec8862bbf3"),
            topic: String::from("/ros"),
            topic_type: String::from("std_msgs/String"),
            tcp_nodelay: true,
        };

        let bytes = model_1.to_bytes(true).unwrap();
        let parsed_1 = ConnectionHeader::from_bytes(&bytes).unwrap();
        assert_eq!(model_1, parsed_1);

        let bytes = model_1.to_bytes(false).unwrap();
        let model_2 = ConnectionHeader {
            tcp_nodelay: false,
            ..model_1
        };

        let parsed_2 = ConnectionHeader::from_bytes(&bytes).unwrap();

        assert_eq!(model_2, parsed_2);
    }
}
