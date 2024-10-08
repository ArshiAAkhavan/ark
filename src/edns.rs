use dns::error::ProtoError;
use dns::op::{Edns, Message, MessageType, OpCode, Query};
use dns::rr::{
    rdata::opt::{EdnsCode, EdnsOption},
    Name, RecordType,
};
use dns::serialize::binary::*;
use hickory_proto as dns;

const ARK_EDNS_OPCODE: u16 = 65001;

#[derive(Debug, thiserror::Error)]
pub enum EdnsError {
    #[error("failed to create DNS packet")]
    DnsPacketError(#[from] ProtoError),

    #[error("failed to extract raw data from EDNS field")]
    EdnsDataNotFound,
}
type EdnsResult<T> = Result<T, EdnsError>;

pub fn to_edns_packet(data: &[u8]) -> EdnsResult<Vec<u8>> {
    let mut msg = Message::new();
    msg.set_id(1)
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(true);

    let query = Query::query(Name::from_ascii("leader.ir.")?, RecordType::A);
    msg.add_query(query);

    let mut edns = Edns::new();
    edns.set_max_payload(4096);
    edns.set_version(0);

    edns.options_mut()
        .insert(EdnsOption::Unknown(ARK_EDNS_OPCODE, data.to_vec()));
    msg.set_edns(edns);

    let mut buf = Vec::new();
    let mut encoder = BinEncoder::new(&mut buf);
    msg.emit(&mut encoder)?;

    Ok(buf)
}

pub fn from_edns_packet(buf: &[u8]) -> EdnsResult<Vec<u8>> {
    let mut deserialized_msg = {
        let mut decoder = BinDecoder::new(buf);
        Message::read(&mut decoder)?
    };

    let edns = deserialized_msg
        .extensions_mut()
        .as_mut()
        .ok_or(EdnsError::EdnsDataNotFound)?;
    let opt = edns.options_mut();
    if let EdnsOption::Unknown(_, data) = opt
        .as_mut()
        .remove(&EdnsCode::Unknown(ARK_EDNS_OPCODE))
        .ok_or(EdnsError::EdnsDataNotFound)?
    {
        Ok(data)
    } else {
        Err(EdnsError::EdnsDataNotFound)
    }
}
