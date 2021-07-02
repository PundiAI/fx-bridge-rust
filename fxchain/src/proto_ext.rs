use eyre::Result;
use prost::{DecodeError, Message};
use prost_types::Any;

pub trait MessageExt: Message {
    fn to_bytes(&self) -> Result<Vec<u8>>;
    fn to_any(&self, type_url: &str) -> Any;
}

impl<M: Message> MessageExt for M {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        Message::encode(self, &mut bytes)?;
        Ok(bytes)
    }

    fn to_any(&self, type_url: &str) -> Any {
        let mut buf = Vec::new();
        buf.reserve(self.encoded_len());
        self.encode(&mut buf).unwrap();
        Any {
            type_url: type_url.to_string(),
            value: buf,
        }
    }
}

pub fn unpack_any<T: Message>(any: Any, mut target: T) -> Result<T, DecodeError> {
    trace!("Unpack any type url '{}'", any.type_url);
    let instance = target.merge(any.value.as_slice()).map(|_| target)?;
    Ok(instance)
}
