use std;
use Result;

pub trait SrdMessage {
    fn read_from(buffer: &mut std::io::Cursor<Vec<u8>>) -> Result<Self>
    where
        Self: Sized;
    fn write_to(&self, buffer: &mut Vec<u8>) -> Result<()>;
    fn get_id(&self) -> u8;
}
