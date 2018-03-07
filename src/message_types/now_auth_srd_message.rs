use std;

pub trait NowAuthSrdMessage {
    fn read_from(buffer: &[u8]) -> Result<Self, std::io::Error>
    where
        Self: Sized;
    fn write_to(&self, buffer: &mut Vec<u8>) -> Result<(), std::io::Error>;
    fn get_size(&self) -> u32;
    fn get_id(&self) -> u16;
}