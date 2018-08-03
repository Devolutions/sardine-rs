use messages::*;
use srd_errors::SrdError;
use std::io::{Read, Write};
use Result;

pub trait Message {
    fn read_from<R: Read>(reader: &mut R) -> Result<Self>
        where
            Self: Sized;
    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()>;
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SrdMessage {
    Initiate(SrdHeader, SrdInitiate),
    Offer(SrdHeader, SrdOffer),
    Accept(SrdHeader, SrdAccept),
    Confirm(SrdHeader, SrdConfirm),
    Delegate(SrdHeader, SrdDelegate),
}

impl SrdMessage {
    #[allow(dead_code)]
    pub fn msg_type(&self) -> u8 {
        match self {
            SrdMessage::Initiate(hdr, _) => hdr.msg_type(),
            SrdMessage::Offer(hdr, _) => hdr.msg_type(),
            SrdMessage::Accept(hdr, _) => hdr.msg_type(),
            SrdMessage::Confirm(hdr, _) => hdr.msg_type(),
            SrdMessage::Delegate(hdr, _) => hdr.msg_type(),
        }
    }

    pub fn signature(&self) -> u32 {
        match self {
            SrdMessage::Initiate(hdr, _) => hdr.signature(),
            SrdMessage::Offer(hdr, _) => hdr.signature(),
            SrdMessage::Accept(hdr, _) => hdr.signature(),
            SrdMessage::Confirm(hdr, _) => hdr.signature(),
            SrdMessage::Delegate(hdr, _) => hdr.signature(),
        }
    }

    pub fn seq_num(&self) -> u8 {
        match self {
            SrdMessage::Initiate(hdr, _) => hdr.seq_num(),
            SrdMessage::Offer(hdr, _) => hdr.seq_num(),
            SrdMessage::Accept(hdr, _) => hdr.seq_num(),
            SrdMessage::Confirm(hdr, _) => hdr.seq_num(),
            SrdMessage::Delegate(hdr, _) => hdr.seq_num(),
        }
    }

    pub fn has_cbt(&self) -> bool {
        match self {
            SrdMessage::Initiate(hdr, _) => hdr.has_cbt(),
            SrdMessage::Offer(hdr, _) => hdr.has_cbt(),
            SrdMessage::Accept(hdr, _) => hdr.has_cbt(),
            SrdMessage::Confirm(hdr, _) => hdr.has_cbt(),
            SrdMessage::Delegate(hdr, _) => hdr.has_cbt(),
        }
    }

    pub fn has_mac(&self) -> bool {
        match self {
            SrdMessage::Initiate(hdr, _) => hdr.has_mac(),
            SrdMessage::Offer(hdr, _) => hdr.has_mac(),
            SrdMessage::Accept(hdr, _) => hdr.has_mac(),
            SrdMessage::Confirm(hdr, _) => hdr.has_mac(),
            SrdMessage::Delegate(hdr, _) => hdr.has_mac(),
        }
    }

    pub fn mac(&self) -> Option<&[u8]> {
        match self {
            SrdMessage::Initiate(_, _) => None,
            SrdMessage::Offer(_, _) => None,
            SrdMessage::Accept(_, accept) => Some(accept.mac()),
            SrdMessage::Confirm(_, confirm) => Some(confirm.mac()),
            SrdMessage::Delegate(_, delegate) => Some(delegate.mac()),
        }
    }

    pub fn set_mac(&mut self, mac: &[u8]) -> Result<()> {
        match self {
            SrdMessage::Initiate(_, _) => Err(SrdError::Proto("No mac on an initiate message".to_owned())),
            SrdMessage::Offer(_, _) => Err(SrdError::Proto("No mac on an offer message".to_owned())),
            SrdMessage::Accept(_, ref mut accept) => Ok(accept.set_mac(mac)),
            SrdMessage::Confirm(_, ref mut confirm) => Ok(confirm.set_mac(mac)),
            SrdMessage::Delegate(_, ref mut delegate) => Ok(delegate.set_mac(mac)),
        }
    }

    pub fn validate(self) -> Result<Self> {
        match &self {
            SrdMessage::Initiate(hdr, initiate) => {
                // No MAC in that message
                hdr.validate_flags(false)?;

                // Key size supported : 256, 512 or 1024
                match initiate.key_size() {
                    256 | 512 | 1024 => {}
                    _ => return Err(SrdError::InvalidKeySize),
                }
            }

            SrdMessage::Offer(hdr, _offer) => {
                // No MAC in that message
                hdr.validate_flags(false)?;
            }

            SrdMessage::Accept(hdr, _accept) => {
                // MAC has to be set
                hdr.validate_flags(true)?;
            }

            SrdMessage::Confirm(hdr, _confirm) => {
                // MAC has to be set
                hdr.validate_flags(true)?;
            }

            SrdMessage::Delegate(hdr, _delegate) => {
                // MAC has to be set
                hdr.validate_flags(true)?;
            }
        }
        Ok(self)
    }
}

impl Message for SrdMessage {
    fn read_from<R: Read>(mut reader: &mut R) -> Result<Self>
        where
            Self: Sized,
    {
        let header = SrdHeader::read_from(&mut reader)?;
        match header.msg_type() {
            srd_msg_id::SRD_INITIATE_MSG_ID => {
                let initiate = SrdInitiate::read_from(&mut reader)?;
                Ok(SrdMessage::Initiate(header, initiate).validate()?)
            }
            srd_msg_id::SRD_OFFER_MSG_ID => {
                let offer = SrdOffer::read_from(&mut reader)?;
                Ok(SrdMessage::Offer(header, offer).validate()?)
            }
            srd_msg_id::SRD_ACCEPT_MSG_ID => {
                let accept = SrdAccept::read_from(&mut reader)?;
                Ok(SrdMessage::Accept(header, accept).validate()?)
            }
            srd_msg_id::SRD_CONFIRM_MSG_ID => {
                let confirm = SrdConfirm::read_from(&mut reader)?;
                Ok(SrdMessage::Confirm(header, confirm).validate()?)
            }
            srd_msg_id::SRD_DELEGATE_MSG_ID => {
                let delegate = SrdDelegate::read_from(&mut reader)?;
                Ok(SrdMessage::Delegate(header, delegate).validate()?)
            }
            _ => Err(SrdError::UnknownMsgType),
        }
    }

    fn write_to<W: Write>(&self, mut writer: &mut W) -> Result<()> {
        match self {
            SrdMessage::Initiate(hdr, initiate) => {
                hdr.write_to(&mut writer)?;
                initiate.write_to(&mut writer)?;
                Ok(())
            }
            SrdMessage::Offer(hdr, offer) => {
                hdr.write_to(&mut writer)?;
                offer.write_to(&mut writer)?;
                Ok(())
            }
            SrdMessage::Accept(hdr, accept) => {
                hdr.write_to(&mut writer)?;
                accept.write_to(&mut writer)?;
                Ok(())
            }
            SrdMessage::Confirm(hdr, confirm) => {
                hdr.write_to(&mut writer)?;
                confirm.write_to(&mut writer)?;
                Ok(())
            }
            SrdMessage::Delegate(hdr, delegate) => {
                hdr.write_to(&mut writer)?;
                delegate.write_to(&mut writer)?;
                Ok(())
            }
        }
    }
}

pub trait ReadMac {
    fn read_mac(&mut self, mac: &mut [u8]) -> Result<()>;
}

//impl<'a> ReadMac for std::io::Cursor<&'a [u8]> {
//    fn read_mac(&mut self, mut mac: &mut [u8]) -> Result<()> {
//
//        // The MAC field is a footer: it is ALWAYS at the very end of the message
//        let mac_position = match (self.get_ref().len() as u64).checked_sub(mac.len() as u64) {
//            Some(mac_position) if mac_position >= self.position() => mac_position,
//            _ => {
//                // Either the buffer is not long enough or not enough data is available to read.
//                return Err(SrdError::InvalidDataLength);
//            }
//        };
//        self.set_position(mac_position);
//        self.read_exact(&mut mac)?;
//        Ok(())
//    }
//}

impl<T: Read> ReadMac for T {
    fn read_mac(&mut self, mac: &mut [u8]) -> Result<()> {
        let mut v = Vec::new();
        self.read_to_end(&mut v)?;

        if v.len() >= mac.len() {
            let len_to_remove = v.len() - mac.len();
            mac.copy_from_slice(&v.split_off(len_to_remove));
            Ok(())
        } else {
            Err(SrdError::InvalidDataLength)
        }
    }
}
