use std::io;
use std::io::{Write};

pub struct PcapWriter<W: Write> {
    writer: W,
}

pub enum LinkType {
    Raw = 101,
}

const MAJOR: u16 = 2;
const MINOR: u16 = 4;

impl<W: Write> PcapWriter<W> {
    fn write_header(&mut self, link_type: LinkType) -> io::Result<()> {
        // Write pcap header
        self.writer.write_all(&0xa1b2c3d4u32.to_be_bytes())?; // Magic byte
        self.writer.write_all(&MAJOR.to_be_bytes())?; // Major version
        self.writer.write_all(&MINOR.to_be_bytes())?; // Minor version
        self.writer.write_all(&[0u8; 4])?; // Reserved1
        self.writer.write_all(&[0u8; 4])?; // Reserved1
        self.writer.write_all(&65534u32.to_be_bytes())?; // Snaplen (biggest packet size)
        self.writer.write_all(&(link_type as u32).to_be_bytes())?; // LinkType

        Ok(())
    }

    pub fn new(
        writer: Box<dyn Write>,
        link_type: LinkType,
    ) -> io::Result<PcapWriter<Box<dyn Write>>> {
        let mut ret = PcapWriter { writer: writer };
        ret.write_header(link_type)?;
        Ok(ret)
    }

    pub fn add_packet(
        &mut self,
        timestamp_sec: u32,
        timestamp_micro: u32,
        packet: Vec<u8>,
    ) -> io::Result<()> {
        self.writer.write_all(&(timestamp_sec).to_be_bytes())?; // Timestamp (sec)
        self.writer.write_all(&(timestamp_micro).to_be_bytes())?; // Timestamp (micro)
        self.writer
            .write_all(&(packet.len() as u32).to_be_bytes())?; // Captured Packet Length
        self.writer
            .write_all(&(packet.len() as u32).to_be_bytes())?; // Original Packet Length
        self.writer.write_all(packet.as_slice())?; // Data
        Ok(())
    }
}
