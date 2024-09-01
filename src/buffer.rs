use crate::DnsError;

pub struct PacketBuffer {
    pub buffer: [u8; 512],
    pub position: usize,
}

impl PacketBuffer {
    pub fn new() -> PacketBuffer {
        PacketBuffer {
            buffer: [0; 512],
            position: 0,
        }
    }

    pub fn position(&self) -> usize {
        self.position
    }

    pub fn step(&mut self, steps: usize) -> crate::Result<()> {
        self.position += steps;

        Ok(())
    }

    pub fn seek(&mut self, pos: usize) -> crate::Result<()> {
        self.position = pos;

        Ok(())
    }

    pub fn read(&mut self) -> crate::Result<u8> {
        if self.position >= 512 {
            return Err(DnsError::BufferEnd);
        }
        let response = self.buffer[self.position];
        self.position += 1;

        Ok(response)
    }

    pub fn get(&mut self, position: usize) -> crate::Result<u8> {
        if position >= 512 {
            return Err(DnsError::BufferEnd);
        }
        Ok(self.buffer[position])
    }

    pub fn get_range(&mut self, start: usize, length: usize) -> crate::Result<&[u8]> {
        if start + length >= 512 {
            return Err(DnsError::BufferEnd);
        }
        Ok(&self.buffer[start..start + length as usize])
    }

    pub fn read_u16(&mut self) -> crate::Result<u16> {
        let result = ((self.read()? as u16) << 8) | (self.read()? as u16);

        Ok(result)
    }

    pub fn read_u32(&mut self) -> crate::Result<u32> {
        let res = ((self.read()? as u32) << 24)
            | ((self.read()? as u32) << 16)
            | ((self.read()? as u32) << 8)
            | ((self.read()? as u32) << 0);

        Ok(res)
    }

    pub fn read_qname(&mut self, outstr: &mut String) -> crate::Result<()> {
        let mut position = self.position();
        let mut jumped = false;

        let mut delimiter = "";
        let max_jumps = 5;
        let mut jumps_performed = 0;
        loop {
            // Prevent from a cycle of jumps
            if jumps_performed > max_jumps {
                return Err(DnsError::MaxJumps(max_jumps));
            }

            let length = self.get(position)?;

            // A two byte sequence, where the two highest bits of the first byte is
            // set, represents a offset relative to the start of the buffer. We
            // handle this by jumping to the offset, setting a flag to indicate
            // that we shouldn't update the shared buffer position once done.
            if (length & 0xC0) == 0xC0 {
                // When a jump is performed, we only modify the shared buffer
                // position once, and avoid making the change later on.
                if !jumped {
                    self.seek(position + 2)?;
                }

                let b2 = self.get(position + 1)? as u16;
                let offset = (((length as u16) ^ 0xC0) << 8) | b2;
                position = offset as usize;
                jumped = true;
                jumps_performed += 1;
                continue;
            }

            position += 1;

            // Names are terminated by an empty label of length 0
            if length == 0 {
                break;
            }

            outstr.push_str(delimiter);

            let str_buffer = self.get_range(position, length as usize)?;
            outstr.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());

            delimiter = ".";

            position += length as usize;
        }

        if !jumped {
            self.seek(position)?;
        }

        Ok(())
    }

    pub fn write(&mut self, value: u8) -> crate::Result<()> {
        if self.position >= 512 {
            return Err(DnsError::BufferEnd);
        }
        self.buffer[self.position] = value;
        self.position += 1;
        Ok(())
    }

    pub fn write_u8(&mut self, value: u8) -> crate::Result<()> {
        self.write(value)?;

        Ok(())
    }

    pub fn write_u16(&mut self, value: u16) -> crate::Result<()> {
        self.write((value >> 8) as u8)?;
        self.write((value & 0xFF) as u8)?;

        Ok(())
    }

    pub fn write_u32(&mut self, value: u32) -> crate::Result<()> {
        self.write(((value >> 24) & 0xFF) as u8)?;
        self.write(((value >> 16) & 0xFF) as u8)?;
        self.write(((value >> 8) & 0xFF) as u8)?;
        self.write(((value >> 0) & 0xFF) as u8)?;

        Ok(())
    }

    pub fn write_qname(&mut self, qname: &str) -> crate::Result<()> {
        for label in qname.split('.') {
            let length = label.len();
            if length > 0x34 {
                return Err(DnsError::LabelExceedsMaxLengthSize);
            }

            self.write_u8(length as u8)?;
            for byte in label.as_bytes() {
                self.write_u8(*byte)?;
            }
        }

        self.write_u8(0)?;

        Ok(())
    }
}
