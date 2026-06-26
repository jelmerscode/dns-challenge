//! We need a function that decodes a DNS name that is encoded in the 'RFC1035
//! compression format' to the usual representation like "www.tweede.golf".
//!
//! A DNS name consists of parts separated by periods, e.g., the domain name
//! above has three parts: "www", "tweede", and "golf".
//!
//! In RFC1035 format, these parts are encoded by prefixing them with one byte
//! indicating the length, followed by the bytes that comprise the part. The
//! domain name itself is zero-terminated (i.e., an "empty part" signifies the
//! end of a domain name); the periods between parts are not encoded.
//!
//! So, for example, "mailcrab.tweedegolf.nl" can be encoded as:
//!
//! 0x08 mailcrab 0x0A tweedegolf 0x02 nl 0x00
//! or, in Rust's bytestring notation:
//!
//! b"\x08mailcrab\x0Atweedegolf\x02nl\0"
//!
//! There are some restrictions:
//! - The maximum size of a part is 63 bytes.
//! - The maximum size of a full domain name (including periods) is 255 bytes.
//! - A domain name cannot be empty.
//!
//! ASSIGNMENT 1: Ignore the `_backlog` argument for now, and implement this
//! functionality. The test case `simple` should now pass. This test case is
//! minimal so feel free to improve the test cases, or even add fuzzing, etc.
//!
//! Make a commit after this point.
//!
//! ---
//!
//! The RFC1035 compression format is used in the context of a larger packet
//! consisting of multiple domain names, where suffixes occur multiple times,
//! e.g. a packet could consist of "mailcrab.tweedegolf.nl",
//! "mail.tweedegolf.nl", "mattermost.tweedegolf.nl", etc.
//!
//! To avoid having to encode the same suffix multiple times, we can jump to an
//! earlier suffix in the packet.
//!
//! This is done by, in place of encoding a part, encoding a 14-bit absolute
//! index in two bytes. The first byte will have its two most significant bits
//! set to 1, followed by the 6 most significant bits of the 14-bit index. The
//! second byte will hold the 8 least significant bits of the index. Or in other
//! words, this index is encoded in big-endian format with the first byte
//! bitwise OR'ed with 0xC0.
//!
//! So for example, this set of records encodes for "tweedegolf.nl",
//! "mailcrab.tweedegolf.nl", "mail.tweedegolf.nl" and
//! "secret.mailcrab.tweedegolf.nl".
//!
//! b"\x0Atweedegolf\x02nl\0\x08mailcrab\xC0\x00\x04mail\xC0\x00\x06secret\xC0\x0F"
//!
//! E.g. "mailcrab.tweedegolf.nl" starts at index 15, where the part for
//! "mailcrab" is encoded, followed by a jump back to index 0, where
//! "tweedegolf" followed by "nl" is encoded. You can find "mail.tweedegolf.nl"
//! at index 26 and "secret.mailcrab.tweedegolf.nl" at index 33.
//!
//! ASSIGNMENT 2: Add this functionality to `decode_dns_name`. The first
//! argument is a slice pointing to the current DNS name to be decoded; the
//! second contains the entire packet. Of course, the first argument is expected
//! to be subslice of the second argument. The second test case should now pass.
//! Again, the test case is the bare minimum.
//!
//! Make a commit after this point.
//!
//! ---
//!
//! ASSIGNMENT 3 (optional): use "cargo fuzz" to test your implementation, did
//! you find any nice bugs?
//!
//! Make a commit after this point.
//!
//! ---
//!
//! Make nice commits.
//! 
//! For a better(?) explanation read section 4.1.4 of RFC 1035: https://www.ietf.org/rfc/rfc1035.txt
//!
//! NOTE: You're only allowed to use the Rust standard library, ob-vi-ous-ly.

use std::collections::HashSet;

#[derive(Debug, PartialEq)]
pub enum DNSNameError {
    EmptyInput,
    InvalidLabelLength,
    MissingIndexByte,
    IndexOutOfBounds,
    LabelExceedsInput,
    MaxLengthExceeded,
    InfiniteCompressionLoop,
}

struct DecodeDnsNameState {
    // length of name
    name_length: usize,
    // number of labels in name
    nlabels: usize,
    // allows for keeping track of indices to prevent compression loops
    visited: HashSet<u16>
}

impl DecodeDnsNameState {
    fn new() -> Self {
        Self { 
            name_length: 0, 
            nlabels: 0, 
            visited: HashSet::new() 
        }
    }

    fn add_label_length(&mut self, label_length: usize) -> usize {
        self.name_length += label_length + if self.nlabels == 0 { 0 } else { 1 };
        self.nlabels += 1;
        self.name_length
    }
}

pub fn decode_dns_name(input: &[u8], backlog: &[u8]) -> Option<Box<[u8]>> {
    decode_dns_name_helper(input, backlog, &mut DecodeDnsNameState::new()).ok().flatten()
}

fn decode_dns_name_helper(input: &[u8], backlog: &[u8], state: &mut DecodeDnsNameState) -> Result<Option<Box<[u8]>>, DNSNameError> {
    use DNSNameError::*;

    if input.len() > 0 {
        // focus on the two most significant bits
        match (input[0] & 0b11000000) >> 6 {
            0b00 => {
                // the two most significant bits are not set indicating the next 6 bits
                // contain the length for the label
                let length = input[0] as usize; // can at most be a value of 63 as we already checked the first two bits
                if length == 0 {
                    // a length of zero indicates the end of a name
                    Ok(None)
                // verify reading a new label doesn't exceed the max name length
                } else if state.add_label_length(length) <= 255 {
                    // the first 1 is for the encoded length, then the length of the label itself follows, 
                    // after which we expect another byte indicating another label or the end of the name.
                    if input.len() >= 1 + length + 1 {
                        // read the label
                        let mut name = (&input[1..=length as usize]).to_vec();
                        // recursively continue reading after the label
                        match decode_dns_name_helper(&input[1 + length..], backlog, state)? {
                            // this was the final label
                            None => Ok(Some(name.into())),
                            // add other label(s)
                            Some(other_label) => {
                                name.push(b'.');
                                name.extend_from_slice(&other_label);
                                Ok(Some(name.into()))
                            }
                        }
                    } else {
                        // the part exceeded the bounds of input
                        Err(LabelExceedsInput)
                    }
                } else {
                    Err(MaxLengthExceeded)
                }
            },
            0b11 => {
                // the two most siginificant bits are set, which means the other 6 bits 
                // in combination with the next byte provide a index of 14 bits for
                // compression
                if input.len() >= 2 {
                    // read two bytes as index, while ignoring the two most significant bits
                    let index: u16 = (((input[0] & 0b00111111) as u16) << 8) + (input[1] as u16);
                    // verify the index to be explored isn't already visited
                    if state.visited.insert(index) {
                        match backlog.get(index as usize..) {
                            // recursively read from the index in the backlog
                            Some(backlog_slice) => decode_dns_name_helper(backlog_slice, backlog, state),
                            None => Err(IndexOutOfBounds)
                        }
                    } else {
                        Err(InfiniteCompressionLoop)
                    }
                    
                } else {
                    Err(MissingIndexByte)
                }
            },
            _ => {
                // the most significant bits are either 0b10 or 0b01 which doesn't indicate
                // compression, and is invalid for a label length as it would exceed 63
                Err(InvalidLabelLength)
            }
        }
    } else {
        Err(EmptyInput)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn single() {
        let input = b"\x03com\0";
        let result = b"com";

        assert_eq!(
            decode_dns_name_helper(&input[..], &[], &mut DecodeDnsNameState::new()),
            Ok(Some(result.to_vec().into_boxed_slice()))
        );
        assert_eq!(
            decode_dns_name(&input[..], &[]).as_deref().unwrap(),
            result
        );
    }
    
    #[test]
    fn simple() {
        let input = b"\x06google\x03com\0";
        let result = b"google.com";

        assert_eq!(
            decode_dns_name_helper(&input[..], &[], &mut DecodeDnsNameState::new()),
            Ok(Some(result.to_vec().into_boxed_slice()))
        );
        assert_eq!(
            decode_dns_name(&input[..], &[]).as_deref().unwrap(),
            result
        );
    }

    #[test]
    fn empty() {
        let input = b"";

        assert_eq!(
            decode_dns_name_helper(&input[..], &[], &mut DecodeDnsNameState::new()),
            Err(DNSNameError::EmptyInput)
        );
        assert_eq!(
            decode_dns_name(&input[..], &[]).as_deref(),
            None
        );
    }

    #[test]
    fn invalid_part_length() {
        let input1 = b"\x7fco\0";
        let input2 = b"\x7fco\0";
        
        assert_eq!(
            decode_dns_name_helper(&input1[..], &[], &mut DecodeDnsNameState::new()),
            Err(DNSNameError::InvalidLabelLength)
        );
        assert_eq!(
            decode_dns_name(&input1[..], &[]).as_deref(),
            None
        );
        assert_eq!(
            decode_dns_name_helper(&input2[..], &[], &mut DecodeDnsNameState::new()),
            Err(DNSNameError::InvalidLabelLength)
        );
        assert_eq!(
            decode_dns_name(&input2[..], &[]).as_deref(),
            None
        );
    }

    #[test]
    fn missing_index_byte() {
        let input = b"\xc0";

        assert_eq!(
            decode_dns_name_helper(&input[..], &[], &mut DecodeDnsNameState::new()),
            Err(DNSNameError::MissingIndexByte)
        );
        assert_eq!(
            decode_dns_name(&input[..], &[]).as_deref(),
            None
        );
    }

    #[test]
    fn index_out_of_bounds() {
        let input = b"\xc0\xff";
        
        assert_eq!(
            decode_dns_name_helper(&input[..], &[], &mut DecodeDnsNameState::new()),
            Err(DNSNameError::IndexOutOfBounds)
        );
        assert_eq!(
            decode_dns_name(&input[..], &[]).as_deref(),
            None
        );
    }

    #[test]
    fn label_exceeds_input() {
        let input = b"\x03com";
        
        assert_eq!(
            decode_dns_name_helper(&input[..], &[], &mut DecodeDnsNameState::new()),
            Err(DNSNameError::LabelExceedsInput)
        );
        assert_eq!(
            decode_dns_name(&input[..], &[]).as_deref(),
            None
        );
    }

    #[test]
    fn max_length_exceeded() {
        let mut input = Vec::new();
        for _ in 0..41 {
            input.push(0x05);
            input.extend_from_slice(b"hello");
        }
        input.extend_from_slice(b"\x06google\x03com\x00");

        assert_eq!(
            input.len()-2,
            256
        );
        
        assert_eq!(
            decode_dns_name_helper(&input[..], &[], &mut DecodeDnsNameState::new()),
            Err(DNSNameError::MaxLengthExceeded)
        );
        assert_eq!(
            decode_dns_name(&input[..], &[]).as_deref(),
            None
        );
    }

    #[test]
    fn infinite_compression_loop() {
        let pkt = b"\xc0\x02\xc0\x00";
        
        assert_eq!(
            decode_dns_name_helper(&pkt[..], &pkt[..], &mut DecodeDnsNameState::new()),
            Err(DNSNameError::InfiniteCompressionLoop)
        );
        assert_eq!(
            decode_dns_name(&pkt[..], &pkt[..]).as_deref(),
            None
        );
    }

    #[test]
    fn simple_backref() {
        let pkt = b"\x06google\x03com\0\x03www\xC0\x00";
        let result = b"www.google.com";

        assert_eq!(
            decode_dns_name_helper(&pkt[12..], &pkt[..], &mut DecodeDnsNameState::new()),
            Ok(Some(result.to_vec().into_boxed_slice()))
        );
        assert_eq!(
            decode_dns_name(&pkt[12..], &pkt[..]).as_deref().unwrap(),
            result
        );
    }
}
